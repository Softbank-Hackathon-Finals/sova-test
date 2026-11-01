"""Fixed SQL writer gate for explicitly instrumented workloads.

The operator preinstalls a control table and grants a separate, non-owner role
SELECT plus UPDATE of its four state columns. This is not an arbitrary writer
discovery/fencing adapter, nor a grant of execution authority. The effect runner
must separately validate approval, security holds and the current execution lease.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import re

from psycopg import sql
from psycopg.pq import TransactionStatus

from sova.domain.contracts import (
    ContractError,
    EffectObservation,
    EffectStatus,
    ExecutionPermit,
    ResourceScope,
    canonical_json,
    identifier,
    utc,
    validate_permit,
)


@dataclass(frozen=True, slots=True)
class PostgresWriteGateRegistration:
    scope: ResourceScope
    connection_ref: str
    database_name: str
    database_oid: int
    system_identifier: str
    executor_role: str
    schema: str
    control_oid: int
    issued_at: datetime
    valid_until: datetime
    allow_private_unix_fixture: bool = False

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed writer scope required")
        for name in (
            "connection_ref",
            "database_name",
            "system_identifier",
            "executor_role",
        ):
            identifier(getattr(self, name), name)
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", self.schema):
            raise ContractError("Registered writer schema required")
        for value in (self.database_oid, self.control_oid):
            if type(value) is not int or not 0 < value <= 4294967295:
                raise ContractError("Exact registered database/table OID required")
        if type(self.allow_private_unix_fixture) is not bool:
            raise ContractError("Explicit fixture transport flag required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Positive writer registration lifetime required")


class PostgresWriteGateAdapter:
    adapter_id = "postgres-instrumented-writer-v1"

    def __init__(
        self,
        registration,
        *,
        connect,
        authenticate_registration,
        authorize_mutation,
        clock=lambda: datetime.now(UTC),
    ):
        if not isinstance(registration, PostgresWriteGateRegistration):
            raise ContractError("Typed writer registration required")
        self.registration = registration
        self.authorize_mutation = authorize_mutation
        self.connect, self.authenticate_registration, self.clock = (
            connect,
            authenticate_registration,
            clock,
        )

    def _grant(self, command):
        grant = self.authorize_mutation(command)
        if not isinstance(grant, ExecutionPermit):
            raise ContractError("Authenticated, command-bound mutation grant required")
        validate_permit(command, grant, self.clock())
        return grant

    def validate(self, command):
        r = self.registration
        self.authenticate_registration(r)
        if not r.issued_at <= utc(self.clock()) < r.valid_until:
            raise ContractError("Writer registration is not current")
        if command.scope != r.scope or command.adapter_id != self.adapter_id:
            raise ContractError("Writer command crosses registered identity")
        if (
            command.action not in {"pause_writes", "resume_writes"}
            or command.parameters != {}
        ):
            raise ContractError("Only an explicit writer state is supported")
        if (
            not re.fullmatch(r"writer:[1-9][0-9]{0,18}", command.expected_revision)
            or int(command.expected_revision[7:]) >= 9223372036854775807
        ):
            raise ContractError("Bounded expected writer revision required")
        if command.fencing_epoch >= 9223372036854775807:
            raise ContractError("Bounded executor epoch required")
        if command.expires_at > r.valid_until:
            raise ContractError("Writer command outlives registration")

    def _begin(self, conn, command, *, readonly=False):
        self.validate(command)
        r = self.registration
        if conn.autocommit or conn.info.transaction_status != TransactionStatus.IDLE:
            raise ContractError("Fresh writer transaction required")
        if conn.info.host.startswith("/"):
            if not r.allow_private_unix_fixture:
                raise ContractError("Private writer fixture was not authorized")
        elif (
            not conn.info.ssl_in_use
            or conn.info.get_parameters().get("sslmode") != "verify-full"
        ):
            raise ContractError("Verified writer TLS required")
        conn.execute(
            "SET TRANSACTION READ ONLY" if readonly else "SET TRANSACTION READ WRITE"
        )
        conn.execute("SET LOCAL statement_timeout='3s'")
        conn.execute("SET LOCAL lock_timeout='1s'")
        conn.execute("SET LOCAL search_path=pg_catalog")
        identity = conn.execute(
            "SELECT current_database(),d.oid,c.system_identifier::text,current_user,session_user FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_control_system() c WHERE d.datname=current_database()"
        ).fetchone()
        if identity != (
            r.database_name,
            r.database_oid,
            r.system_identifier,
            r.executor_role,
            r.executor_role,
        ):
            raise ContractError("Registered writer database identity drift")
        if conn.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE (rolname=current_user OR pg_catalog.pg_has_role(current_user,oid,'MEMBER')) AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication))"
        ).fetchone()[0]:
            raise ContractError("Privileged writer executor rejected")
        table = conn.execute(
            "SELECT c.oid,c.relkind,c.relrowsecurity,c.relforcerowsecurity,pg_catalog.pg_has_role(current_user,c.relowner,'MEMBER') FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname='control'",
            (r.schema,),
        ).fetchone()
        if table != (r.control_oid, "r", False, False, False):
            raise ContractError("Writer control identity or ownership drift")
        unsafe = conn.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_trigger WHERE tgrelid=%s AND NOT tgisinternal) OR EXISTS(SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class=%s) OR EXISTS(SELECT 1 FROM pg_catalog.pg_inherits WHERE inhrelid=%s OR inhparent=%s) OR EXISTS(SELECT 1 FROM pg_catalog.pg_roles role WHERE (role.rolname=current_user OR pg_catalog.pg_has_role(current_user,role.oid,'MEMBER')) AND (pg_catalog.has_schema_privilege(role.oid,%s,'CREATE') OR pg_catalog.has_table_privilege(role.oid,%s,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))) ",
            (
                r.control_oid,
                r.control_oid,
                r.control_oid,
                r.control_oid,
                r.schema,
                r.control_oid,
            ),
        ).fetchone()[0]
        if unsafe:
            raise ContractError(
                "Writer control has unregistered behavior or broad privileges"
            )
        return sql.SQL("{}.control").format(sql.Identifier(r.schema))

    def apply(self, command):
        r = self.registration
        self.validate(command)
        initial_grant = self._grant(command)
        with self.connect(r.connection_ref) as conn:
            table = self._begin(conn, command)
            key = int.from_bytes(
                hashlib.sha256(r.schema.encode()).digest()[:8], "big", signed=True
            )
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
            # A blocking drain can consume the approval's lifetime. Check again
            # after obtaining the lock and before the CAS mutation.
            self.validate(command)
            current_grant = self._grant(command)
            if utc(self.clock()) >= command.expires_at:
                raise ContractError("Writer command expired during drain")
            changed = conn.execute(
                sql.SQL(
                    "UPDATE {} SET writes_enabled=%s,writer_epoch=writer_epoch+1,execution_epoch=%s,last_command_digest=%s WHERE singleton AND writer_epoch=%s AND execution_epoch<=%s AND clock_timestamp()>=%s AND clock_timestamp()<%s RETURNING writer_epoch"
                ).format(table),
                (
                    command.action == "resume_writes",
                    command.fencing_epoch,
                    command.fingerprint,
                    int(command.expected_revision[7:]),
                    command.fencing_epoch,
                    r.issued_at,
                    min(
                        command.expires_at,
                        r.valid_until,
                        initial_grant.expires_at,
                        current_grant.expires_at,
                    ),
                ),
            ).fetchone()
            if changed is None:
                raise ContractError("Writer revision or executor epoch changed")

    def readback(self, command, now):
        with self.connect(self.registration.connection_ref) as conn:
            table = self._begin(conn, command, readonly=True)
            row = conn.execute(
                sql.SQL(
                    "SELECT writes_enabled,writer_epoch,execution_epoch,last_command_digest FROM {} WHERE singleton"
                ).format(table)
            ).fetchone()
        expected = int(command.expected_revision[7:]) + 1
        confirmed = row == (
            command.action == "resume_writes",
            expected,
            command.fencing_epoch,
            command.fingerprint,
        )
        return EffectObservation(
            command.scope,
            command.fingerprint,
            EffectStatus.APPLIED if confirmed else EffectStatus.UNKNOWN,
            now,
            canonical_json(
                {
                    "registered_writer_gate": True,
                    "confirmed": confirmed,
                    "all_writers_fenced": False,
                }
            ),
        )
