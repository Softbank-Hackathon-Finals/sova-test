"""Owner installation of a fixed, redacted app-DB subscription inspection port.

Never grant an observer SELECT on pg_subscription.subconninfo: it contains
credentials. The definer function has no caller-selected object argument and
exposes one role-bound subscription's configuration digest only. Its exact
owner, definition and OID must be authenticated in the registration.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path
import re

from psycopg import sql

from sova.domain.contracts import ContractError, digest, identifier, utc


@dataclass(frozen=True, slots=True)
class SubscriptionInspector:
    function_oid: int
    definition_digest: str
    owner_role: str
    publisher_configuration_digest: str
    expected_slot_name: str | None = None

    def __post_init__(self):
        if type(self.function_oid) is not int or self.function_oid < 1:
            raise ContractError("Positive subscription inspector OID required")
        digest(self.definition_digest)
        digest(self.publisher_configuration_digest)
        identifier(self.owner_role)
        if self.expected_slot_name is not None and not re.fullmatch(
            r"[a-z0-9_]{1,63}", self.expected_slot_name
        ):
            raise ContractError("Registered subscription slot name required")


def install_channel_inspector(
    connection,
    *,
    reader_role,
    subscription_oid,
    expected_connection_digest,
    valid_until: datetime,
    expected_slot_name: str | None = None,
):
    """Explicit migration-owner operation, excluded from app and guest runners.

    The caller derives expected_connection_digest from the approved publisher
    connection configuration, never from an uploaded manifest or readback alone.
    This installs only in the current app DB, not all customer databases.
    """
    identifier(reader_role)
    digest(expected_connection_digest)
    valid_until = utc(valid_until)
    if type(subscription_oid) is not int or subscription_oid < 1:
        raise ContractError("Positive registered subscription OID required")
    with connection.transaction():
        owner = connection.execute("SELECT current_user").fetchone()[0]
        schema_owner = connection.execute(
            "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname='sova_replication_inspection'"
        ).fetchone()
        if schema_owner is not None and schema_owner != (owner,):
            raise ContractError("Subscription inspection schema has a different owner")
        actual = connection.execute(
            "SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(subconninfo,'UTF8')),'hex') FROM pg_catalog.pg_subscription WHERE oid=%s AND subdbid=(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database())",
            (subscription_oid,),
        ).fetchone()
        if actual != (expected_connection_digest,):
            raise ContractError(
                "Subscription differs from approved publisher configuration"
            )
        if expected_slot_name is not None:
            if not re.fullmatch(r"[a-z0-9_]{1,63}", expected_slot_name):
                raise ContractError("Registered subscription slot name required")
            slot = connection.execute(
                "SELECT subslotname FROM pg_catalog.pg_subscription WHERE oid=%s",
                (subscription_oid,),
            ).fetchone()
            if slot != (expected_slot_name,):
                raise ContractError("Subscription slot differs from approved channel")
        reader = connection.execute(
            "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s", (reader_role,)
        ).fetchone()
        if reader is None or reader_role == owner:
            raise ContractError("Distinct existing observer role required")
        connection.execute(
            (
                Path(__file__).parent / "sql/postgres_replication_inspection_v1.sql"
            ).read_text()
        )
        unsafe = connection.execute(
            "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_namespace n CROSS JOIN LATERAL pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a WHERE n.nspname='sova_replication_inspection' AND a.privilege_type='CREATE' AND a.grantee<>n.nspowner)"
        ).fetchone()[0]
        table_owner = connection.execute(
            "SELECT pg_catalog.pg_get_userbyid(c.relowner),EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner AND a.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER')) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sova_replication_inspection' AND c.relname='reader_bindings'"
        ).fetchone()
        if unsafe or table_owner != (owner, False):
            raise ContractError(
                "Subscription inspector schema/table grants are mutable by another role"
            )
        connection.execute(
            "INSERT INTO sova_replication_inspection.reader_bindings VALUES(%s,%s,%s) ON CONFLICT(reader_oid) DO UPDATE SET subscription_oid=EXCLUDED.subscription_oid,valid_until=EXCLUDED.valid_until",
            (reader[0], subscription_oid, valid_until),
        )
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_replication_inspection TO {}").format(
                sql.Identifier(reader_role)
            )
        )
        connection.execute(
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION sova_replication_inspection.channel_state() TO {}"
            ).format(sql.Identifier(reader_role))
        )
        if expected_slot_name is not None:
            connection.execute(
                sql.SQL(
                    "GRANT SELECT(subslotname) ON pg_catalog.pg_subscription TO {}"
                ).format(sql.Identifier(reader_role))
            )
        identity = connection.execute(
            "SELECT p.oid,pg_catalog.pg_get_functiondef(p.oid),pg_catalog.pg_get_userbyid(p.proowner) FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='sova_replication_inspection' AND p.proname='channel_state' AND p.pronargs=0"
        ).fetchone()
        if identity is None or identity[2] != owner:
            raise ContractError("Unverified subscription inspector ownership")
        return SubscriptionInspector(
            identity[0],
            hashlib.sha256(identity[1].encode()).hexdigest(),
            identity[2],
            expected_connection_digest,
            expected_slot_name,
        )
