"""Read-only sequence observations; never calls nextval/setval or opens writers.

PostgreSQL sequence state is not MVCC. This observation must be combined with
independent all-writer fencing and a final data comparison before promotion.
Only a registered single integer primary key with one owned positive, noncycling
sequence is supported. Unsupported layouts fail closed.
"""

from dataclasses import dataclass
from datetime import datetime

from psycopg import sql

from sova.adapters.postgres_dataset import PostgresDatasetRegistration, table_definition
from sova.adapters.postgres_readonly import begin_registered_read, require_select_only
from sova.domain.contracts import ContractError, ResourceScope, utc
from sova.domain.evidence import RevisionSet


@dataclass(frozen=True, slots=True)
class SequenceObservation:
    scope: ResourceScope
    revisions: RevisionSet
    dataset: str
    schema_digest: str
    column: str
    sequence_oid: int
    maximum_id: int | None
    next_value: int
    limit: int
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        from sova.domain.contracts import digest, identifier

        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed sequence observation scope required")
        for value in (self.dataset, self.column):
            identifier(value)
        digest(self.schema_digest)
        if (
            any(
                type(v) is not int or v < 1
                for v in (self.sequence_oid, self.next_value, self.limit)
            )
            or self.next_value > self.limit
            or self.maximum_id is not None
            and type(self.maximum_id) is not int
        ):
            raise ContractError("Bounded positive sequence state required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Positive sequence observation validity required")


class PostgresSequenceObserver:
    def __init__(
        self,
        registration,
        *,
        connect,
        authorize,
        authenticate_registration,
        clock,
        monotonic,
    ):
        if not isinstance(registration, PostgresDatasetRegistration):
            raise ContractError("Registered dataset required for sequence observation")
        self.registration = registration
        self.connect = connect
        self.authorize = authorize
        self.authenticate_registration = authenticate_registration
        self.clock = clock
        self.monotonic = monotonic

    def observe(self, actor):
        r = self.registration
        started = self.monotonic()

        def guard():
            self.authorize(actor, r.scope, "data:sequence-observe")
            self.authenticate_registration(r)
            r.require_current(self.clock())
            if self.monotonic() - started > 15:
                raise ContractError("Sequence inspection deadline exceeded")

        guard()
        if len(r.primary_key) != 1:
            raise ContractError(
                "Only one integer primary key supported for sequence promotion"
            )
        with self.connect(r.connection_ref) as conn:
            begin_registered_read(conn, r)
            definition = table_definition(conn, r.schema_name, r.table_name)
            if (
                definition["table_oid"],
                definition["schema_digest"],
                definition["columns"],
                definition["primary_key"],
            ) != (r.table_oid, r.schema_digest, r.columns, r.primary_key) or definition[
                "document"
            ]["row_security"]:
                raise ContractError("Registered sequence table or schema drift")
            require_select_only(conn, r.table_oid)
            states = conn.execute(
                "SELECT s.oid,n.nspname,s.relname,q.seqincrement,q.seqmin,q.seqmax,q.seqcycle FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_depend d ON d.refobjid=a.attrelid AND d.refobjsubid=a.attnum AND d.deptype IN ('a','i') JOIN pg_catalog.pg_class s ON s.oid=d.objid AND s.relkind='S' JOIN pg_catalog.pg_namespace n ON n.oid=s.relnamespace JOIN pg_catalog.pg_sequence q ON q.seqrelid=s.oid WHERE a.attrelid=%s AND a.attname=%s AND a.atttypid IN ('int2'::regtype,'int4'::regtype,'int8'::regtype)",
                (r.table_oid, r.primary_key[0]),
            ).fetchall()
            if (
                len(states) != 1
                or states[0][3] != 1
                or states[0][4] < 1
                or states[0][6]
            ):
                raise ContractError(
                    "One owned, positive, unit-increment, noncycling sequence required"
                )
            oid, schema, name, _, _, maximum, _ = states[0]
            require_select_only(conn, oid, sequence=True)
            last, called = conn.execute(
                sql.SQL("SELECT last_value,is_called FROM {}.{}").format(
                    sql.Identifier(schema), sql.Identifier(name)
                )
            ).fetchone()
            rowmax = conn.execute(
                sql.SQL("SELECT max({}) FROM {}.{}").format(
                    sql.Identifier(r.primary_key[0]),
                    sql.Identifier(r.schema_name),
                    sql.Identifier(r.table_name),
                )
            ).fetchone()[0]
            guard()
            return SequenceObservation(
                r.scope,
                r.revisions,
                r.schema_name + "." + r.table_name,
                r.schema_digest,
                r.primary_key[0],
                oid,
                rowmax,
                last + 1 if called else last,
                maximum,
                utc(self.clock()),
                r.valid_until,
            )


def compare_sequence_observations(source, target, *, now):
    if not isinstance(source, SequenceObservation) or not isinstance(
        target, SequenceObservation
    ):
        raise ContractError("Typed sequence observations required")
    if (source.scope.tenant_id, source.scope.application_id) != (
        target.scope.tenant_id,
        target.scope.application_id,
    ) or source.scope.environment_id == target.scope.environment_id:
        raise ContractError("Distinct same-application sequence scopes required")
    if (source.revisions, source.dataset, source.schema_digest, source.column) != (
        target.revisions,
        target.dataset,
        target.schema_digest,
        target.column,
    ):
        raise ContractError("Sequence revision/dataset mismatch")
    now = utc(now)
    if any(not v.observed_at <= now < v.valid_until for v in (source, target)):
        raise ContractError("Sequence observation expired or from future")
    safe = (
        source.maximum_id == target.maximum_id
        and target.next_value >= source.next_value
        and (target.maximum_id is None or target.next_value > target.maximum_id)
    )
    return {
        "observed_collision_safe": safe,
        "source_next_value": source.next_value,
        "target_next_value": target.next_value,
        "table_maxima_match": source.maximum_id == target.maximum_id,
        "cutover_authorized": False,
        "not_verified": [
            "all-writer-fencing",
            "data-content-equality",
            "reverse-recovery",
        ],
    }
