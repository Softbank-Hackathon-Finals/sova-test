"""Read-only qualification of one registered PostgreSQL replication channel.

A registered barrier observation is not publisher transport attestation, writer fencing, a content comparison,
sequence safety, recovery qualification or permission to cut over. The operator
must create the publication/subscription and own the barrier writer separately.
No connection strings, passwords, row content or arbitrary SQL are returned.
"""

from contextlib import ExitStack
from dataclasses import dataclass
from datetime import datetime
import hashlib
import re
from uuid import UUID

from psycopg import sql
from sova.adapters.postgres_readonly import begin_registered_read, require_select_only

from sova.adapters.postgres_dataset import table_definition
from sova.adapters.postgres_channel_inspection import SubscriptionInspector
from sova.adapters.postgres_publisher_inspection import (
    PublisherInspector,
    inspect_publisher_transport,
)
from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova.domain.evidence import RevisionSet


@dataclass(frozen=True, slots=True)
class ReplicationEndpoint:
    scope: ResourceScope
    connection_ref: str
    database_name: str
    database_oid: int
    system_identifier: str
    reader_role: str
    allow_private_unix_fixture: bool = False

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed replication scope required")
        for value in (self.connection_ref, self.database_name, self.reader_role):
            identifier(value)
        if (
            type(self.database_oid) is not int
            or self.database_oid < 1
            or type(self.system_identifier) is not str
            or not re.fullmatch("[0-9]{1,20}", self.system_identifier)
            or type(self.allow_private_unix_fixture) is not bool
        ):
            raise ContractError(
                "Registered database identity and transport policy required"
            )


@dataclass(frozen=True, slots=True)
class ReplicatedTable:
    schema: str
    table: str
    source_oid: int
    target_oid: int
    schema_digest: str

    def __post_init__(self):
        identifier(self.schema)
        identifier(self.table)
        digest(self.schema_digest)
        if any(
            type(oid) is not int or oid < 1
            for oid in (self.source_oid, self.target_oid)
        ):
            raise ContractError("Registered replication relation OIDs required")


@dataclass(frozen=True, slots=True)
class ReplicationRegistration:
    source: ReplicationEndpoint
    target: ReplicationEndpoint
    revisions: RevisionSet
    publication: str
    publication_oid: int
    subscription: str
    subscription_oid: int
    tables: tuple[ReplicatedTable, ...]
    barrier_schema: str
    barrier_table: str
    issued_at: datetime
    valid_until: datetime
    inspector: SubscriptionInspector | None = None
    publisher_inspector: PublisherInspector | None = None

    def __post_init__(self):
        if (
            not isinstance(self.source, ReplicationEndpoint)
            or not isinstance(self.target, ReplicationEndpoint)
            or not isinstance(self.revisions, RevisionSet)
        ):
            raise ContractError("Typed replication endpoints and revisions required")
        a, b = self.source, self.target
        if (
            (a.scope.tenant_id, a.scope.application_id)
            != (b.scope.tenant_id, b.scope.application_id)
            or a.scope.environment_id == b.scope.environment_id
            or a.connection_ref == b.connection_ref
            or (a.system_identifier, a.database_oid)
            == (b.system_identifier, b.database_oid)
        ):
            raise ContractError(
                "Distinct same-application replication databases required"
            )
        for value in (
            self.publication,
            self.subscription,
            self.barrier_schema,
            self.barrier_table,
        ):
            identifier(value)
        if any(
            type(v) is not int or v < 1
            for v in (self.publication_oid, self.subscription_oid)
        ):
            raise ContractError("Registered replication channel OIDs required")
        if (
            type(self.tables) is not tuple
            or not 1 <= len(self.tables) <= 32
            or any(not isinstance(t, ReplicatedTable) for t in self.tables)
            or len({(t.schema, t.table) for t in self.tables}) != len(self.tables)
            or (self.barrier_schema, self.barrier_table)
            not in {(t.schema, t.table) for t in self.tables}
        ):
            raise ContractError(
                "Explicit complete publication including barrier required"
            )
        if self.inspector is not None and not isinstance(
            self.inspector, SubscriptionInspector
        ):
            raise ContractError("Typed subscription inspection binding required")
        if self.publisher_inspector is not None and (
            not isinstance(self.publisher_inspector, PublisherInspector)
            or self.inspector is None
            or self.inspector.expected_slot_name != self.publisher_inspector.slot_name
        ):
            raise ContractError(
                "Publisher inspection requires the same bound subscription slot"
            )
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Positive replication registration validity required")

    def require_current(self, now):
        if not self.issued_at <= utc(now) < self.valid_until:
            raise ContractError("Replication registration expired or from future")


class PostgresReplicationObserver:
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
        if not isinstance(registration, ReplicationRegistration):
            raise ContractError("Typed replication registration required")
        self.registration = registration
        self.connect = connect
        self.authorize = authorize
        self.authenticate_registration = authenticate_registration
        self.clock = clock
        self.monotonic = monotonic

    def inspect(self, actor, *, boundary_id, plan_digest, writer_epoch):
        r = self.registration
        try:
            boundary_id = str(UUID(boundary_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ContractError("Canonical UUID barrier required") from exc
        digest(plan_digest)
        if type(writer_epoch) is not int or writer_epoch < 1:
            raise ContractError("Positive expected writer epoch required")
        started = self.monotonic()

        def guard():
            for endpoint in (r.source, r.target):
                self.authorize(actor, endpoint.scope, "data:replication-observe")
            self.authenticate_registration(r)
            r.require_current(self.clock())
            if self.monotonic() - started > 15:
                raise ContractError("Replication inspection deadline exceeded")

        guard()
        with ExitStack() as stack:
            connections = []
            definitions = []
            for side, endpoint in (("source", r.source), ("target", r.target)):
                conn = stack.enter_context(self.connect(endpoint.connection_ref))
                begin_registered_read(conn, endpoint)
                tables = {}
                for table in r.tables:
                    guard()
                    definition = table_definition(conn, table.schema, table.table)
                    if (
                        definition["table_oid"] != getattr(table, side + "_oid")
                        or definition["schema_digest"] != table.schema_digest
                        or definition["document"]["row_security"]
                    ):
                        raise ContractError("Replication schema or relation drift")
                    require_select_only(conn, definition["table_oid"])
                    tables[(table.schema, table.table)] = definition
                connections.append(conn)
                definitions.append(tables)
            source, target = connections
            publication = source.execute(
                "SELECT oid,puballtables,pubinsert,pubupdate,pubdelete,pubtruncate FROM pg_catalog.pg_publication WHERE pubname=%s",
                (r.publication,),
            ).fetchone()
            if publication != (r.publication_oid, False, True, True, True, True):
                raise ContractError("Publication identity or event coverage drift")
            published = source.execute(
                "SELECT schemaname,tablename,attnames,rowfilter FROM pg_catalog.pg_publication_tables WHERE pubname=%s",
                (r.publication,),
            ).fetchall()
            expected = set(definitions[0])
            if {(row[0], row[1]) for row in published} != expected or len(
                published
            ) != len(expected):
                raise ContractError("Publication table coverage drift")
            for schema, table, columns, rowfilter in published:
                if (
                    tuple(columns) != definitions[0][(schema, table)]["columns"]
                    or rowfilter is not None
                ):
                    raise ContractError(
                        "Filtered replication cannot qualify full dataset"
                    )
            publisher_configuration_bound = False
            publisher_slot_bound = False
            if r.inspector is not None:
                inspector = r.inspector
                definition = target.execute(
                    "SELECT p.oid,pg_catalog.pg_get_functiondef(p.oid),pg_catalog.pg_get_userbyid(p.proowner),p.prosecdef FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='sova_replication_inspection' AND p.proname='channel_state' AND p.pronargs=0"
                ).fetchone()
                if (
                    definition is None
                    or definition[0] != inspector.function_oid
                    or hashlib.sha256(definition[1].encode()).hexdigest()
                    != inspector.definition_digest
                    or definition[2] != inspector.owner_role
                    or definition[3] is not True
                ):
                    raise ContractError(
                        "Subscription inspector definition or owner drift"
                    )
                if target.execute(
                    "SELECT pg_catalog.pg_has_role(current_user,%s,'MEMBER')",
                    (inspector.owner_role,),
                ).fetchone()[0]:
                    raise ContractError(
                        "Observer must not be a member of the inspector owner role"
                    )
                binding_oid = target.execute(
                    "SELECT 'sova_replication_inspection.reader_bindings'::regclass::oid"
                ).fetchone()[0]
                require_select_only(target, binding_oid)
                binding = target.execute(
                    "SELECT * FROM sova_replication_inspection.channel_state()"
                ).fetchall()
                expected = (
                    r.subscription_oid,
                    r.target.database_oid,
                    r.subscription,
                    True,
                    [r.publication],
                    inspector.publisher_configuration_digest,
                    r.valid_until,
                )
                if binding != [expected]:
                    raise ContractError("Publisher configuration or role binding drift")
                publisher_configuration_bound = True
                if inspector.expected_slot_name is not None:
                    slot = target.execute(
                        "SELECT subslotname FROM pg_catalog.pg_subscription WHERE oid=%s",
                        (r.subscription_oid,),
                    ).fetchone()
                    if slot != (inspector.expected_slot_name,):
                        raise ContractError("Subscription slot binding drift")
                    publisher_slot_bound = True
            publisher_transport = None
            if r.publisher_inspector is not None:
                publisher_transport = inspect_publisher_transport(
                    source,
                    r.publisher_inspector,
                    database_oid=r.source.database_oid,
                    valid_until=r.valid_until,
                )
            subscription = target.execute(
                "SELECT oid,subdbid,subenabled,subpublications FROM pg_catalog.pg_subscription WHERE subname=%s AND subdbid=%s",
                (r.subscription, r.target.database_oid),
            ).fetchone()
            if subscription != (
                r.subscription_oid,
                r.target.database_oid,
                True,
                [r.publication],
            ):
                raise ContractError("Subscription identity or publication drift")
            states = target.execute(
                "SELECT srrelid,srsubstate FROM pg_catalog.pg_subscription_rel WHERE srsubid=%s",
                (r.subscription_oid,),
            ).fetchall()
            if {(row[0], row[1]) for row in states} != {
                (table.target_oid, "r") for table in r.tables
            } or len(states) != len(r.tables):
                raise ContractError("Subscription tables not all ready")
            barrier_query = sql.SQL(
                "SELECT boundary_id::text,plan_digest,writer_epoch FROM {}.{} WHERE boundary_id=%s"
            ).format(sql.Identifier(r.barrier_schema), sql.Identifier(r.barrier_table))
            expected_barrier = (boundary_id, plan_digest, writer_epoch)
            if any(
                conn.execute(barrier_query, (boundary_id,)).fetchone()
                != expected_barrier
                for conn in connections
            ):
                raise ContractError(
                    "Exact same-channel barrier not present on both databases"
                )
            guard()
            reference = hashlib.sha256(
                canonical_json(
                    {
                        "source_scope": {
                            key: getattr(r.source.scope, key)
                            for key in (
                                "tenant_id",
                                "application_id",
                                "environment_id",
                                "resource_id",
                            )
                        },
                        "target_scope": {
                            key: getattr(r.target.scope, key)
                            for key in (
                                "tenant_id",
                                "application_id",
                                "environment_id",
                                "resource_id",
                            )
                        },
                        "revisions": {
                            key: getattr(r.revisions, key)
                            for key in (
                                "source",
                                "configuration",
                                "policy",
                                "environment",
                            )
                        },
                        "source": r.source.connection_ref,
                        "target": r.target.connection_ref,
                        "publication_oid": r.publication_oid,
                        "subscription_oid": r.subscription_oid,
                        "publisher_configuration_digest": r.inspector.publisher_configuration_digest
                        if r.inspector is not None
                        else None,
                        "publisher_slot": r.inspector.expected_slot_name
                        if r.inspector is not None
                        else None,
                        "publisher_transport_digest": publisher_transport[
                            "observation_digest"
                        ]
                        if publisher_transport is not None
                        else None,
                        "publisher_inspection_policy": {
                            "function_oid": r.publisher_inspector.function_oid,
                            "definition": r.publisher_inspector.definition_digest,
                            "owner": r.publisher_inspector.owner_role,
                            "binding_oid": r.publisher_inspector.binding_oid,
                            "slot": r.publisher_inspector.slot_name,
                            "role_oid": r.publisher_inspector.replicator_oid,
                            "role": r.publisher_inspector.replicator_role,
                            "application": r.publisher_inspector.application_name,
                            "peers": list(
                                r.publisher_inspector.expected_peer_addresses
                            ),
                        }
                        if r.publisher_inspector is not None
                        else None,
                        "boundary": boundary_id,
                        "plan": plan_digest,
                        "epoch": writer_epoch,
                        "tables": [
                            [
                                t.schema,
                                t.table,
                                t.source_oid,
                                t.target_oid,
                                t.schema_digest,
                            ]
                            for t in r.tables
                        ],
                    },
                    limit=65536,
                ).encode()
            ).hexdigest()
            return {
                "verification_scope": "registered-publication-and-subscription-barrier",
                "channel_observation_digest": reference,
                "boundary_id": boundary_id,
                "plan_digest": plan_digest,
                "writer_epoch": writer_epoch,
                "tables_observed": len(r.tables),
                "barrier_arrived": True,
                "publisher_configuration_bound": publisher_configuration_bound,
                "publisher_slot_bound": publisher_slot_bound,
                "publisher_transport_observation": publisher_transport,
                "observed_at": utc(self.clock()).isoformat(),
                "valid_until": r.valid_until.isoformat(),
                "cutover_authorized": False,
                "not_verified": [
                    *(
                        []
                        if publisher_configuration_bound
                        else ["publisher-configuration-binding"]
                    ),
                    *([] if publisher_slot_bound else ["publisher-slot-binding"]),
                    "publisher-transport-runtime-identity",
                    "all-writer-fencing",
                    "data-content-equality",
                    "sequence-safety",
                    "post-cutover-writes",
                    "reverse-recovery",
                ],
            }
