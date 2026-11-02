"""Immutable sanitized observations/events; no implicit collection or auth."""

from psycopg.types.json import Jsonb
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.security.adapters.security_codec import decode_snapshot, decode_event
from sova.domain.contracts import ContractError, identifier
from sova.ports.plans import RecordNotFound, RepositoryConflict


class PostgresSecurityObservations:
    def __init__(self, connect, *, tenant_id):
        self.tenant_id = identifier(tenant_id)
        self._transactions = PostgresLifecycleRepository(connect, tenant_id=tenant_id)

    def _snapshot(self, app, row):
        if not row:
            raise RecordNotFound("Security snapshot not found")
        value = decode_snapshot(row[2])
        graph = value.graph
        if (
            graph.tenant_id,
            graph.application_id,
            value.fingerprint,
            graph.fingerprint,
        ) != (self.tenant_id, app, row[0], row[1]):
            raise ContractError("Security snapshot integrity/scope mismatch")
        if (
            {r.scope.environment_id for r in graph.resources} != {row[3]}
            or graph.observed_at != row[4]
            or graph.valid_until != row[5]
        ):
            raise ContractError("Security snapshot metadata mismatch")
        return value

    def save_snapshot(self, snapshot):
        graph = snapshot.graph
        environments = {r.scope.environment_id for r in graph.resources}
        if graph.tenant_id != self.tenant_id or len(environments) != 1:
            raise ContractError("Single registered environment and tenant required")
        environment = next(iter(environments))
        with self._transactions.transaction() as conn:
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if graph.observed_at > now:
                raise ContractError("Future security snapshot")
            conn.execute(
                """INSERT INTO sova_control.security_snapshots
             (tenant_id,application_id,environment_id,digest,graph_digest,observed_at,valid_until,document)
             VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (
                    self.tenant_id,
                    graph.application_id,
                    environment,
                    snapshot.fingerprint,
                    graph.fingerprint,
                    graph.observed_at,
                    graph.valid_until,
                    Jsonb(snapshot.document),
                ),
            )
            stored = self._snapshot(
                graph.application_id,
                conn.execute(
                    "SELECT digest,graph_digest,document,environment_id,observed_at,valid_until FROM sova_control.security_snapshots WHERE tenant_id=%s AND application_id=%s AND digest=%s",
                    (self.tenant_id, graph.application_id, snapshot.fingerprint),
                ).fetchone(),
            )
            if stored.fingerprint != snapshot.fingerprint:
                raise RepositoryConflict("Immutable security snapshot conflict")

    def get_snapshot(self, application_id, digest):
        with self._transactions.transaction() as conn:
            return self._snapshot(
                application_id,
                conn.execute(
                    "SELECT digest,graph_digest,document,environment_id,observed_at,valid_until FROM sova_control.security_snapshots WHERE tenant_id=%s AND application_id=%s AND digest=%s",
                    (self.tenant_id, application_id, digest),
                ).fetchone(),
            )

    def latest_snapshot(self, application_id, environment_id):
        with self._transactions.transaction() as conn:
            rows = conn.execute(
                """SELECT digest,graph_digest,document,environment_id,observed_at,valid_until FROM sova_control.security_snapshots
             WHERE tenant_id=%s AND application_id=%s AND environment_id=%s ORDER BY observed_at DESC,digest LIMIT 2""",
                (self.tenant_id, application_id, environment_id),
            ).fetchall()
            if len(rows) > 1 and rows[0][4] == rows[1][4]:
                raise ContractError("Ambiguous latest security snapshots")
            return self._snapshot(application_id, rows[0] if rows else None)

    def append_event(self, event):
        if event.scope.tenant_id != self.tenant_id:
            raise ContractError("Security event tenant mismatch")
        with self._transactions.transaction() as conn:
            snapshot = self._snapshot(
                event.scope.application_id,
                conn.execute(
                    "SELECT digest,graph_digest,document,environment_id,observed_at,valid_until FROM sova_control.security_snapshots WHERE tenant_id=%s AND application_id=%s AND digest=%s",
                    (self.tenant_id, event.scope.application_id, event.snapshot_digest),
                ).fetchone(),
            )
            nodes = {r.node_id: r for r in snapshot.graph.resources}
            if (
                event.graph_digest != snapshot.graph.fingerprint
                or any(n not in nodes for n in event.node_ids)
                or event.scope not in {nodes[n].scope for n in event.node_ids}
                or event.recorded_at < snapshot.graph.observed_at
            ):
                raise ContractError("Security event subject/revision mismatch")
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if event.recorded_at > now:
                raise ContractError("Future security event")
            conn.execute(
                """INSERT INTO sova_control.security_event_log
             (tenant_id,application_id,event_id,snapshot_digest,digest,document) VALUES(%s,%s,%s,%s,%s,%s)
             ON CONFLICT DO NOTHING""",
                (
                    self.tenant_id,
                    event.scope.application_id,
                    event.event_id,
                    event.snapshot_digest,
                    event.fingerprint,
                    Jsonb(event.document),
                ),
            )
            row = conn.execute(
                "SELECT sequence,digest FROM sova_control.security_event_log WHERE tenant_id=%s AND application_id=%s AND event_id=%s",
                (self.tenant_id, event.scope.application_id, event.event_id),
            ).fetchone()
            if not row or row[1] != event.fingerprint:
                raise RepositoryConflict("Security event ID cannot be overwritten")
            return row[0]

    def list_events(self, application_id, *, after=0, limit=100, recent=False):
        if (
            type(after) is not int
            or after < 0
            or type(limit) is not int
            or not 1 <= limit <= 100
            or type(recent) is not bool
            or (recent and after != 0)
        ):
            raise ContractError("Bounded security event cursor required")
        with self._transactions.transaction() as conn:
            rows = conn.execute(
                """SELECT sequence,digest,document,event_id,snapshot_digest FROM sova_control.security_event_log
             WHERE tenant_id=%s AND application_id=%s AND sequence>%s ORDER BY sequence """
                + ("DESC" if recent else "ASC")
                + " LIMIT %s",
                (self.tenant_id, application_id, after, limit),
            ).fetchall()
            result = []
            for sequence, digest, document, event_id, snapshot_digest in rows:
                event = decode_event(document)
                if (
                    event.scope.tenant_id,
                    event.scope.application_id,
                    event.fingerprint,
                ) != (self.tenant_id, application_id, digest):
                    raise ContractError("Security event integrity/scope mismatch")
                if (
                    event.event_id != event_id
                    or event.snapshot_digest != snapshot_digest
                ):
                    raise ContractError("Security event metadata mismatch")
                result.append((sequence, event))
            return tuple(reversed(result)) if recent else tuple(result)
