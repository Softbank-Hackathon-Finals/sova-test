"""Append-only security hold events, scoped RLS and serialized CAS release.

Runtime authorization is an application responsibility. An authenticated tenant
context and non-owner DB role are required; a compromised shared DB credential
is not isolated by the tenant setting itself.
"""

from datetime import datetime
from psycopg.types.json import Jsonb

from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.plan_codec import document_hash
from sova.adapters.registration.graph_codec import exact
from sova.domain.contracts import ContractError, ResourceScope, identifier
from sova.security.domain.governance import SecurityHold, HoldRelease, StoredHold
from sova.domain.evidence import RevisionSet
from sova.ports.plans import RecordNotFound, RepositoryConflict


def lock_security_hold_set(conn, tenant_id, application_id):
    key = document_hash(
        {"tenant": tenant_id, "app": application_id, "purpose": "security-hold-set"}
    )
    conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))


def decode_hold(document):
    try:
        exact(document, ("hold", "revision", "release"))
        hold = document["hold"]
        exact(hold, ("hold_id", "scope", "raised_by", "reason", "raised_at"))
        exact(
            hold["scope"],
            ("tenant_id", "application_id", "environment_id", "resource_id"),
        )
        value = SecurityHold(
            hold["hold_id"],
            ResourceScope(**hold["scope"]),
            hold["raised_by"],
            hold["reason"],
            datetime.fromisoformat(hold["raised_at"]),
        )
        release = document["release"]
        if release is not None:
            exact(
                release,
                (
                    "hold_id",
                    "scope",
                    "revisions",
                    "expected_revision",
                    "requested_by",
                    "approved_by",
                    "reason",
                    "evidence_id",
                    "evidence_digest",
                    "approved_at",
                    "valid_until",
                ),
            )
            exact(
                release["scope"],
                ("tenant_id", "application_id", "environment_id", "resource_id"),
            )
            exact(
                release["revisions"],
                ("source", "configuration", "policy", "environment"),
            )
            release = HoldRelease(
                **{
                    key: value
                    for key, value in release.items()
                    if key not in {"scope", "revisions", "approved_at", "valid_until"}
                },
                scope=ResourceScope(**release["scope"]),
                revisions=RevisionSet(**release["revisions"]),
                approved_at=datetime.fromisoformat(release["approved_at"]),
                valid_until=datetime.fromisoformat(release["valid_until"]),
            )
        return StoredHold(value, document["revision"], release)
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Invalid persisted security hold") from exc


class PostgresSecurityHolds:
    def __init__(self, connect, *, tenant_id):
        self.tenant_id = identifier(tenant_id)
        self._transactions = PostgresLifecycleRepository(connect, tenant_id=tenant_id)

    def _decode_row(self, app, row):
        value = decode_hold(row[3])
        if (
            value.hold.scope.tenant_id,
            value.hold.scope.application_id,
            value.hold.hold_id,
            value.revision,
            document_hash(row[3]),
        ) != (self.tenant_id, app, row[0], row[1], row[2]):
            raise ContractError("Security hold integrity/scope mismatch")
        return value

    def _get(self, conn, app, hold_id):
        row = conn.execute(
            """SELECT hold_id,revision,digest,document FROM sova_control.security_hold_events
          WHERE tenant_id=%s AND application_id=%s AND hold_id=%s ORDER BY revision DESC LIMIT 1""",
            (self.tenant_id, app, hold_id),
        ).fetchone()
        if not row:
            raise RecordNotFound("Security hold not found")
        return self._decode_row(app, row)

    def get_hold(self, application_id, hold_id):
        identifier(application_id)
        identifier(hold_id)
        with self._transactions.transaction() as conn:
            return self._get(conn, application_id, hold_id)

    def active_holds(self, application_id):
        identifier(application_id)
        with self._transactions.transaction() as conn:
            return self._active(conn, application_id)

    def _active(self, conn, application_id):
        rows = conn.execute(
            """SELECT hold_id,revision,digest,document FROM (
          SELECT DISTINCT ON (hold_id) hold_id,revision,digest,document,event_kind
          FROM sova_control.security_hold_events WHERE tenant_id=%s AND application_id=%s
          ORDER BY hold_id,revision DESC) latest WHERE event_kind='opened' ORDER BY hold_id LIMIT 257""",
            (self.tenant_id, application_id),
        ).fetchall()
        if len(rows) > 256:
            raise ContractError("Active security hold limit exceeded")
        return tuple(self._decode_row(application_id, row) for row in rows)

    def _lock(self, conn, app, hold_id):
        # Hash collisions cause additional serialization, never broader access.
        lock_security_hold_set(conn, self.tenant_id, app)
        key = document_hash({"tenant": self.tenant_id, "app": app, "hold": hold_id})
        conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))

    def _append(self, conn, stored):
        hold = stored.hold
        document = stored.document
        conn.execute(
            """INSERT INTO sova_control.security_hold_events
          (tenant_id,application_id,hold_id,revision,event_kind,digest,document) VALUES(%s,%s,%s,%s,%s,%s,%s)""",
            (
                self.tenant_id,
                hold.scope.application_id,
                hold.hold_id,
                stored.revision,
                "opened" if stored.active else "released",
                document_hash(document),
                Jsonb(document),
            ),
        )

    def open_hold(self, hold):
        if hold.scope.tenant_id != self.tenant_id:
            raise ContractError("Security hold tenant mismatch")
        with self._transactions.transaction() as conn:
            self._lock(conn, hold.scope.application_id, hold.hold_id)
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if hold.raised_at > now:
                raise ContractError("Future security hold")
            try:
                existing = self._get(conn, hold.scope.application_id, hold.hold_id)
            except RecordNotFound:
                existing = None
            if existing:
                if existing.hold != hold or not existing.active:
                    raise RepositoryConflict(
                        "Security hold ID cannot be replaced/reactivated"
                    )
                return existing
            stored = StoredHold(hold, 1)
            self._append(conn, stored)
            return stored

    def release_hold(self, application_id, release):
        identifier(application_id)
        with self._transactions.transaction() as conn:
            self._lock(conn, application_id, release.hold_id)
            stored = self._get(conn, application_id, release.hold_id)
            if not stored.active or stored.revision != release.expected_revision:
                raise RepositoryConflict("Security hold release CAS conflict")
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            release.require_valid(stored.hold, stored.revision, now)
            result = StoredHold(stored.hold, stored.revision + 1, release)
            self._append(conn, result)
            return result

    def open_incident(self, scope, reason, raised_by):
        """Deduplicate an unresolved scoped trigger under a transaction lock."""
        from uuid import uuid4

        if scope.tenant_id != self.tenant_id:
            raise ContractError("Incident tenant mismatch")
        identifier(reason, limit=1024)
        identifier(raised_by)
        key = document_hash(
            {
                "scope": {
                    k: getattr(scope, k)
                    for k in (
                        "tenant_id",
                        "application_id",
                        "environment_id",
                        "resource_id",
                    )
                },
                "reason": reason,
            }
        )
        with self._transactions.transaction() as conn:
            self._lock(conn, scope.application_id, "trigger:" + key)
            rows = conn.execute(
                """SELECT hold_id,revision,digest,document FROM (
              SELECT DISTINCT ON (hold_id) hold_id,revision,digest,document,event_kind
              FROM sova_control.security_hold_events WHERE tenant_id=%s AND application_id=%s
              ORDER BY hold_id,revision DESC) latest WHERE event_kind='opened' LIMIT 257""",
                (self.tenant_id, scope.application_id),
            ).fetchall()
            if len(rows) > 256:
                raise ContractError("Active incident limit exceeded")
            for row in rows:
                stored = self._decode_row(scope.application_id, row)
                if stored.hold.scope == scope and stored.hold.reason == reason:
                    return stored, False
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            stored = StoredHold(
                SecurityHold("incident-" + uuid4().hex, scope, raised_by, reason, now),
                1,
            )
            self._append(conn, stored)
            return stored, True
