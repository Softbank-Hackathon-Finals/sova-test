"""Durable monitoring leases and failure/attention outbox, tenant RLS enforced.

No resource mutations, network destinations, secret values, or exception text are
stored here. Database time owns leases; a stale worker cannot mark a run healthy.
"""

from datetime import timedelta
from uuid import uuid4

from psycopg.types.json import Jsonb

from sova.domain.contracts import ContractError, digest, identifier
from sova.monitoring.contracts import MonitorClaim, MonitorRegistration
from sova.ports.operations import LeaseLost
from sova.ports.plans import RepositoryConflict


class PostgresMonitorRepository:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    @property
    def tenant_id(self):
        return self.lifecycle.tenant_id

    def register(self, registration):
        if not isinstance(registration, MonitorRegistration):
            raise ContractError("Typed monitor registration required")
        self.lifecycle.require_scope(registration.scope)
        r = registration
        with self.lifecycle.transaction() as conn:
            conn.execute(
                """INSERT INTO sova_control.monitor_jobs
                (tenant_id,application_id,job_id,digest,document,next_due,valid_until)
                VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (
                    self.tenant_id,
                    r.scope.application_id,
                    r.job_id,
                    r.fingerprint,
                    Jsonb(r.document),
                    r.registered_at,
                    r.valid_until,
                ),
            )
            row = conn.execute(
                """SELECT digest,document FROM sova_control.monitor_jobs
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s""",
                (self.tenant_id, r.scope.application_id, r.job_id),
            ).fetchone()
            if row != (r.fingerprint, r.document):
                raise RepositoryConflict(
                    "Monitor job ID already has different immutable registration"
                )

    def disable(self, application_id, job_id, *, expected_digest):
        digest(expected_digest)
        with self.lifecycle.transaction() as conn:
            changed = conn.execute(
                """UPDATE sova_control.monitor_jobs SET enabled=false
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s AND digest=%s
                RETURNING job_id""",
                (self.tenant_id, application_id, job_id, expected_digest),
            ).fetchone()
            if changed is None:
                raise RepositoryConflict("Registered monitor changed or not found")

    @staticmethod
    def _alert(conn, tenant, app, job, run, category):
        conn.execute(
            """INSERT INTO sova_control.monitor_alerts
            (tenant_id,application_id,job_id,run_id,alert_id,category)
            VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
            (tenant, app, job, run, uuid4().hex, category),
        )

    def claim(self, registration, owner_id, *, lease_seconds=120):
        if not isinstance(registration, MonitorRegistration):
            raise ContractError("Typed monitor registration required")
        self.lifecycle.require_scope(registration.scope)
        identifier(owner_id)
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 300:
            raise ContractError("Monitoring lease must be 5 to 300 seconds")
        r = registration
        app = r.scope.application_id
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """SELECT digest,document,enabled,next_due,valid_until,
                lease_until,run_id FROM sova_control.monitor_jobs
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s FOR UPDATE""",
                (self.tenant_id, app, r.job_id),
            ).fetchone()
            if row is None or row[:2] != (r.fingerprint, r.document):
                raise RepositoryConflict("Current registered monitor not found")
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if not row[2] or now < row[3] or now >= row[4] or (row[5] and now < row[5]):
                return None
            if row[6] is not None:
                conn.execute(
                    """UPDATE sova_control.monitor_runs SET outcome='abandoned',finished_at=%s
                    WHERE tenant_id=%s AND application_id=%s AND job_id=%s AND run_id=%s AND outcome='running'""",
                    (now, self.tenant_id, app, r.job_id, row[6]),
                )
                self._alert(
                    conn, self.tenant_id, app, r.job_id, row[6], "monitor_abandoned"
                )
            token, run = uuid4().hex, uuid4().hex
            until = min(now + timedelta(seconds=lease_seconds), r.valid_until)
            conn.execute(
                """UPDATE sova_control.monitor_jobs
                SET owner_id=%s,lease_token=%s,lease_until=%s,run_id=%s
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s""",
                (owner_id, token, until, run, self.tenant_id, app, r.job_id),
            )
            conn.execute(
                """INSERT INTO sova_control.monitor_runs
                (tenant_id,application_id,job_id,run_id,outcome,started_at)
                VALUES(%s,%s,%s,%s,'running',%s)""",
                (self.tenant_id, app, r.job_id, run, now),
            )
            return MonitorClaim(
                r.fingerprint, r.job_id, app, run, owner_id, token, until
            )

    def complete(self, claim, *, outcome, review_digest):
        if not isinstance(claim, MonitorClaim) or outcome not in {
            "observed",
            "attention",
            "failed",
        }:
            raise ContractError("Typed monitor completion required")
        if outcome == "failed":
            if review_digest is not None:
                raise ContractError("Failed monitor cannot assert a review")
        else:
            digest(review_digest)
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """SELECT document FROM sova_control.monitor_jobs
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s AND digest=%s
                AND enabled AND owner_id=%s AND lease_token=%s AND run_id=%s
                AND lease_until>clock_timestamp() AND valid_until>clock_timestamp()
                FOR UPDATE""",
                (
                    self.tenant_id,
                    claim.application_id,
                    claim.job_id,
                    claim.registration_digest,
                    claim.owner_id,
                    claim.lease_token,
                    claim.run_id,
                ),
            ).fetchone()
            if row is None:
                raise LeaseLost("Monitoring lease lost or registration disabled")
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            conn.execute(
                """UPDATE sova_control.monitor_runs SET outcome=%s,review_digest=%s,finished_at=%s
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s AND run_id=%s AND outcome='running'""",
                (
                    outcome,
                    review_digest,
                    now,
                    self.tenant_id,
                    claim.application_id,
                    claim.job_id,
                    claim.run_id,
                ),
            )
            if outcome != "observed":
                self._alert(
                    conn,
                    self.tenant_id,
                    claim.application_id,
                    claim.job_id,
                    claim.run_id,
                    "monitor_failed" if outcome == "failed" else "security_attention",
                )
            conn.execute(
                """UPDATE sova_control.monitor_jobs
                SET owner_id=NULL,lease_token=NULL,lease_until=NULL,run_id=NULL,next_due=%s
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s""",
                (
                    now + timedelta(seconds=row[0]["interval_seconds"]),
                    self.tenant_id,
                    claim.application_id,
                    claim.job_id,
                ),
            )

    def alerts(self, application_id, *, limit=100):
        identifier(application_id)
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ContractError("Bounded alert query required")
        with self.lifecycle.transaction() as conn:
            return tuple(
                dict(
                    zip(
                        (
                            "alert_id",
                            "job_id",
                            "run_id",
                            "category",
                            "created_at",
                            "delivered_at",
                        ),
                        row,
                    )
                )
                for row in conn.execute(
                    """SELECT alert_id,job_id,run_id,category,created_at,delivered_at
                         FROM sova_control.monitor_alerts WHERE tenant_id=%s AND application_id=%s
                         ORDER BY created_at DESC,alert_id LIMIT %s""",
                    (self.tenant_id, application_id, limit),
                )
            )

    def claim_alert(self, application_id, owner_id, *, lease_seconds=30):
        from sova.monitoring.contracts import AlertDelivery

        identifier(application_id)
        identifier(owner_id)
        if type(lease_seconds) is not int or not 5 <= lease_seconds <= 120:
            raise ContractError("Bounded alert delivery lease required")
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """SELECT alert_id,job_id,run_id,category FROM sova_control.monitor_alerts
                WHERE tenant_id=%s AND application_id=%s AND delivered_at IS NULL AND attempts<8
                AND (lease_until IS NULL OR lease_until<=clock_timestamp())
                ORDER BY created_at,alert_id FOR UPDATE SKIP LOCKED LIMIT 1""",
                (self.tenant_id, application_id),
            ).fetchone()
            if row is None:
                return None
            token = uuid4().hex
            until = conn.execute(
                "SELECT clock_timestamp()+%s", (timedelta(seconds=lease_seconds),)
            ).fetchone()[0]
            conn.execute(
                """UPDATE sova_control.monitor_alerts
                SET owner_id=%s,lease_token=%s,lease_until=%s,attempts=attempts+1
                WHERE tenant_id=%s AND application_id=%s AND alert_id=%s""",
                (owner_id, token, until, self.tenant_id, application_id, row[0]),
            )
            return AlertDelivery(
                self.tenant_id, application_id, *row, owner_id, token, until
            )

    def acknowledge_alert(self, delivery, receipt):
        from sova.monitoring.contracts import AlertDelivery, AlertReceipt

        if (
            not isinstance(delivery, AlertDelivery)
            or not isinstance(receipt, AlertReceipt)
            or delivery.tenant_id != self.tenant_id
            or receipt.alert_id != delivery.alert_id
        ):
            raise ContractError("Scoped typed alert acknowledgement required")
        with self.lifecycle.transaction() as conn:
            changed = conn.execute(
                """UPDATE sova_control.monitor_alerts
                SET delivered_at=clock_timestamp(),sink_id=%s,receipt_id=%s,
                owner_id=NULL,lease_token=NULL,lease_until=NULL
                WHERE tenant_id=%s AND application_id=%s AND alert_id=%s
                AND delivered_at IS NULL AND owner_id=%s AND lease_token=%s
                AND lease_until>clock_timestamp() RETURNING alert_id""",
                (
                    receipt.sink_id,
                    receipt.receipt_id,
                    self.tenant_id,
                    delivery.application_id,
                    delivery.alert_id,
                    delivery.owner_id,
                    delivery.lease_token,
                ),
            ).fetchone()
            if changed is None:
                raise LeaseLost("Alert delivery lease lost")

    def get_registration(self, application_id, job_id):
        from datetime import datetime
        from sova.domain.contracts import ResourceScope

        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """SELECT digest,document,enabled FROM sova_control.monitor_jobs
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s""",
                (self.tenant_id, application_id, job_id),
            ).fetchone()
            if row is None or not row[2]:
                raise ContractError("Active monitoring registration not found")
            data = dict(row[1])
            if data.pop("schema_version", None) != 1:
                raise ContractError("Unknown monitor registration schema")
            value = MonitorRegistration(
                **{
                    **data,
                    "scope": ResourceScope(**data["scope"]),
                    "registered_at": datetime.fromisoformat(data["registered_at"]),
                    "valid_until": datetime.fromisoformat(data["valid_until"]),
                }
            )
            if value.fingerprint != row[0] or (
                value.scope.tenant_id,
                value.scope.application_id,
                value.job_id,
            ) != (self.tenant_id, application_id, job_id):
                raise ContractError("Stored monitoring registration integrity mismatch")
            return value

    def publish_inputs(self, value):
        from sova.monitoring.contracts import MonitorInputSet

        if not isinstance(value, MonitorInputSet):
            raise ContractError("Typed input set required")
        self.lifecycle.require_scope(value.scope)
        r = value
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """SELECT enabled,valid_until,document FROM sova_control.monitor_jobs
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s FOR UPDATE""",
                (self.tenant_id, r.scope.application_id, r.job_id),
            ).fetchone()
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if (
                not row
                or not row[0]
                or row[2].get("scope") != r.document["scope"]
                or not r.observed_at <= now < min(row[1], r.valid_until)
            ):
                raise ContractError("Current registered monitoring inputs required")
            previous = conn.execute(
                """SELECT revision,digest FROM sova_control.monitor_input_sets
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s ORDER BY revision DESC LIMIT 1""",
                (self.tenant_id, r.scope.application_id, r.job_id),
            ).fetchone()
            if previous == (r.revision, r.fingerprint):
                return
            if (r.revision, r.predecessor_digest) != (
                (previous[0] + 1, previous[1]) if previous else (1, None)
            ):
                raise RepositoryConflict("Monitor input set compare-and-swap failed")
            conn.execute(
                """INSERT INTO sova_control.monitor_input_sets
                (tenant_id,application_id,job_id,revision,digest,document) VALUES(%s,%s,%s,%s,%s,%s)""",
                (
                    self.tenant_id,
                    r.scope.application_id,
                    r.job_id,
                    r.revision,
                    r.fingerprint,
                    Jsonb(r.document),
                ),
            )

    def latest_inputs(self, application_id, job_id):
        from datetime import datetime
        from sova.domain.contracts import ResourceScope
        from sova.monitoring.contracts import MonitorInputSet

        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """SELECT digest,document FROM sova_control.monitor_input_sets
                WHERE tenant_id=%s AND application_id=%s AND job_id=%s ORDER BY revision DESC LIMIT 1""",
                (self.tenant_id, application_id, job_id),
            ).fetchone()
            if row is None:
                raise ContractError("No authenticated monitoring input set registered")
            data = dict(row[1])
            if data.pop("schema_version", None) != 1:
                raise ContractError("Unknown monitor input schema")
            result = MonitorInputSet(
                **{
                    **data,
                    "scope": ResourceScope(**data["scope"]),
                    "observed_at": datetime.fromisoformat(data["observed_at"]),
                    "valid_until": datetime.fromisoformat(data["valid_until"]),
                }
            )
            if result.fingerprint != row[0] or (
                result.scope.tenant_id,
                result.scope.application_id,
                result.job_id,
            ) != (self.tenant_id, application_id, job_id):
                raise ContractError("Stored monitoring input integrity mismatch")
            return result
