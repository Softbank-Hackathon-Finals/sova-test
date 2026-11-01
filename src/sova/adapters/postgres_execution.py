"""Fail-closed app ownership: expiry never clears unresolved effect barriers."""

from uuid import uuid4

from psycopg.types.json import Jsonb

from sova.domain.contracts import ContractError, identifier
from sova.domain.execution import ExecutionLease, ExecutionMode, pending_digest
from sova.ports.execution import ExecutionBusy, RecoveryRequired
from sova.ports.operations import LeaseLost


class PostgresExecutionOwnership:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    @property
    def tenant_id(self):
        return self.lifecycle.tenant_id

    @staticmethod
    def duration(seconds):
        if type(seconds) is not int or not 1 <= seconds <= 300:
            raise ContractError("Execution lease must be 1..300 seconds")

    def lock_app(self, conn, app):
        identifier(app, "application_id")
        conn.execute(
            "INSERT INTO sova_control.app_execution(tenant_id,application_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",
            (self.tenant_id, app),
        )
        return conn.execute(
            """SELECT operation_id,owner_id,token,epoch,valid_until,mode,
            proof_valid_until,recovery_effects FROM sova_control.app_execution
            WHERE tenant_id=%s AND application_id=%s FOR UPDATE""",
            (self.tenant_id, app),
        ).fetchone()

    def pending(self, conn, app):
        return tuple(
            row[0]
            for row in conn.execute(
                """SELECT fingerprint FROM sova_control.effects
            WHERE tenant_id=%s AND application_id=%s AND status IN ('prepared','in_flight','unknown')
            ORDER BY fingerprint""",
                (self.tenant_id, app),
            )
        )

    def require_current(self, conn, lease, *, lock=True):
        if lease.tenant_id != self.tenant_id:
            raise ContractError("Execution tenant mismatch")
        row = conn.execute(
            """SELECT operation_id,owner_id,token,epoch,valid_until,mode,
            proof_valid_until,recovery_effects FROM sova_control.app_execution
            WHERE tenant_id=%s AND application_id=%s"""
            + (" FOR UPDATE" if lock else ""),
            (self.tenant_id, lease.application_id),
        ).fetchone()
        now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        if (
            not row
            or (row[0], row[1], row[2], row[3], row[5])
            != (
                lease.operation_id,
                lease.owner_id,
                lease.token,
                lease.epoch,
                str(lease.mode),
            )
            or row[4] <= now
            or (lease.mode == ExecutionMode.RECONCILE and row[6] <= now)
        ):
            raise LeaseLost("App execution lease expired or changed")
        return row, now

    def require_operation(self, conn, app, operation_id, *, recovery=False):
        row = conn.execute(
            """SELECT security_hold,status FROM sova_control.operations
            WHERE tenant_id=%s AND application_id=%s AND operation_id=%s FOR SHARE""",
            (self.tenant_id, app, operation_id),
        ).fetchone()
        if not row:
            raise ContractError("Operation not registered for this app")
        if not recovery and (
            row[0]
            or row[1]
            in (
                "cancelled",
                "response_verified",
                "phase_verified",
                "failed",
                "blocked",
                "finalized",
                "recovered",
                "recovery_required",
            )
        ):
            raise ContractError("Operation is held or cannot mutate")

    def _event(self, conn, lease, action, proof=None):
        conn.execute(
            """INSERT INTO sova_control.execution_events
            (tenant_id,application_id,operation_id,epoch,owner_id,action,proof_digest)
            VALUES(%s,%s,%s,%s,%s,%s,%s)""",
            (
                self.tenant_id,
                lease.application_id,
                lease.operation_id,
                lease.epoch,
                lease.owner_id,
                action,
                proof,
            ),
        )

    def acquire(self, application_id, operation_id, owner_id, *, lease_seconds=30):
        self.duration(lease_seconds)
        identifier(owner_id, "owner_id")
        with self.lifecycle.transaction() as conn:
            row = self.lock_app(conn, application_id)
            self.require_operation(conn, application_id, operation_id)
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if row[2] is not None and row[4] > now:
                raise ExecutionBusy("App already has an execution owner")
            if self.pending(conn, application_id):
                raise RecoveryRequired("Unresolved effects block owner replacement")
            token = uuid4().hex
            epoch = row[3] + 1
            deadline = conn.execute(
                """UPDATE sova_control.app_execution SET operation_id=%s,
                owner_id=%s,token=%s,epoch=%s,valid_until=clock_timestamp()+make_interval(secs=>%s),
                mode='mutate',proof_digest=NULL,proof_valid_until=NULL,recovery_effects=NULL
                WHERE tenant_id=%s AND application_id=%s RETURNING valid_until""",
                (
                    operation_id,
                    owner_id,
                    token,
                    epoch,
                    lease_seconds,
                    self.tenant_id,
                    application_id,
                ),
            ).fetchone()[0]
            lease = ExecutionLease(
                self.tenant_id,
                application_id,
                operation_id,
                owner_id,
                token,
                epoch,
                deadline,
                ExecutionMode.MUTATE,
            )
            self._event(conn, lease, "acquired")
            return lease

    def acquire_recovery(self, proof, owner_id, *, lease_seconds=30):
        """Internal persistence boundary: proof must be authenticated by its caller."""
        self.duration(lease_seconds)
        identifier(owner_id, "owner_id")
        if proof.tenant_id != self.tenant_id:
            raise ContractError("Recovery proof tenant mismatch")
        with self.lifecycle.transaction() as conn:
            row = self.lock_app(conn, proof.application_id)
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if row[2] is not None and row[4] > now:
                raise ExecutionBusy("Prior owner still has a live lease")
            pending = self.pending(conn, proof.application_id)
            if (
                not pending
                or row[0] != proof.operation_id
                or row[3] != proof.source_epoch
                or pending_digest(pending) != proof.pending_effects_digest
                or not proof.observed_at <= now < proof.valid_until
            ):
                raise ContractError(
                    "Recovery proof does not bind current pending effects"
                )
            self.require_operation(
                conn, proof.application_id, proof.operation_id, recovery=True
            )
            token = uuid4().hex
            epoch = row[3] + 1
            deadline = conn.execute(
                """UPDATE sova_control.app_execution SET owner_id=%s,token=%s,epoch=%s,
                valid_until=LEAST(clock_timestamp()+make_interval(secs=>%s),%s),mode='reconcile',
                proof_digest=%s,proof_valid_until=%s,recovery_effects=%s
                WHERE tenant_id=%s AND application_id=%s RETURNING valid_until""",
                (
                    owner_id,
                    token,
                    epoch,
                    lease_seconds,
                    proof.valid_until,
                    proof.artifact_digest,
                    proof.valid_until,
                    Jsonb(list(pending)),
                    self.tenant_id,
                    proof.application_id,
                ),
            ).fetchone()[0]
            lease = ExecutionLease(
                self.tenant_id,
                proof.application_id,
                proof.operation_id,
                owner_id,
                token,
                epoch,
                deadline,
                ExecutionMode.RECONCILE,
            )
            self._event(conn, lease, "recovery_acquired", proof.artifact_digest)
            return lease

    def renew(self, lease, *, lease_seconds=30):
        self.duration(lease_seconds)
        with self.lifecycle.transaction() as conn:
            self.require_current(conn, lease)
            deadline = conn.execute(
                """UPDATE sova_control.app_execution SET valid_until=
                LEAST(clock_timestamp()+make_interval(secs=>%s),COALESCE(proof_valid_until,'infinity'::timestamptz))
                WHERE tenant_id=%s AND application_id=%s RETURNING valid_until""",
                (lease_seconds, self.tenant_id, lease.application_id),
            ).fetchone()[0]
            updated = ExecutionLease(
                lease.tenant_id,
                lease.application_id,
                lease.operation_id,
                lease.owner_id,
                lease.token,
                lease.epoch,
                deadline,
                lease.mode,
            )
            self._event(conn, updated, "renewed")
            return updated

    def release(self, lease):
        with self.lifecycle.transaction() as conn:
            self._release_locked(conn, lease)

    def _release_locked(self, conn, lease, proof_digest=None):
        self.require_current(conn, lease)
        if self.pending(conn, lease.application_id):
            raise RecoveryRequired("Cannot release unresolved effects")
        conn.execute(
            """UPDATE sova_control.app_execution SET owner_id=NULL,token=NULL,valid_until=NULL,
            mode=NULL,proof_digest=NULL,proof_valid_until=NULL,recovery_effects=NULL
            WHERE tenant_id=%s AND application_id=%s""",
            (self.tenant_id, lease.application_id),
        )
        self._event(conn, lease, "released", proof_digest)
