"""Shared effect journal guarded by app ownership in every write transaction."""

from dataclasses import asdict
from datetime import datetime

from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    EffectObservation,
    EffectRecord,
    EffectStatus,
    ResourceScope,
)
from sova.domain.execution import ExecutionMode
from sova.ports.effects import EffectConflict


_TRANSITIONS = {
    EffectStatus.PREPARED: {EffectStatus.IN_FLIGHT, EffectStatus.NOT_APPLIED},
    EffectStatus.IN_FLIGHT: {
        EffectStatus.APPLIED,
        EffectStatus.NOT_APPLIED,
        EffectStatus.UNKNOWN,
    },
    EffectStatus.UNKNOWN: {EffectStatus.UNKNOWN, EffectStatus.APPLIED},
}


class PostgresEffectJournal:
    def __init__(self, ownership, lease):
        self.ownership, self.lease = ownership, lease
        self.lifecycle = ownership.lifecycle
        if lease.tenant_id != ownership.tenant_id:
            raise ContractError("Effect journal tenant mismatch")

    def require_command(self, conn, command, *, mutation):
        row, database_now = self.ownership.require_current(conn, self.lease)
        if (
            command.scope.tenant_id,
            command.scope.application_id,
            command.operation_id,
        ) != (self.lease.tenant_id, self.lease.application_id, self.lease.operation_id):
            raise ContractError("Command is outside execution ownership")
        operation = conn.execute(
            """SELECT plan_digest,approval_id,approval_revision,plan_id FROM sova_control.operations
            WHERE tenant_id=%s AND application_id=%s AND operation_id=%s""",
            (self.lease.tenant_id, self.lease.application_id, self.lease.operation_id),
        ).fetchone()
        if not operation or operation[0] != command.plan_digest:
            raise ContractError("Command plan does not match operation")
        plan = self.lifecycle._get_plan(conn, self.lease.application_id, operation[3])
        expected = plan.command(
            command.step_id,
            operation_id=command.operation_id,
            epoch=command.fencing_epoch,
        )
        if expected.fingerprint != command.fingerprint:
            raise ContractError("Command differs from the stored approved plan step")
        if mutation:
            if (
                self.lease.mode != ExecutionMode.MUTATE
                or command.fencing_epoch != self.lease.epoch
            ):
                raise ContractError("Execution mode or epoch cannot mutate")
            self.ownership.require_operation(
                conn, self.lease.application_id, self.lease.operation_id
            )
            approved = self.lifecycle._get_approval(
                conn, self.lease.application_id, operation[1]
            )
            if approved.revoked or approved.revision != operation[2]:
                raise ContractError("Operation approval revoked or changed")
            # A slow/skewed application clock cannot extend a DB-backed grant.
            approved.approval.require_valid(plan, database_now)
        elif command.fencing_epoch > self.lease.epoch:
            raise ContractError("Cannot inspect a future execution epoch")
        return row

    def authorize(self, command, permit, now, mutation):
        with self.lifecycle.transaction() as conn:
            row = self.require_command(conn, command, mutation=mutation)
            if not mutation and self.lease.mode != ExecutionMode.RECONCILE:
                raise ContractError(
                    "Uncertain effects require a verified recovery lease"
                )
            if (
                not mutation
                and self.lease.mode == ExecutionMode.RECONCILE
                and command.fingerprint not in row[7]
            ):
                raise ContractError("Recovery proof does not include this effect")

    def _row(self, conn, command):
        row = conn.execute(
            """SELECT fingerprint,command_document,status,revision,observation_document,
            environment_id,resource_id,operation_id FROM sova_control.effects
            WHERE tenant_id=%s AND application_id=%s AND idempotency_key=%s""",
            (self.lease.tenant_id, self.lease.application_id, command.idempotency_key),
        ).fetchone()
        if not row:
            return None
        stored = EffectCommand.from_document(row[1])
        if (
            stored.fingerprint != row[0]
            or stored.scope.tenant_id != self.lease.tenant_id
            or stored.scope.application_id != self.lease.application_id
            or (
                stored.scope.environment_id,
                stored.scope.resource_id,
                stored.operation_id,
            )
            != (row[5], row[6], row[7])
            or stored.idempotency_key != command.idempotency_key
        ):
            raise ContractError("Stored effect integrity mismatch")
        if stored.fingerprint != command.fingerprint:
            # Reuse only completed receipts under a strictly newer epoch and
            # otherwise identical intent. Never restamp or replay unknown work.
            if not (
                row[2] == str(EffectStatus.APPLIED)
                and stored.fencing_epoch < command.fencing_epoch
                and stored.intent_fingerprint == command.intent_fingerprint
            ):
                raise EffectConflict("Idempotency key has different effect input")
        return row

    @staticmethod
    def _decode(row):
        observation = None
        if row[4]:
            data = row[4]
            observation = EffectObservation(
                ResourceScope(**data["scope"]),
                data["command_digest"],
                EffectStatus(data["status"]),
                datetime.fromisoformat(data["observed_at"]),
                data["evidence_json"],
            )
        return EffectRecord(
            EffectCommand.from_document(row[1]),
            EffectStatus(row[2]),
            row[3],
            observation,
        )

    def _event(self, conn, command, revision, status, observation=None):
        conn.execute(
            """INSERT INTO sova_control.effect_events
            (tenant_id,application_id,idempotency_key,revision,status,observation_document)
            VALUES(%s,%s,%s,%s,%s,%s)""",
            (
                self.lease.tenant_id,
                self.lease.application_id,
                command.idempotency_key,
                revision,
                str(status),
                Jsonb(observation) if observation else None,
            ),
        )

    def reserve(self, command):
        with self.lifecycle.transaction() as conn:
            self.require_command(conn, command, mutation=True)
            row = self._row(conn, command)
            if row:
                return self._decode(row)
            try:
                conn.execute(
                    """INSERT INTO sova_control.effects
                    (tenant_id,application_id,environment_id,resource_id,operation_id,idempotency_key,
                     fingerprint,command_document,status,revision)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,'prepared',1)""",
                    (
                        self.lease.tenant_id,
                        self.lease.application_id,
                        command.scope.environment_id,
                        command.scope.resource_id,
                        command.operation_id,
                        command.idempotency_key,
                        command.fingerprint,
                        Jsonb(command.document),
                    ),
                )
            except UniqueViolation as error:
                raise EffectConflict("Unresolved effect holds resource") from error
            self._event(conn, command, 1, EffectStatus.PREPARED)
            return self._decode(self._row(conn, command))

    def get(self, command):
        with self.lifecycle.transaction() as conn:
            self.require_command(conn, command, mutation=False)
            row = self._row(conn, command)
            if not row:
                raise EffectConflict("Effect not registered")
            return self._decode(row)

    def transition(
        self, command, expected_revision, expected_status, status, observation=None
    ):
        if type(expected_revision) is not int or expected_revision < 1:
            raise ContractError("Positive effect revision required")
        if (
            not isinstance(expected_status, EffectStatus)
            or not isinstance(status, EffectStatus)
            or status not in _TRANSITIONS.get(expected_status, set())
        ):
            raise ContractError("Invalid effect transition")
        if observation is not None and (
            not isinstance(observation, EffectObservation)
            or observation.scope != command.scope
            or observation.command_digest != command.fingerprint
            or observation.status != status
        ):
            raise ContractError("Effect evidence binding mismatch")
        if status == EffectStatus.APPLIED and observation is None:
            raise ContractError("Applied effect needs evidence")
        data = None
        if observation:
            data = {
                **asdict(observation),
                "observed_at": observation.observed_at.isoformat(),
                "status": str(observation.status),
            }
        with self.lifecycle.transaction() as conn:
            # Completion is bookkeeping, not a new provider call. A still-live
            # owner may record an issued effect after approval revocation/hold.
            # Only the dispatch transition requires a currently valid approval.
            grant = self.require_command(
                conn, command, mutation=status == EffectStatus.IN_FLIGHT
            )
            if (
                self.lease.mode == ExecutionMode.MUTATE
                and command.fencing_epoch != self.lease.epoch
            ):
                raise ContractError("Old epoch cannot complete an effect")
            if self.lease.mode == ExecutionMode.RECONCILE:
                if command.fingerprint not in grant[7] or not (
                    (
                        expected_status
                        in (EffectStatus.IN_FLIGHT, EffectStatus.UNKNOWN)
                        and status in (EffectStatus.APPLIED, EffectStatus.UNKNOWN)
                    )
                    or (
                        expected_status == EffectStatus.PREPARED
                        and status == EffectStatus.NOT_APPLIED
                    )
                ):
                    raise ContractError(
                        "Recovery lease permits only bound readback or unissued cancellation"
                    )
            self._row(conn, command)
            changed = conn.execute(
                """UPDATE sova_control.effects SET status=%s,revision=revision+1,observation_document=%s
                WHERE tenant_id=%s AND application_id=%s AND idempotency_key=%s
                  AND fingerprint=%s AND revision=%s AND status=%s RETURNING revision""",
                (
                    str(status),
                    Jsonb(data) if data else None,
                    self.lease.tenant_id,
                    self.lease.application_id,
                    command.idempotency_key,
                    command.fingerprint,
                    expected_revision,
                    str(expected_status),
                ),
            ).fetchone()
            if not changed:
                raise EffectConflict("Effect revision or owner changed")
            self._event(conn, command, changed[0], status, data)
            return self._decode(self._row(conn, command))
