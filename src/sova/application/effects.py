"""Durable intent before effects, explicit readback after uncertainty.

No worker lease, cloud fencing, multi-tenant authentication, or distributed
exactly-once guarantee is implemented by this use case.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Callable

from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    EffectObservation,
    EffectRecord,
    EffectStatus,
    ExecutionPermit,
    validate_permit,
)
from sova.ports.effects import EffectAdapter, EffectJournal


class UncertainEffect(RuntimeError):
    """The caller must retain the operation and reconcile; do not replay apply."""


class EffectExecutor:
    def __init__(
        self,
        journal: EffectJournal,
        *,
        authorize: Callable[[EffectCommand, ExecutionPermit, datetime, bool], None],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.journal, self.authorize, self.clock = journal, authorize, clock

    def check(
        self,
        command: EffectCommand,
        permit: ExecutionPermit,
        adapter: EffectAdapter,
        *,
        mutation: bool = True,
    ) -> datetime:
        now = self.clock()
        validate_permit(command, permit, now, mutation=mutation)
        if adapter.adapter_id != command.adapter_id:
            raise ContractError("Adapter identity mismatch")
        adapter.validate(command)
        self.authorize(command, permit, now, mutation)
        # Authorization/remote policy lookups can take time. Do not dispatch
        # using a permit that expired while its checks were running.
        checked_at = self.clock()
        if checked_at < now:
            raise ContractError("Execution clock moved backwards")
        validate_permit(command, permit, checked_at, mutation=mutation)
        return checked_at

    def _observe(
        self, command: EffectCommand, adapter: EffectAdapter
    ) -> EffectObservation:
        now = self.clock()
        observed = adapter.readback(command, now)
        if (
            not isinstance(observed, EffectObservation)
            or observed.scope != command.scope
            or observed.command_digest != command.fingerprint
            or observed.observed_at != now
        ):
            raise ContractError("Readback is not bound to this command and observation")
        return observed

    def execute(
        self, command: EffectCommand, permit: ExecutionPermit, adapter: EffectAdapter
    ) -> EffectRecord:
        self.check(command, permit, adapter)
        record = self.journal.reserve(command)
        if record.status == EffectStatus.APPLIED:
            return record  # Historical receipt, not a fresh health claim.
        if record.status != EffectStatus.PREPARED:
            raise UncertainEffect(
                "Existing effect cannot be replayed; inspect its record"
            )
        record = self.journal.transition(
            command,
            record.revision,
            EffectStatus.PREPARED,
            EffectStatus.IN_FLIGHT,
        )
        # Recheck expiry/holds after durable claim and immediately before apply.
        try:
            self.check(command, permit, adapter)
        except Exception:
            self.journal.transition(
                command,
                record.revision,
                EffectStatus.IN_FLIGHT,
                EffectStatus.NOT_APPLIED,
            )
            raise
        try:
            adapter.apply(command)
            observation = self._observe(command, adapter)
        except Exception as error:
            self.journal.transition(
                command,
                record.revision,
                EffectStatus.IN_FLIGHT,
                EffectStatus.UNKNOWN,
            )
            raise UncertainEffect(
                "External effect requires read-only reconciliation"
            ) from error
        record = self.journal.transition(
            command,
            record.revision,
            EffectStatus.IN_FLIGHT,
            observation.status,
            observation,
        )
        if record.status != EffectStatus.APPLIED:
            raise UncertainEffect("Readback did not confirm the requested state")
        return record

    def reconcile(
        self, command: EffectCommand, permit: ExecutionPermit, adapter: EffectAdapter
    ) -> EffectRecord:
        # authorize(..., mutation=False) must establish that an old executor and
        # its remote requests can no longer issue a late conflicting change.
        # A database lease expiring or a matching GET alone is insufficient.
        self.check(command, permit, adapter, mutation=False)
        record = self.journal.get(command)
        if record.status in (EffectStatus.APPLIED, EffectStatus.NOT_APPLIED):
            return record
        if record.status not in (EffectStatus.IN_FLIGHT, EffectStatus.UNKNOWN):
            raise ContractError("No issued effect to reconcile")
        observation = self._observe(command, adapter)
        return self.journal.transition(
            command,
            record.revision,
            record.status,
            observation.status,
            observation,
        )

    def cancel_prepared(
        self, command: EffectCommand, permit: ExecutionPermit, adapter: EffectAdapter
    ) -> EffectRecord:
        self.check(command, permit, adapter, mutation=False)
        record = self.journal.get(command)
        if record.status != EffectStatus.PREPARED:
            raise ContractError("Only a never-claimed intent can be cancelled")
        return self.journal.transition(
            command,
            record.revision,
            EffectStatus.PREPARED,
            EffectStatus.NOT_APPLIED,
        )
