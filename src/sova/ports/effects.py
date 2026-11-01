from __future__ import annotations

from datetime import datetime
from typing import Protocol

from sova.domain.contracts import (
    EffectCommand,
    EffectObservation,
    EffectRecord,
    EffectStatus,
)


class EffectConflict(RuntimeError):
    pass


class EffectAdapter(Protocol):
    adapter_id: str

    def validate(self, command: EffectCommand) -> None:
        """Reject all unregistered scopes, actions, or non-whitelisted parameters."""
        ...

    def apply(self, command: EffectCommand) -> None:
        """Issue only the bounded command. Never retry an uncertain mutation."""
        ...

    def readback(self, command: EffectCommand, now: datetime) -> EffectObservation:
        """Read actual owned state. This method must not cause a mutation."""
        ...


class EffectJournal(Protocol):
    def reserve(self, command: EffectCommand) -> EffectRecord: ...

    def get(self, command: EffectCommand) -> EffectRecord: ...

    def transition(
        self,
        command: EffectCommand,
        expected_revision: int,
        expected_status: EffectStatus,
        status: EffectStatus,
        observation: EffectObservation | None = None,
    ) -> EffectRecord: ...
