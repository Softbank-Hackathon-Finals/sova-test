"""A terminal receipt binds the final readback, plan, epoch and verification window."""

from dataclasses import dataclass
from datetime import datetime
import hashlib
from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    EffectObservation,
    EffectStatus,
    canonical_json,
    identifier,
    utc,
)
from sova.security.domain.governance import scope_document


@dataclass(frozen=True, slots=True)
class ResponseCompletion:
    command: EffectCommand
    observation: EffectObservation
    owner_id: str
    verified_until: datetime

    def __post_init__(self):
        if not isinstance(self.command, EffectCommand) or not isinstance(
            self.observation, EffectObservation
        ):
            raise ContractError("Typed response completion command/readback required")
        identifier(self.owner_id)
        object.__setattr__(self, "verified_until", utc(self.verified_until))
        c, o = self.command, self.observation
        if (
            c.action != "switch_route"
            or c.step_id != "switch_route"
            or o.status != EffectStatus.APPLIED
            or o.command_digest != c.fingerprint
            or o.scope != c.scope
        ):
            raise ContractError("Final applied response route readback required")
        if not o.observed_at < self.verified_until <= c.expires_at:
            raise ContractError("Completion cannot outlive verification or plan")
        canonical_json(self.document, limit=16384)

    @property
    def document(self):
        c, o = self.command, self.observation
        return {
            "schema_version": 1,
            "scope": scope_document(c.scope),
            "operation_id": c.operation_id,
            "plan_digest": c.plan_digest,
            "epoch": c.fencing_epoch,
            "owner_id": self.owner_id,
            "command_digest": c.fingerprint,
            "observed_at": o.observed_at.isoformat(),
            "verified_until": self.verified_until.isoformat(),
            "evidence": o.evidence,
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=16384).encode()
        ).hexdigest()
