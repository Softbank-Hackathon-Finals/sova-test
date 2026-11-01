"""A phase receipt is historical proof, never full migration qualification."""

from dataclasses import dataclass
from datetime import datetime
import hashlib

from sova.domain.contracts import (
    ContractError,
    EffectObservation,
    EffectStatus,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova.domain.governance import scope_document
from sova.domain.migration_phases import MigrationPhase


@dataclass(frozen=True, slots=True)
class PhaseCompletion:
    tenant_id: str
    application_id: str
    operation_id: str
    plan_digest: str
    program_digest: str
    phase: MigrationPhase
    epoch: int
    owner_id: str
    verified_until: datetime
    observations: tuple[EffectObservation, ...]

    def __post_init__(self):
        for field in ("tenant_id", "application_id", "operation_id", "owner_id"):
            identifier(getattr(self, field), field)
        digest(self.plan_digest)
        digest(self.program_digest)
        if (
            not isinstance(self.phase, MigrationPhase)
            or type(self.epoch) is not int
            or self.epoch < 1
        ):
            raise ContractError("Typed phase and executor epoch required")
        object.__setattr__(self, "verified_until", utc(self.verified_until))
        if (
            type(self.observations) is not tuple
            or not 1 <= len(self.observations) <= 128
        ):
            raise ContractError("Bounded immutable final observations required")
        seen = set()
        for o in self.observations:
            if (
                not isinstance(o, EffectObservation)
                or o.status != EffectStatus.APPLIED
                or (o.scope.tenant_id, o.scope.application_id)
                != (self.tenant_id, self.application_id)
                or o.command_digest in seen
                or o.observed_at >= self.verified_until
            ):
                raise ContractError("Unique applied scoped final observations required")
            seen.add(o.command_digest)
        canonical_json(self.document, limit=262144)

    @property
    def document(self):
        return {
            "schema_version": 1,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "operation_id": self.operation_id,
            "plan_digest": self.plan_digest,
            "program_digest": self.program_digest,
            "phase": str(self.phase),
            "epoch": self.epoch,
            "owner_id": self.owner_id,
            "verified_until": self.verified_until.isoformat(),
            "observations": [
                {
                    "scope": scope_document(o.scope),
                    "command_digest": o.command_digest,
                    "status": str(o.status),
                    "observed_at": o.observed_at.isoformat(),
                    "evidence": o.evidence,
                }
                for o in self.observations
            ],
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=262144).encode()
        ).hexdigest()
