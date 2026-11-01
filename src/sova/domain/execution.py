"""App-scoped execution ownership, separate from outbox delivery leases."""

import hashlib
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sova.domain.contracts import ContractError, canonical_json, digest, identifier, utc


class ExecutionMode(StrEnum):
    MUTATE = "mutate"
    RECONCILE = "reconcile"


def pending_digest(fingerprints: tuple[str, ...]) -> str:
    if type(fingerprints) is not tuple or len(set(fingerprints)) != len(fingerprints):
        raise ContractError("Unique immutable pending effect digests required")
    for item in fingerprints:
        digest(item)
    return hashlib.sha256(
        canonical_json({"pending": sorted(fingerprints)}, limit=262144).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ExecutionLease:
    tenant_id: str
    application_id: str
    operation_id: str
    owner_id: str
    token: str
    epoch: int
    valid_until: datetime
    mode: ExecutionMode

    def __post_init__(self):
        for name in (
            "tenant_id",
            "application_id",
            "operation_id",
            "owner_id",
            "token",
        ):
            identifier(getattr(self, name), name)
        if (
            type(self.epoch) is not int
            or self.epoch < 1
            or not isinstance(self.mode, ExecutionMode)
        ):
            raise ContractError("Typed execution mode and positive epoch required")
        object.__setattr__(self, "valid_until", utc(self.valid_until))


@dataclass(frozen=True, slots=True)
class QuiescenceProof:
    """Issued only after a trusted verifier proves old worker AND requests settled.

    The artifact digest is not authentication; the recovery application must
    authenticate issuer and proof content before passing it to the repository.
    """

    tenant_id: str
    application_id: str
    operation_id: str
    source_epoch: int
    pending_effects_digest: str
    artifact_digest: str
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        for name in ("tenant_id", "application_id", "operation_id"):
            identifier(getattr(self, name), name)
        if type(self.source_epoch) is not int or self.source_epoch < 1:
            raise ContractError("Positive source epoch required")
        digest(self.pending_effects_digest)
        digest(self.artifact_digest)
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Positive proof validity required")
