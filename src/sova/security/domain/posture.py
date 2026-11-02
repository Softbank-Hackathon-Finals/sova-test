"""Sanitized configuration findings are narrower than runtime security proof."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova.domain.evidence import EvidenceRecord, RevisionSet, VerificationResult
from sova.security.domain.governance import ControlFamily, scope_document


class FindingBasis(StrEnum):
    CONFIGURATION = "configuration"
    RUNTIME = "runtime_probe"


@dataclass(frozen=True, slots=True)
class PostureFinding:
    control_id: str
    family: ControlFamily
    scope: ResourceScope
    resource_revision: str
    result: VerificationResult
    basis: FindingBasis
    reason_code: str
    source_digest: str
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        for key in ("control_id", "resource_revision", "reason_code"):
            identifier(getattr(self, key), key)
        if (
            not isinstance(self.family, ControlFamily)
            or not isinstance(self.scope, ResourceScope)
            or not isinstance(self.result, VerificationResult)
            or not isinstance(self.basis, FindingBasis)
        ):
            raise ContractError("Typed posture finding required")
        if self.result == VerificationResult.NOT_APPLICABLE:
            raise ContractError("Posture collector cannot grant a security exception")
        digest(self.source_digest)
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Invalid finding validity")

    @property
    def document(self):
        return {
            "control_id": self.control_id,
            "family": str(self.family),
            "scope": scope_document(self.scope),
            "resource_revision": self.resource_revision,
            "result": str(self.result),
            "basis": str(self.basis),
            "reason_code": self.reason_code,
            "source_digest": self.source_digest,
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()

    @property
    def obligation_id(self):
        key = hashlib.sha256(
            canonical_json(scope_document(self.scope)).encode()
        ).hexdigest()
        return "posture:" + self.control_id + ":" + key

    @property
    def verifier_version(self):
        return "sova-kubernetes-" + str(self.basis) + "-v1"

    def evidence(self, revisions: RevisionSet):
        # Trust/issuer validation remains mandatory at the receiving boundary.
        return EvidenceRecord(
            "finding:" + self.fingerprint,
            self.obligation_id,
            self.scope,
            revisions,
            self.verifier_version,
            self.observed_at,
            self.valid_until,
            self.result,
            "posture:" + self.fingerprint,
            self.fingerprint,
        )
