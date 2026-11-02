"""Compare protection outcomes, never provider feature names.

The policy authority selects controls and verifier versions. This model does not
authenticate provider facts, map IAM permissions to RBAC, or grant exceptions.
"""

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
from sova.domain.evidence import (
    EvidenceRecord,
    Gate,
    RevisionSet,
    VerificationObligation,
    VerificationResult,
    evaluate_gate,
)
from sova.security.domain.governance import ControlFamily, scope_document


class Availability(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ProtectionEndpoint:
    scope: ResourceScope
    provider: str
    implementation: str
    provider_capability: Availability
    adapter_implementation: Availability
    source_digest: str
    configuration_digest: str
    environment_digest: str
    verifier_version: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or any(
            not isinstance(v, Availability)
            for v in (self.provider_capability, self.adapter_implementation)
        ):
            raise ContractError("Typed protection scope and availability required")
        for key in ("provider", "implementation", "verifier_version"):
            identifier(getattr(self, key), key)
        for key in ("source_digest", "configuration_digest", "environment_digest"):
            digest(getattr(self, key))

    def revisions(self, policy_digest):
        return RevisionSet(
            self.source_digest,
            self.configuration_digest,
            policy_digest,
            self.environment_digest,
        )

    @property
    def document(self):
        return {
            "scope": scope_document(self.scope),
            "provider": self.provider,
            "implementation": self.implementation,
            "provider_capability": str(self.provider_capability),
            "adapter_implementation": str(self.adapter_implementation),
            "source_digest": self.source_digest,
            "configuration_digest": self.configuration_digest,
            "environment_digest": self.environment_digest,
            "verifier_version": self.verifier_version,
        }


@dataclass(frozen=True, slots=True)
class ProtectionRequirement:
    requirement_id: str
    family: ControlFamily
    objective: str
    source: ProtectionEndpoint
    target: ProtectionEndpoint
    required: bool = True

    def __post_init__(self):
        identifier(self.requirement_id)
        identifier(self.objective, limit=1024)
        if (
            not isinstance(self.family, ControlFamily)
            or type(self.required) is not bool
        ):
            raise ContractError("Typed protection family and required flag needed")
        if not isinstance(self.source, ProtectionEndpoint) or not isinstance(
            self.target, ProtectionEndpoint
        ):
            raise ContractError("Typed source and target endpoints required")
        a, b = self.source.scope, self.target.scope
        if (a.tenant_id, a.application_id) != (
            b.tenant_id,
            b.application_id,
        ) or a.environment_id == b.environment_id:
            raise ContractError("Distinct same-application environments required")
        if a.resource_id == b.resource_id:
            raise ContractError("Source and target cannot alias the same resource")

    def obligation(self, side):
        if side not in {"source", "target"}:
            raise ContractError("Invalid protection side")
        endpoint = getattr(self, side)
        return VerificationObligation(
            "parity:" + self.requirement_id + ":" + side,
            endpoint.scope,
            Gate.PREFLIGHT,
            endpoint.verifier_version,
            self.required,
        )

    @property
    def document(self):
        return {
            "requirement_id": self.requirement_id,
            "family": str(self.family),
            "objective": self.objective,
            "source": self.source.document,
            "target": self.target.document,
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class ProtectionPolicy:
    tenant_id: str
    application_id: str
    revision: int
    requirements: tuple[ProtectionRequirement, ...]
    issued_at: datetime
    valid_until: datetime
    profile_digest: str | None = None

    def __post_init__(self):
        identifier(self.tenant_id)
        identifier(self.application_id)
        if self.profile_digest is not None:
            digest(self.profile_digest)
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive protection policy revision required")
        if (
            type(self.requirements) is not tuple
            or not 1 <= len(self.requirements) <= 64
        ):
            raise ContractError("Bounded nonempty protection requirements required")
        ids = set()
        resource_revisions = {}
        for req in self.requirements:
            if not isinstance(req, ProtectionRequirement) or req.requirement_id in ids:
                raise ContractError("Unique typed protection requirements required")
            if (req.source.scope.tenant_id, req.source.scope.application_id) != (
                self.tenant_id,
                self.application_id,
            ):
                raise ContractError("Protection policy crosses application")
            ids.add(req.requirement_id)
            for endpoint in (req.source, req.target):
                binding = (
                    endpoint.source_digest,
                    endpoint.configuration_digest,
                    endpoint.environment_digest,
                )
                previous = resource_revisions.setdefault(endpoint.scope, binding)
                if previous != binding:
                    raise ContractError(
                        "One resource has contradictory protection revisions"
                    )
        if not any(req.required for req in self.requirements):
            raise ContractError("At least one mandatory protection required")
        object.__setattr__(
            self,
            "requirements",
            tuple(sorted(self.requirements, key=lambda r: r.requirement_id)),
        )
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Invalid protection policy lifetime")
        canonical_json(self.document, limit=131072)

    @property
    def document(self):
        document = {
            "schema_version": 1,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "revision": self.revision,
            "requirements": [r.document for r in self.requirements],
            "issued_at": self.issued_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }
        if self.profile_digest is not None:
            document["schema_version"] = 2
            document["profile_digest"] = self.profile_digest
        return document

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=131072).encode()
        ).hexdigest()


def assess_protection(policy, evidence, *, now):
    if not isinstance(policy, ProtectionPolicy):
        raise ContractError("Typed protection policy required")
    now = utc(now)
    if not policy.issued_at <= now < policy.valid_until:
        raise ContractError("Protection policy expired or future")
    if (
        type(evidence) is not tuple
        or len(evidence) > 512
        or any(not isinstance(e, EvidenceRecord) for e in evidence)
    ):
        raise ContractError("Bounded immutable evidence required")
    if len({e.evidence_id for e in evidence}) != len(evidence):
        raise ContractError("Duplicate protection evidence IDs")
    rows, expiries = [], [policy.valid_until]
    for req in policy.requirements:
        sides = {}
        for side in ("source", "target"):
            endpoint = getattr(req, side)
            obligation = req.obligation(side)
            decision = evaluate_gate(
                Gate.PREFLIGHT,
                (obligation,),
                evidence,
                endpoint.revisions(policy.fingerprint),
                now=now,
            ).decisions[0]
            state = {
                VerificationResult.PASS: "satisfied",
                VerificationResult.FAIL: "violated",
            }.get(decision.result, "unknown")
            reason = decision.reason
            if endpoint.provider_capability != Availability.AVAILABLE:
                state, reason = (
                    "unknown",
                    "provider_capability_" + str(endpoint.provider_capability),
                )
            elif endpoint.adapter_implementation != Availability.AVAILABLE:
                state, reason = (
                    "unknown",
                    "adapter_" + str(endpoint.adapter_implementation),
                )
            if decision.result == VerificationResult.NOT_APPLICABLE:
                state, reason = "unknown", "exception_not_supported"
            if decision.evidence_id:
                expiries.extend(
                    e.valid_until
                    for e in evidence
                    if e.evidence_id == decision.evidence_id
                )
            sides[side] = {
                "state": state,
                "reason": reason,
                "evidence_id": decision.evidence_id,
                "scope": scope_document(endpoint.scope),
                "provider": endpoint.provider,
                "implementation": endpoint.implementation,
                "provider_capability": str(endpoint.provider_capability),
                "adapter": str(endpoint.adapter_implementation),
            }
        before, after = sides["source"]["state"], sides["target"]["state"]
        if "unknown" in (before, after):
            comparison = "unverified"
        elif after == "violated":
            comparison = "regressed" if before == "satisfied" else "unmet"
        else:
            comparison = "maintained" if before == "satisfied" else "improved"
        rows.append(
            {
                "requirement_id": req.requirement_id,
                "family": str(req.family),
                "objective": req.objective,
                "required": req.required,
                **sides,
                "comparison": comparison,
                "accepted": comparison in {"maintained", "improved"},
            }
        )
    return {
        "policy_digest": policy.fingerprint,
        "assessed_at": now.isoformat(),
        "valid_until": min(expiries).isoformat(),
        "requirements": rows,
        "accepted": all(r["accepted"] for r in rows if r["required"]),
        "scope": "registered protection objectives only; not whole-environment equivalence",
    }
