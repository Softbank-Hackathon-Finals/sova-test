"""Revision-bound verification obligations and fail-closed gate decisions.

The evidence issuer must be authenticated outside this pure domain model.
An artifact hash or approved_by string is not a signature or authorization.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, StrEnum

from sova.domain.contracts import ContractError, ResourceScope, digest, identifier, utc


class Gate(IntEnum):
    REGISTRATION = 0
    REQUIREMENTS = 1
    CHANGE = 2
    STARTUP = 3
    BEHAVIOR = 4
    DATA = 5
    PROTECTION = 6
    PREFLIGHT = 7
    POSTFLIGHT = 8


class VerificationResult(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, slots=True)
class RevisionSet:
    source: str
    configuration: str
    policy: str
    environment: str

    def __post_init__(self):
        for value in (self.source, self.configuration, self.policy, self.environment):
            digest(value)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    obligation_id: str
    scope: ResourceScope
    revisions: RevisionSet
    verifier_version: str
    observed_at: datetime
    valid_until: datetime
    result: VerificationResult
    artifact_id: str
    artifact_digest: str
    justification: str | None = None
    approved_by: str | None = None

    def __post_init__(self):
        for field in (
            "evidence_id",
            "obligation_id",
            "verifier_version",
            "artifact_id",
        ):
            identifier(getattr(self, field), field)
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed evidence scope and revisions are required")
        if not isinstance(self.result, VerificationResult):
            raise ContractError("A typed verification result is required")
        digest(self.artifact_digest)
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Evidence must have a positive validity interval")
        if self.result == VerificationResult.NOT_APPLICABLE:
            identifier(self.justification, "not-applicable justification", limit=2048)
            identifier(self.approved_by, "not-applicable approver")


@dataclass(frozen=True, slots=True)
class VerificationObligation:
    obligation_id: str
    scope: ResourceScope
    due_gate: Gate
    verifier_version: str
    required: bool = True

    def __post_init__(self):
        identifier(self.obligation_id, "obligation_id")
        identifier(self.verifier_version, "verifier_version")
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.due_gate, Gate
        ):
            raise ContractError("Typed scope and gate are required")
        if type(self.required) is not bool:
            raise ContractError("required must be a boolean")


@dataclass(frozen=True, slots=True)
class ObligationDecision:
    obligation: VerificationObligation
    result: VerificationResult
    evidence_id: str | None
    reason: str


@dataclass(frozen=True, slots=True)
class GateDecision:
    gate: Gate
    accepted: bool
    decisions: tuple[ObligationDecision, ...]
    carry_forward: tuple[str, ...]


def evaluate_gate(
    gate: Gate,
    obligations: tuple[VerificationObligation, ...],
    evidence: tuple[EvidenceRecord, ...],
    revisions: RevisionSet,
    *,
    now: datetime,
) -> GateDecision:
    now = utc(now)
    if not isinstance(gate, Gate) or not isinstance(revisions, RevisionSet):
        raise ContractError("Typed gate and revisions are required")
    if (
        type(obligations) is not tuple
        or len(obligations) > 512
        or any(not isinstance(o, VerificationObligation) for o in obligations)
    ):
        raise ContractError("Bounded immutable verification obligations required")
    if (
        type(evidence) is not tuple
        or len(evidence) > 4096
        or any(not isinstance(e, EvidenceRecord) for e in evidence)
    ):
        raise ContractError("Bounded immutable evidence required")
    ids = [o.obligation_id for o in obligations]
    if len(ids) != len(set(ids)):
        raise ContractError("Duplicate obligation IDs")
    evidence_ids = [item.evidence_id for item in evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ContractError("Duplicate evidence IDs")
    decisions = []
    for obligation in obligations:
        candidates = [
            item
            for item in evidence
            if (
                item.obligation_id == obligation.obligation_id
                and item.scope == obligation.scope
                and item.revisions == revisions
                and item.verifier_version == obligation.verifier_version
            )
        ]
        result, chosen_id, reason = (
            VerificationResult.UNKNOWN,
            None,
            "missing_bound_evidence",
        )
        if candidates:
            latest_at = max(item.observed_at for item in candidates)
            latest = [item for item in candidates if item.observed_at == latest_at]
            if len(latest) != 1:
                reason = "ambiguous_latest_evidence"
            else:
                chosen = latest[0]
                chosen_id = chosen.evidence_id
                if chosen.observed_at > now:
                    reason = "future_observation"
                elif now >= chosen.valid_until:
                    reason = "expired_evidence"
                else:
                    result, reason = chosen.result, "current_bound_evidence"
        decisions.append(ObligationDecision(obligation, result, chosen_id, reason))
    resolved = {VerificationResult.PASS, VerificationResult.NOT_APPLICABLE}
    accepted = all(
        not d.obligation.required
        or d.obligation.due_gate > gate
        or d.result in resolved
        for d in decisions
    )
    # Include every future obligation even if it currently has passing evidence:
    # the next gate must recheck its freshness and exact environment revision.
    carry = tuple(
        d.obligation.obligation_id for d in decisions if d.obligation.due_gate > gate
    )
    return GateDecision(gate, accepted, tuple(decisions), carry)
