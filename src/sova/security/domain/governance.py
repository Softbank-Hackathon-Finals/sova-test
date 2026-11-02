"""Common security objectives; provider feature names are not security proof.

Authentication of policy, evidence and release signatures is a trusted boundary.
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


class ControlFamily(StrEnum):
    IDENTITY = "identity"
    SECRETS = "secrets"
    NETWORK = "network"
    ENCRYPTION = "encryption"
    AUDIT = "audit"
    POLICY = "policy"
    BACKUP = "backup"


@dataclass(frozen=True, slots=True)
class SecurityControl:
    family: ControlFamily
    obligation: VerificationObligation

    def __post_init__(self):
        if not isinstance(self.family, ControlFamily) or not isinstance(
            self.obligation, VerificationObligation
        ):
            raise ContractError("Typed security control required")
        if not self.obligation.required or self.obligation.due_gate > Gate.PREFLIGHT:
            raise ContractError("Security controls must be mandatory before execution")

    @property
    def document(self):
        o = self.obligation
        return {
            "family": str(self.family),
            "obligation_id": o.obligation_id,
            "scope": scope_document(o.scope),
            "due_gate": int(o.due_gate),
            "verifier_version": o.verifier_version,
        }


def scope_document(scope):
    return {
        key: getattr(scope, key)
        for key in ("tenant_id", "application_id", "environment_id", "resource_id")
    }


@dataclass(frozen=True, slots=True)
class GovernancePolicy:
    tenant_id: str
    application_id: str
    revision: int
    controls: tuple[SecurityControl, ...]
    issued_at: datetime
    valid_until: datetime

    def __post_init__(self):
        identifier(self.tenant_id)
        identifier(self.application_id)
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive policy revision required")
        if type(self.controls) is not tuple or not 1 <= len(self.controls) <= 128:
            raise ContractError("Bounded nonempty controls required")
        ids = set()
        for control in self.controls:
            if not isinstance(control, SecurityControl):
                raise ContractError("Typed security controls required")
            scope = control.obligation.scope
            if (scope.tenant_id, scope.application_id) != (
                self.tenant_id,
                self.application_id,
            ):
                raise ContractError("Policy crosses tenant/application")
            if control.obligation.obligation_id in ids:
                raise ContractError("Duplicate security obligation")
            ids.add(control.obligation.obligation_id)
        object.__setattr__(
            self,
            "controls",
            tuple(sorted(self.controls, key=lambda c: c.obligation.obligation_id)),
        )
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Invalid policy validity")
        canonical_json(self.document, limit=131072)

    @property
    def document(self):
        return {
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "revision": self.revision,
            "controls": [c.document for c in self.controls],
            "issued_at": self.issued_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=131072).encode()
        ).hexdigest()

    def require_current(self, now):
        if not self.issued_at <= utc(now) < self.valid_until:
            raise ContractError("Security policy expired or not yet valid")


def assess_governance(policy, evidence, revisions, *, now):
    if not isinstance(policy, GovernancePolicy) or not isinstance(
        revisions, RevisionSet
    ):
        raise ContractError("Typed governance policy and revisions required")
    policy.require_current(now)
    if revisions.policy != policy.fingerprint:
        raise ContractError("Security policy revision mismatch")
    if (
        type(evidence) is not tuple
        or len(evidence) > 512
        or any(not isinstance(e, EvidenceRecord) for e in evidence)
    ):
        raise ContractError("Bounded immutable security evidence required")
    decision = evaluate_gate(
        Gate.PREFLIGHT,
        tuple(c.obligation for c in policy.controls),
        evidence,
        revisions,
        now=now,
    )
    families = {c.obligation.obligation_id: c.family for c in policy.controls}
    rows = []
    for item in decision.decisions:
        # N/A strings and ordinary approvals cannot waive required controls.
        state = {
            VerificationResult.PASS: "satisfied",
            VerificationResult.FAIL: "violated",
        }.get(item.result, "unknown")
        rows.append(
            {
                "control_id": item.obligation.obligation_id,
                "family": str(families[item.obligation.obligation_id]),
                "scope": scope_document(item.obligation.scope),
                "state": state,
                "evidence_id": item.evidence_id,
                "reason": "security-exception-not-supported"
                if item.result == VerificationResult.NOT_APPLICABLE
                else item.reason,
            }
        )
    return {
        "accepted": all(row["state"] == "satisfied" for row in rows),
        "policy_digest": policy.fingerprint,
        "controls": rows,
        "assessed_at": utc(now).isoformat(),
        "valid_until": min(
            (
                policy.valid_until,
                *(
                    record.valid_until
                    for record in evidence
                    if record.evidence_id in {row["evidence_id"] for row in rows}
                ),
            )
        ).isoformat(),
    }


@dataclass(frozen=True, slots=True)
class SecurityHold:
    hold_id: str
    scope: ResourceScope
    raised_by: str
    reason: str
    raised_at: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed hold scope required")
        identifier(self.hold_id)
        identifier(self.raised_by)
        identifier(self.reason, limit=1024)
        object.__setattr__(self, "raised_at", utc(self.raised_at))

    @property
    def document(self):
        return {
            "hold_id": self.hold_id,
            "scope": scope_document(self.scope),
            "raised_by": self.raised_by,
            "reason": self.reason,
            "raised_at": self.raised_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class HoldRelease:
    hold_id: str
    scope: ResourceScope
    revisions: RevisionSet
    expected_revision: int
    requested_by: str
    approved_by: str
    reason: str
    evidence_id: str
    evidence_digest: str
    approved_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed release scope and revisions required")
        for key in ("hold_id", "requested_by", "approved_by", "reason", "evidence_id"):
            identifier(getattr(self, key), key, limit=1024 if key == "reason" else 256)
        if type(self.expected_revision) is not int or self.expected_revision < 1:
            raise ContractError("Positive hold revision required")
        if self.requested_by == self.approved_by:
            raise ContractError("Independent hold release approver required")
        digest(self.evidence_digest)
        object.__setattr__(self, "approved_at", utc(self.approved_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.approved_at:
            raise ContractError("Invalid release validity")

    def require_valid(self, hold, revision, now):
        if (
            self.hold_id != hold.hold_id
            or self.scope != hold.scope
            or revision != self.expected_revision
        ):
            raise ContractError("Hold release revision/scope mismatch")
        if self.approved_by == hold.raised_by:
            raise ContractError("Hold raiser cannot approve its release")
        if not hold.raised_at <= self.approved_at <= utc(now) < self.valid_until:
            raise ContractError("Expired or future hold release")

    @property
    def document(self):
        return {
            **{
                key: getattr(self, key)
                for key in (
                    "hold_id",
                    "expected_revision",
                    "requested_by",
                    "approved_by",
                    "reason",
                    "evidence_id",
                    "evidence_digest",
                )
            },
            "scope": scope_document(self.scope),
            "revisions": {
                key: getattr(self.revisions, key)
                for key in ("source", "configuration", "policy", "environment")
            },
            "approved_at": self.approved_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class StoredHold:
    hold: SecurityHold
    revision: int
    release: HoldRelease | None = None

    def __post_init__(self):
        if (
            not isinstance(self.hold, SecurityHold)
            or type(self.revision) is not int
            or self.revision < 1
        ):
            raise ContractError("Typed stored hold required")
        if self.release is None:
            if self.revision != 1:
                raise ContractError("Open hold revision must be one")
        elif (
            not isinstance(self.release, HoldRelease)
            or self.revision != 2
            or self.release.expected_revision != 1
            or self.release.hold_id != self.hold.hold_id
            or self.release.scope != self.hold.scope
        ):
            raise ContractError("Invalid stored release")

    @property
    def active(self):
        return self.release is None

    @property
    def document(self):
        return {
            "hold": self.hold.document,
            "revision": self.revision,
            "release": None if self.release is None else self.release.document,
        }
