"""Test authorities and repository doubles, not production authentication."""

from dataclasses import replace
from datetime import timedelta

from sova.domain.contracts import ContractError
from sova.domain.evidence import (
    EvidenceRecord,
    Gate,
    RevisionSet,
    VerificationObligation,
    VerificationResult,
)
from sova.domain.governance import (
    ControlFamily,
    GovernancePolicy,
    SecurityControl,
    SecurityHold,
    HoldRelease,
    StoredHold,
)
from sova.domain.plans import LifecyclePlan, PlanApproval, PlanPurpose, PlanStep
from sova.ports.plans import RecordNotFound, RepositoryConflict


def bundle(scope, now):
    obligation = VerificationObligation(
        "security.encryption", scope, Gate.PROTECTION, "tls-verifier-v1"
    )
    policy = GovernancePolicy(
        scope.tenant_id,
        scope.application_id,
        1,
        (SecurityControl(ControlFamily.ENCRYPTION, obligation),),
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
    )
    revisions = RevisionSet("a" * 64, "b" * 64, policy.fingerprint, "d" * 64)
    evidence = EvidenceRecord(
        "tls-evidence",
        obligation.obligation_id,
        scope,
        revisions,
        obligation.verifier_version,
        now,
        now + timedelta(minutes=5),
        VerificationResult.PASS,
        "tls-report",
        "e" * 64,
    )
    plan = LifecyclePlan(
        "plan",
        scope.tenant_id,
        scope.application_id,
        "author",
        PlanPurpose.CHANGE,
        revisions,
        now + timedelta(minutes=5),
        (
            PlanStep(
                "isolate",
                scope,
                "test-ingress",
                "set_ingress",
                '{"blocked":true}',
                "r1",
            ),
        ),
        (obligation,),
    )
    approval = PlanApproval(
        plan.fingerprint, "deployer", plan.purpose, plan.valid_until
    )
    hold = SecurityHold(
        "incident-1",
        scope,
        "detector",
        "security review required",
        now - timedelta(seconds=1),
    )
    return policy, plan, approval, evidence, hold


def release_bundle(hold, revisions, now):
    evidence = EvidenceRecord(
        "revalidation",
        "security-release:" + hold.hold_id,
        hold.scope,
        revisions,
        "security-revalidation-v1",
        now,
        now + timedelta(minutes=4),
        VerificationResult.PASS,
        "release-report",
        "f" * 64,
    )
    request = HoldRelease(
        hold.hold_id,
        hold.scope,
        revisions,
        1,
        "responder",
        "security-approver",
        "reviewed remediation",
        evidence.evidence_id,
        evidence.artifact_digest,
        now,
        now + timedelta(minutes=2),
    )
    return request, evidence


class MemoryHolds:
    def __init__(self, tenant_id, now):
        self.tenant_id = tenant_id
        self.now = now
        self.values = {}

    def open_hold(self, hold):
        if hold.scope.tenant_id != self.tenant_id:
            raise ContractError("Wrong tenant")
        key = (hold.scope.application_id, hold.hold_id)
        if key in self.values and self.values[key] != StoredHold(hold, 1):
            raise RepositoryConflict("Immutable hold")
        self.values[key] = StoredHold(hold, 1)
        return self.values[key]

    def get_hold(self, app, hold_id):
        try:
            return self.values[(app, hold_id)]
        except KeyError:
            raise RecordNotFound()

    def active_holds(self, app):
        return tuple(v for (a, _), v in self.values.items() if a == app and v.active)

    def release_hold(self, app, request):
        stored = self.get_hold(app, request.hold_id)
        if not stored.active:
            raise RepositoryConflict("Already released")
        request.require_valid(stored.hold, stored.revision, self.now)
        value = replace(stored, revision=2, release=request)
        self.values[(app, request.hold_id)] = value
        return value
