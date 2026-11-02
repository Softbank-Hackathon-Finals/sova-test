"""Independent security gate and privileged release. No implicit risk exceptions."""

from datetime import UTC, datetime

from sova.domain.contracts import ContractError
from sova.domain.evidence import VerificationResult
from sova.security.domain.governance import assess_governance


class GovernanceGuard:
    def __init__(
        self,
        holds,
        *,
        policy_provider,
        evidence_provider,
        authenticate_policy,
        authenticate_evidence,
        clock=lambda: datetime.now(UTC),
    ):
        self.holds = holds
        self.policy_provider = policy_provider
        self.evidence_provider = evidence_provider
        self.authenticate_policy = authenticate_policy
        self.authenticate_evidence = authenticate_evidence
        self.clock = clock

    def assess(self, plan, now):
        if self.holds.tenant_id != plan.tenant_id:
            raise ContractError("Governance tenant mismatch")
        policy = self.policy_provider(plan)
        self.authenticate_policy(policy)
        if (policy.tenant_id, policy.application_id) != (
            plan.tenant_id,
            plan.application_id,
        ):
            raise ContractError("Security policy scope mismatch")
        required = {c.obligation for c in policy.controls}
        if not required <= set(plan.obligations):
            raise ContractError("Plan omitted or weakened security controls")
        controlled = {o.scope for o in required}
        if any(step.scope not in controlled for step in plan.steps):
            raise ContractError("Plan resource lacks security controls")
        evidence = self.evidence_provider(plan)
        if type(evidence) is not tuple:
            raise ContractError("Immutable security evidence required")
        for record in evidence:
            self.authenticate_evidence(record)
        holds = self.holds.active_holds(plan.application_id)
        if type(holds) is not tuple:
            raise ContractError("Immutable hold snapshot required")
        for stored in holds:
            if not stored.active or (
                stored.hold.scope.tenant_id,
                stored.hold.scope.application_id,
            ) != (plan.tenant_id, plan.application_id):
                raise ContractError("Invalid scoped security hold snapshot")
        checked_at = self.clock()
        if checked_at < now:
            raise ContractError("Governance clock moved backwards")
        result = assess_governance(policy, evidence, plan.revisions, now=checked_at)
        result["active_holds"] = [h.hold.hold_id for h in holds]
        result["accepted"] = result["accepted"] and not holds
        return result

    def __call__(self, plan, now):
        result = self.assess(plan, now)
        if not result["accepted"]:
            raise ContractError("Security governance blocks execution")
        return datetime.fromisoformat(result["valid_until"])


class SecurityHoldService:
    def __init__(
        self,
        repository,
        *,
        authorize,
        authenticate_release,
        authenticate_evidence,
        current_revisions,
        clock,
    ):
        self.repository = repository
        self.authorize = authorize
        self.authenticate_release = authenticate_release
        self.authenticate_evidence = authenticate_evidence
        self.current_revisions = current_revisions
        self.clock = clock

    def open(self, actor, hold):
        if actor != hold.raised_by or hold.scope.tenant_id != self.repository.tenant_id:
            raise ContractError("Security hold actor/scope mismatch")
        self.authorize(actor, hold.scope, "security:hold")
        if hold.raised_at > self.clock():
            raise ContractError("Future hold timestamp")
        return self.repository.open_hold(hold)

    def release(self, actor, application_id, request, evidence):
        stored = self.repository.get_hold(application_id, request.hold_id)
        if not stored.active:
            raise ContractError("Security hold already released")
        scope = stored.hold.scope
        if (
            actor != request.requested_by
            or request.scope != scope
            or request.revisions != self.current_revisions(scope)
        ):
            raise ContractError("Hold release requester/scope/revisions mismatch")
        self.authorize(actor, scope, "security:release-request")
        self.authenticate_release(request)
        self.authorize(request.approved_by, scope, "security:release-approve")
        self.authenticate_evidence(evidence)
        now = self.clock()
        request.require_valid(stored.hold, stored.revision, now)
        if (
            evidence.obligation_id != "security-release:" + stored.hold.hold_id
            or evidence.scope != scope
            or evidence.revisions != request.revisions
            or request.revisions != self.current_revisions(scope)
            or evidence.verifier_version != "security-revalidation-v1"
            or evidence.result != VerificationResult.PASS
            or not stored.hold.raised_at
            <= evidence.observed_at
            <= now
            < evidence.valid_until
            or evidence.evidence_id != request.evidence_id
            or evidence.artifact_digest != request.evidence_digest
            or request.valid_until > evidence.valid_until
        ):
            raise ContractError(
                "Hold release lacks current bound security revalidation"
            )
        return self.repository.release_hold(application_id, request)
