"""Trusted parity assessment and fail-closed execution integration.

Every callback is a server-side authority. The HTTP caller cannot select a
policy, assert adapter support, or authenticate its own evidence.
"""

from datetime import datetime

from sova.domain.contracts import ContractError, utc
from sova.security.domain.protection_parity import ProtectionPolicy, assess_protection


class ProtectionParityGuard:
    def __init__(
        self,
        *,
        policy_provider,
        evidence_provider,
        authenticate_policy,
        authenticate_evidence,
        profile_provider,
        current_revisions,
        holds,
        clock,
        record_assessment=None,
    ):
        for callback in (
            policy_provider,
            evidence_provider,
            authenticate_policy,
            authenticate_evidence,
            profile_provider,
            current_revisions,
            clock,
        ):
            if not callable(callback):
                raise ContractError("Explicit trusted protection authorities required")
        self.policy_provider = policy_provider
        self.evidence_provider = evidence_provider
        self.authenticate_policy = authenticate_policy
        self.authenticate_evidence = authenticate_evidence
        self.current_revisions = current_revisions
        self.profile_provider = profile_provider
        self.holds = holds
        self.clock = clock
        self.record_assessment = record_assessment

    def assess(self, plan, now):
        policy = self.policy_provider(plan)
        if not isinstance(policy, ProtectionPolicy):
            raise ContractError("Registered protection policy required")
        self.authenticate_policy(policy)
        profile = self.profile_provider(plan)
        from sova.security.domain.protection_profiles import ProtectionProfile

        if not isinstance(profile, ProtectionProfile):
            raise ContractError("Registered protection execution profile required")
        profile.require_policy(policy)
        if (policy.tenant_id, policy.application_id, policy.fingerprint) != (
            plan.tenant_id,
            plan.application_id,
            plan.revisions.policy,
        ) or self.holds.tenant_id != plan.tenant_id:
            raise ContractError("Plan protection policy binding mismatch")
        protected = {
            ep.scope
            for req in policy.requirements
            if req.required
            for ep in (req.source, req.target)
        }
        if any(step.scope not in protected for step in plan.steps):
            raise ContractError("Plan has a resource outside protection policy")
        for req in policy.requirements:
            if not req.required:
                continue
            if req.target.revisions(policy.fingerprint) != plan.revisions:
                raise ContractError(
                    "Plan target revisions differ from protection policy"
                )
            for endpoint in (req.source, req.target):
                if self.current_revisions(endpoint.scope) != endpoint.revisions(
                    policy.fingerprint
                ):
                    raise ContractError("Protection observation revision changed")
        evidence = self.evidence_provider(policy)
        if type(evidence) is not tuple:
            raise ContractError("Immutable authenticated protection evidence required")
        for record in evidence:
            self.authenticate_evidence(record)
        # Remote issuer/metadata lookups may overlap a policy update or drift.
        # Re-read the authorities; an earlier successful lookup is not a lease.
        if (
            self.policy_provider(plan) != policy
            or self.profile_provider(plan) != profile
        ):
            raise ContractError("Protection policy changed during verification")
        self.authenticate_policy(policy)
        for req in policy.requirements:
            if req.required:
                for endpoint in (req.source, req.target):
                    if self.current_revisions(endpoint.scope) != endpoint.revisions(
                        policy.fingerprint
                    ):
                        raise ContractError(
                            "Protection observation revision changed during verification"
                        )
        checked_at = utc(self.clock())
        if checked_at < utc(now):
            raise ContractError("Protection clock moved backwards")
        report = assess_protection(policy, evidence, now=checked_at)
        active = self.holds.active_holds(plan.application_id)
        if type(active) is not tuple or any(
            not h.active
            or (h.hold.scope.tenant_id, h.hold.scope.application_id)
            != (plan.tenant_id, plan.application_id)
            for h in active
        ):
            raise ContractError("Invalid protection hold snapshot")
        report["active_holds"] = [h.hold.hold_id for h in active]
        report["accepted"] = report["accepted"] and not active
        if self.record_assessment is not None:
            self.record_assessment(plan, policy, evidence, report)
        if (
            self.policy_provider(plan) != policy
            or self.profile_provider(plan) != profile
        ):
            raise ContractError("Protection policy changed before execution grant")
        # Recording is also an external boundary. A successful historical
        # assessment must not become a grant after expiry, drift or a new hold.
        final_now = utc(self.clock())
        if final_now < checked_at or (
            report["accepted"]
            and final_now >= datetime.fromisoformat(report["valid_until"])
        ):
            raise ContractError("Protection verification expired before grant")
        if self.holds.active_holds(plan.application_id) != active:
            raise ContractError("Protection hold set changed before grant")
        for req in policy.requirements:
            if req.required:
                for endpoint in (req.source, req.target):
                    if self.current_revisions(endpoint.scope) != endpoint.revisions(
                        policy.fingerprint
                    ):
                        raise ContractError(
                            "Protection observation revision changed before grant"
                        )
        return report

    def __call__(self, plan, now):
        report = self.assess(plan, now)
        if not report["accepted"]:
            raise ContractError("Protection parity blocks execution")
        return datetime.fromisoformat(report["valid_until"])
