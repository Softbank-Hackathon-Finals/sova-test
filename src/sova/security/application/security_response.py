"""Purpose-specific hold exception: exact approved steps, never general deploy."""

from sova.domain.contracts import ContractError
from sova.domain.plans import PlanPurpose
from sova.security.domain.security_response import ACTIONS


class SecurityResponseGuard:
    def __init__(self, binding, holds, *, authorize_profile, verify_admission, clock):
        self.binding = binding
        self.holds = holds
        self.authorize_profile = authorize_profile
        self.verify_admission = verify_admission
        self.clock = clock

    def __call__(self, plan, now):
        binding = self.binding
        if (
            plan.purpose != PlanPurpose.SECURITY_RESPONSE
            or self.holds.tenant_id != plan.tenant_id
        ):
            raise ContractError(
                "Security response gate cannot authorize ordinary deployment"
            )
        expected = binding.compile(
            plan_id=plan.plan_id,
            created_by=plan.created_by,
            now=now,
            valid_until=plan.valid_until,
        )
        if plan.fingerprint != expected.fingerprint:
            raise ContractError("Security response differs from bound exact plan")
        if tuple(step.action for step in plan.steps) != ACTIONS:
            raise ContractError("Unregistered security response action")

        def require_holds():
            active = self.holds.active_holds(plan.application_id)
            if (
                type(active) is not tuple
                or {h.hold.hold_id for h in active} != set(binding.hold_ids)
                or len(active) != len(binding.hold_ids)
            ):
                raise ContractError(
                    "Incident holds changed; require a new response approval"
                )
            if not active or any(
                not h.active or h.hold.scope != binding.source_resource.scope
                for h in active
            ):
                raise ContractError("Response cannot bypass unrelated security holds")

        require_holds()
        self.authorize_profile(binding.profile, plan)
        # Must verify provenance, target protection and retained management paths.
        self.verify_admission(binding, plan)
        require_holds()
        checked = self.clock()
        binding.source.graph.require_current(checked)
        binding.target.graph.require_current(checked)
        if checked < now or checked >= min(
            binding.profile.valid_until, plan.valid_until
        ):
            raise ContractError("Response grant expired during admission")
        return min(
            binding.source.graph.valid_until,
            binding.target.graph.valid_until,
            binding.profile.valid_until,
            plan.valid_until,
        )
