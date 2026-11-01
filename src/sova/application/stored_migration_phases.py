"""Re-read authenticated phase policy before each durable effect dispatch.

The caller authenticates the tenant before choosing repositories. Publishers of
programs/phase bindings must be separate from workers. The action registry and
program authenticator are trusted services, not fields supplied in a request.
"""

from sova.application.migration_phases import phase_action_digest
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import ContractError
from sova.domain.evidence import VerificationObligation


class StoredMigrationPhaseExecutor:
    def __init__(
        self,
        repository,
        executor,
        *,
        action_registry_provider,
        authenticate_registry,
        authenticate_program,
    ):
        if executor.execution_gate is not None:
            raise ContractError("Cannot replace an existing execution phase policy")
        self.repository, self.executor = repository, executor
        self.action_registry_provider = action_registry_provider
        self.authenticate_registry = authenticate_registry
        self.authenticate_program = authenticate_program

    def _runner(self, application_id, plan_id):
        def current_binding(plan, now):
            if (plan.tenant_id, plan.application_id, plan.plan_id) != (
                self.repository.tenant_id,
                application_id,
                plan_id,
            ):
                raise ContractError("Execution crosses requested phase binding")
            registry = self.action_registry_provider(
                self.repository.tenant_id, application_id
            )
            self.authenticate_registry(registry)
            phase_action_digest(registry)
            binding = self.repository.get_binding(
                application_id, plan_id, action_registry=registry
            )
            self.authenticate_program(binding.program)
            binding.execution_gate(plan, now)
            return binding

        def gate(plan, now):
            binding = current_binding(plan, now)
            return binding.execution_gate(plan, now)

        def mandatory(plan):
            binding = current_binding(plan, self.executor.clock())
            baseline = self.executor.required_obligations(plan)
            if (
                type(baseline) is not tuple
                or not 1 <= len(baseline) <= 256
                or any(
                    not isinstance(o, VerificationObligation) or not o.required
                    for o in baseline
                )
            ):
                raise ContractError(
                    "Base execution policy must define mandatory obligations"
                )
            combined = {}
            for obligation in (*baseline, *binding.required_obligations(plan)):
                previous = combined.get(obligation.obligation_id)
                if previous is not None and previous != obligation:
                    raise ContractError("Phase cannot weaken base execution policy")
                combined[obligation.obligation_id] = obligation
            return tuple(combined.values())

        guarded = ApprovedPlanExecutor(
            self.executor.effects,
            required_obligations=mandatory,
            execution_gate=gate,
            authenticate_approval=self.executor.authenticate_approval,
            authenticate_evidence=self.executor.authenticate_evidence,
            governance_guard=self.executor.governance_guard,
            clock=self.executor.clock,
        )
        return StoredPlanExecutor(self.repository.lifecycle, guarded)

    def check_plan(self, application_id, plan_id, approval_id, *, evidence):
        return self._runner(application_id, plan_id).check_plan(
            application_id, plan_id, approval_id, evidence=evidence
        )

    def execute_step(
        self,
        application_id,
        plan_id,
        approval_id,
        step_id,
        *,
        operation_id,
        epoch,
        evidence,
        adapter,
    ):
        return self._runner(application_id, plan_id).execute_step(
            application_id,
            plan_id,
            approval_id,
            step_id,
            operation_id=operation_id,
            epoch=epoch,
            evidence=evidence,
            adapter=adapter,
        )
