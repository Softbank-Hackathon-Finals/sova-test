"""Load immutable plans and re-read persisted approval before every dispatch."""

from sova.application.plans import ApprovedPlanExecutor
from sova.domain.contracts import ContractError
from sova.ports.plans import LifecycleRepository
from sova_security.contracts.authority import require_accept


class StoredPlanExecutor:
    def __init__(self, repository: LifecycleRepository, executor: ApprovedPlanExecutor):
        self.repository, self.executor = repository, executor

    def _load_guarded(self, application_id, plan_id, approval_id):
        plan = self.repository.get_plan(application_id, plan_id)
        saved = self.repository.get_approval(application_id, approval_id)
        if saved.plan_id != plan_id or saved.revoked:
            raise ContractError("Stored approval is revoked or belongs to another plan")

        def authenticate(current_plan, current_approval):
            require_accept(
                self.executor.authenticate_approval, current_plan, current_approval
            )
            fresh = self.repository.get_approval(application_id, approval_id)
            if fresh != saved or fresh.revoked:
                raise ContractError("Stored approval changed or was revoked")

        guarded = ApprovedPlanExecutor(
            self.executor.effects,
            required_obligations=self.executor.required_obligations,
            authenticate_approval=authenticate,
            authenticate_evidence=self.executor.authenticate_evidence,
            governance_guard=self.executor.governance_guard,
            execution_gate=self.executor.execution_gate,
            clock=self.executor.clock,
        )
        return plan, saved, guarded

    def check_plan(self, application_id, plan_id, approval_id, *, evidence):
        plan, saved, guarded = self._load_guarded(application_id, plan_id, approval_id)
        return guarded.check_plan(plan, saved.approval, evidence, self.executor.clock())

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
        plan, saved, guarded = self._load_guarded(application_id, plan_id, approval_id)
        return guarded.execute_step(
            plan,
            saved.approval,
            step_id,
            operation_id=operation_id,
            epoch=epoch,
            evidence=evidence,
            adapter=adapter,
        )
