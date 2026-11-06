"""Compose document-derived obligations into the existing Sova executor.

The stored approval, lease, effect CAS, patch/parity guards and readback remain
owned by their current services. A program review alone never executes anything.
"""

from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import ContractError
from sova_security.domain.security_program import (
    ProgramKind,
    ProgramPhase,
    SecurityProgram,
)
from sova_security.contracts.plans import PlanPurpose


def with_security_program(stored_executor, service, *, actor, scope):
    if not isinstance(stored_executor, StoredPlanExecutor):
        raise ContractError("Existing Sova stored-plan executor required")
    base = stored_executor.executor

    def guard(plan, now):
        deadline = plan.valid_until
        if base.governance_guard is not None:
            deadline = min(deadline, base.governance_guard(plan, now))
        program = service.program_for(scope, plan.fingerprint)
        if not isinstance(program, SecurityProgram):
            raise ContractError("Registered security program required")
        if (
            (plan.tenant_id, plan.application_id)
            != (scope.tenant_id, scope.application_id)
            or any(
                step.scope not in {program.source, program.target}
                for step in plan.steps
            )
            or (
                program.kind == ProgramKind.PATCH
                and (
                    plan.purpose != PlanPurpose.CHANGE
                    or any(step.action != "apply-verified-patch" for step in plan.steps)
                )
            )
            or (
                program.kind == ProgramKind.MIGRATION
                and plan.purpose != PlanPurpose.MIGRATION_PHASE
            )
        ):
            raise ContractError("Security program does not cover this plan")
        review = service.review(
            actor,
            scope=scope,
            subject_digest=plan.fingerprint,
            phase=ProgramPhase.PREFLIGHT,
        )
        if review.program_digest != program.fingerprint or not review.passed:
            raise ContractError("Security program preflight has not passed")
        return min(review.valid_until, deadline)

    return StoredPlanExecutor(
        stored_executor.repository,
        ApprovedPlanExecutor(
            base.effects,
            required_obligations=base.required_obligations,
            authenticate_approval=base.authenticate_approval,
            authenticate_evidence=base.authenticate_evidence,
            governance_guard=guard,
            execution_gate=base.execution_gate,
            clock=base.clock,
        ),
    )


def with_patch_security_program(patch_service, program_service, *, scope):
    """Copy a configured patch service and require both program phases per call."""
    from sova.security.application.patch_execution import PatchPlanExecutionService

    if not isinstance(patch_service, PatchPlanExecutionService):
        raise ContractError("Existing patch execution service required")
    if patch_service.program_service is not None:
        raise ContractError("An existing program policy must not be silently replaced")
    return PatchPlanExecutionService(
        stored_executor=patch_service.stored,
        patch_guard=patch_service.patch_guard,
        binding_for=patch_service.binding_for,
        observe_runtime=patch_service.observe_runtime,
        reassessment_for=patch_service.reassessment_for,
        authenticate_runtime=patch_service.authenticate_runtime,
        authenticate_binding=patch_service.authenticate_binding,
        authorize=patch_service.authorize,
        record_hold=patch_service.record_hold,
        clock=patch_service.clock,
        program_service=program_service,
        program_scope=scope,
    )
