"""Connect security patch guards to Sova's existing stored-plan execution.

The service composes PatchExecutionGuard into the stored executor per actor.
The host retains durable approvals, leases/fencing, effects and incident holds.
No scanner, Harbor runtime or deployment adapter is implemented here.
"""

from dataclasses import dataclass

from sova.domain.contracts import ContractError, EffectStatus, utc
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.application.effects import UncertainEffect
from sova_security.application.boundary import require_accept
from sova_security.domain.patch_execution import (
    PatchExecutionBinding,
    PatchRuntimeObservation,
    require_postflight,
)
from sova_security.domain.security_program import ProgramPhase, ProgramReview
from sova_security.contracts.commands import ResourceScope


class PatchPostflightRequired(RuntimeError):
    """The effect may be applied. Retain its ID and reconcile; never replay it."""


@dataclass(frozen=True, slots=True)
class VerifiedPatchStep:
    effect: object
    observation: PatchRuntimeObservation
    program_review: ProgramReview | None = None


class PatchPlanExecutionService:
    def __init__(
        self,
        *,
        stored_executor,
        patch_guard,
        binding_for,
        observe_runtime,
        reassessment_for,
        authenticate_runtime,
        authenticate_binding,
        authorize,
        record_hold,
        clock,
        program_service=None,
        program_scope=None,
    ):
        if not isinstance(stored_executor, StoredPlanExecutor):
            raise ContractError("Existing stored-plan executor required")
        self.stored = stored_executor
        self.patch_guard = patch_guard
        self.binding_for = binding_for
        self.observe_runtime = observe_runtime
        self.reassessment_for = reassessment_for
        self.authenticate_runtime = authenticate_runtime
        self.authenticate_binding = authenticate_binding
        self.authorize = authorize
        self.record_hold = record_hold
        self.clock = clock
        if (program_service is None) != (program_scope is None) or (
            program_scope is not None and not isinstance(program_scope, ResourceScope)
        ):
            raise ContractError(
                "Program service and typed target scope must be supplied together"
            )
        self.program_service = program_service
        self.program_scope = program_scope

    def execute_step(
        self,
        actor,
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
        started = utc(self.clock())
        stored = self.stored
        if self.program_service is not None:
            from sova.security.application.security_program import with_security_program

            stored = with_security_program(
                stored, self.program_service, actor=actor, scope=self.program_scope
            )
        base = stored.executor

        def guard(plan, at):
            deadline = self.patch_guard.check(actor, plan)
            if base.governance_guard is not None:
                deadline = min(deadline, base.governance_guard(plan, at))
            return deadline

        def authenticate_approval(plan, approval):
            require_accept(base.authenticate_approval, plan, approval)
            self.patch_guard.check_approval(plan, approval)

        # Compose the patch guard here so callers cannot accidentally omit it.
        # Do not mutate a shared executor used by another actor or operation.
        guarded = StoredPlanExecutor(
            stored.repository,
            ApprovedPlanExecutor(
                base.effects,
                required_obligations=base.required_obligations,
                authenticate_approval=authenticate_approval,
                authenticate_evidence=base.authenticate_evidence,
                governance_guard=guard,
                execution_gate=base.execution_gate,
                clock=base.clock,
            ),
        )
        try:
            effect = guarded.execute_step(
                application_id,
                plan_id,
                approval_id,
                step_id,
                operation_id=operation_id,
                epoch=epoch,
                evidence=evidence,
                adapter=adapter,
            )
        except UncertainEffect as error:
            plan = self.stored.repository.get_plan(application_id, plan_id)
            command = plan.command(step_id, operation_id=operation_id, epoch=epoch)
            require_accept(self.record_hold, command, "patch-effect-uncertain")
            raise PatchPostflightRequired(
                "Patch effect uncertain; reconcile the existing operation read-only"
            ) from error
        # Historical APPLIED means no re-apply. It still needs fresh health proof.
        try:
            if effect.status != EffectStatus.APPLIED or effect.observation is None:
                raise ContractError("Patch effect is not independently confirmed")
            command = effect.command
            binding = self.binding_for(command)
            if not isinstance(binding, PatchExecutionBinding):
                raise ContractError("Registered runtime patch binding required")
            require_accept(
                self.authorize, actor, command.scope, "security:verify-patch"
            )
            require_accept(self.authenticate_binding, actor, binding)
            proof = self.observe_runtime(command, binding)
            reassessment = self.reassessment_for(proof)
            require_accept(self.authenticate_runtime, actor, binding, command, proof)
            if self.binding_for(command) != binding:
                raise ContractError("Patch binding revoked during final verification")
            require_postflight(
                binding,
                proof,
                command=command,
                not_before=started,
                now=self.clock(),
                reassessment=reassessment,
            )
            require_accept(
                self.authorize, actor, command.scope, "security:verify-patch"
            )
            require_accept(self.authenticate_binding, actor, binding)
            if self.binding_for(command) != binding:
                raise ContractError("Patch binding changed during runtime verification")
            # Recheck signature/trust after any host I/O, then clock/validity.
            require_accept(self.authenticate_runtime, actor, binding, command, proof)
            if self.reassessment_for(proof) != reassessment:
                raise ContractError("Patch reassessment changed during verification")
            if utc(self.clock()) < started:
                raise ContractError("Execution verification clock moved backwards")
            require_postflight(
                binding,
                proof,
                command=command,
                not_before=started,
                now=self.clock(),
                reassessment=reassessment,
            )
            review = None
            if self.program_service is not None:
                review = self.program_service.review(
                    actor,
                    scope=self.program_scope,
                    subject_digest=command.plan_digest,
                    phase=ProgramPhase.POSTFLIGHT,
                    not_before=started,
                )
                if not review.passed:
                    raise ContractError("Security program postflight has not passed")
                # Program producers may perform I/O. Keep the original runtime
                # and approval-bound patch authority current through that work.
                require_accept(
                    self.authorize, actor, command.scope, "security:verify-patch"
                )
                require_accept(self.authenticate_binding, actor, binding)
                require_accept(
                    self.authenticate_runtime, actor, binding, command, proof
                )
                if (
                    self.binding_for(command) != binding
                    or self.reassessment_for(proof) != reassessment
                ):
                    raise ContractError(
                        "Runtime authority changed during program verification"
                    )
                finished = utc(self.clock())
                if finished < started or finished >= review.valid_until:
                    raise ContractError(
                        "Program verification expired before completion"
                    )
                require_postflight(
                    binding,
                    proof,
                    command=command,
                    not_before=started,
                    now=finished,
                    reassessment=reassessment,
                )
            return VerifiedPatchStep(effect, proof, review)
        except Exception as error:
            # Fixed reason avoids persisting exception text containing remote data.
            require_accept(
                self.record_hold, effect.command, "patch-postflight-unverified"
            )
            raise PatchPostflightRequired(
                "Patch may be applied; retain the effect and reconcile read-only"
            ) from error
