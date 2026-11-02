"""Purpose-specific response uses the existing operation/ownership/effect ledger."""

from sova.application.effects import EffectExecutor, UncertainEffect
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import ContractError, EffectStatus
from sova.domain.workflows import OperationStatus, OperationProfile
from sova.security.domain.response_completion import ResponseCompletion
from sova.ports.plans import RecordNotFound


class SecurityResponseRunner:
    def __init__(
        self,
        lifecycle,
        operations,
        ownership,
        *,
        journal_factory,
        authenticate_approval,
        authenticate_evidence,
        clock,
    ):
        self.journal_factory = journal_factory
        self.lifecycle = lifecycle
        self.operations = operations
        self.ownership = ownership
        self.authenticate_approval = authenticate_approval
        self.authenticate_evidence = authenticate_evidence
        self.clock = clock

    def run(
        self, application_id, operation_id, *, owner_id, evidence, guard, adapter, emit
    ):
        if guard is None or not callable(guard):
            raise ContractError("An explicit security response guard is required")
        admitted = self.operations.get(application_id, operation_id)
        if (
            admitted.state.profile != OperationProfile.SECURITY_RESPONSE
            or admitted.state.status != OperationStatus.REGISTERED
        ):
            raise ContractError("Only a newly admitted security response may start")
        lease = self.ownership.acquire(
            application_id, operation_id, owner_id, lease_seconds=180
        )
        journal = self.journal_factory(self.ownership, lease)
        executor = ApprovedPlanExecutor(
            EffectExecutor(journal, authorize=journal.authorize, clock=self.clock),
            required_obligations=lambda plan: plan.obligations,
            authenticate_approval=self.authenticate_approval,
            authenticate_evidence=self.authenticate_evidence,
            governance_guard=guard,
            clock=self.clock,
        )
        stored = StoredPlanExecutor(self.lifecycle, executor)
        state = admitted.state
        completion = None

        def outcome(committed, proof, *, recovered=False):
            return {
                "operation_id": operation_id,
                "status": str(committed.state.status),
                "revision": committed.state.revision,
                "plan_digest": proof.command.plan_digest,
                "completion_digest": proof.fingerprint,
                "completion_recovered_read_only": recovered,
            }

        def advance(target):
            nonlocal state
            state = self.operations.advance_owned(
                self.ownership,
                lease,
                target,
                expected_revision=state.revision,
                actor_id=owner_id,
            ).state

        try:
            phases = [
                OperationStatus.CONTAINING,
                OperationStatus.PREPARING_REPLACEMENT,
                OperationStatus.VERIFYING_REPLACEMENT,
                OperationStatus.SWITCHING,
            ]
            plan = self.lifecycle.get_plan(application_id, admitted.request.plan_id)
            for step, phase in zip(plan.steps, phases, strict=True):
                advance(phase)
                result = stored.execute_step(
                    application_id,
                    plan.plan_id,
                    admitted.request.approval_id,
                    step.step_id,
                    operation_id=operation_id,
                    epoch=lease.epoch,
                    evidence=evidence,
                    adapter=adapter,
                )
                if result.status != EffectStatus.APPLIED:
                    raise UncertainEffect("Response effect not confirmed")
                emit(step.action, result)
            advance(OperationStatus.VERIFYING)
            # The switch step readback already verifies the actual target request.
            # Keep final verification distinct and fail if the routing proof changed.
            stored.check_plan(
                application_id,
                plan.plan_id,
                admitted.request.approval_id,
                evidence=evidence,
            )
            final = adapter.readback(result.command, self.clock())
            if final.status != EffectStatus.APPLIED:
                raise UncertainEffect("Final route revalidation failed")
            checked = stored.check_plan(
                application_id,
                plan.plan_id,
                admitted.request.approval_id,
                evidence=evidence,
            )
            used = {
                d.evidence_id
                for d in checked.gate.decisions
                if d.obligation.required and d.obligation.due_gate <= checked.gate.gate
            }
            deadline = min(
                plan.valid_until,
                *(e.valid_until for e in evidence if e.evidence_id in used),
            )
            if checked.security_deadline is not None:
                deadline = min(deadline, checked.security_deadline)
            completion = ResponseCompletion(result.command, final, owner_id, deadline)
            committed, proof = self.operations.finish_response(
                self.ownership, lease, completion, expected_revision=state.revision
            )
            state = committed.state
            return outcome(committed, proof)
        except Exception:
            if completion is not None:
                # The completion transaction may have committed while its reply
                # was lost. Query the immutable receipt; never repeat effects.
                try:
                    committed, proof = self.operations.get_response_completion(
                        application_id, operation_id
                    )
                    if proof != completion:
                        raise ContractError(
                            "Recovered completion differs from the requested receipt"
                        )
                    return outcome(committed, proof, recovered=True)
                except RecordNotFound:
                    pass
            if state.status not in {
                OperationStatus.RECOVERY_REQUIRED,
                OperationStatus.RESPONSE_VERIFIED,
            }:
                advance(OperationStatus.RECOVERY_REQUIRED)
            # Never release an unresolved effect or replay a remote mutation.
            raise
