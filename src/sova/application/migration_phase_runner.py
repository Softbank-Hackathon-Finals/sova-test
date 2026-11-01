"""Execute one approved phase, not a whole migration, under durable ownership.

Adapters are trusted, bounded implementations selected by the server. Long cloud
jobs need separate start/poll effects; this runner does not replay unknown work or
hide a lost lease behind a heartbeat thread. Independent recovery remains explicit.
"""

from sova.application.effects import EffectExecutor, UncertainEffect
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_migration_phases import StoredMigrationPhaseExecutor
from sova.domain.contracts import ContractError, EffectStatus, ExecutionPermit
from sova.domain.phase_completion import PhaseCompletion
from sova.domain.workflows import OperationProfile, OperationStatus
from sova.ports.plans import RecordNotFound


class MigrationPhaseRunner:
    def __init__(
        self,
        programs,
        operations,
        ownership,
        *,
        journal_factory,
        required_obligations,
        action_registry_provider,
        authenticate_registry,
        authenticate_program,
        authenticate_approval,
        authenticate_evidence,
        governance_guard,
        clock,
    ):
        if not callable(governance_guard):
            raise ContractError("Explicit independent governance guard required")
        self.programs, self.operations, self.ownership = programs, operations, ownership
        self.journal_factory = journal_factory
        self.required_obligations = required_obligations
        self.action_registry_provider = action_registry_provider
        self.authenticate_registry = authenticate_registry
        self.authenticate_program = authenticate_program
        self.authenticate_approval = authenticate_approval
        self.authenticate_evidence = authenticate_evidence
        self.governance_guard, self.clock = governance_guard, clock

    def registry(self, application_id):
        registry = self.action_registry_provider(
            self.programs.tenant_id, application_id
        )
        self.authenticate_registry(registry)
        return registry

    @staticmethod
    def outcome(committed, proof, recovered=False):
        return {
            "operation_id": committed.request.operation_id,
            "status": str(committed.state.status),
            "revision": committed.state.revision,
            "phase": str(proof.phase),
            "plan_digest": proof.plan_digest,
            "program_digest": proof.program_digest,
            "completion_digest": proof.fingerprint,
            "completion_recovered_read_only": recovered,
            "verification_valid_until": proof.verified_until.isoformat(),
            "receipt_only": True,
            "full_migration_verified": False,
        }

    def run(self, application_id, operation_id, *, owner_id, evidence, adapter_factory):
        if type(evidence) is not tuple:
            raise ContractError("Immutable verifier evidence snapshot required")
        lifecycle = self.programs.lifecycle
        admitted = self.operations.get(application_id, operation_id)
        if (
            admitted.state.profile == OperationProfile.MIGRATION_PHASE
            and admitted.state.status == OperationStatus.PHASE_VERIFIED
        ):
            committed, proof = self.programs.get_phase_completion(
                self.operations, application_id, operation_id
            )
            return self.outcome(committed, proof, True)
        if (
            admitted.state.profile != OperationProfile.MIGRATION_PHASE
            or admitted.state.status != OperationStatus.REGISTERED
        ):
            raise ContractError("Only a newly admitted migration phase may start")
        binding = self.programs.get_binding(
            application_id,
            admitted.request.plan_id,
            action_registry=self.registry(application_id),
        )
        self.authenticate_program(binding.program)
        plan = binding.plan
        approved = lifecycle.get_approval(application_id, admitted.request.approval_id)
        lease = self.ownership.acquire(
            application_id, operation_id, owner_id, lease_seconds=180
        )
        journal = self.journal_factory(self.ownership, lease)
        effects = EffectExecutor(journal, authorize=journal.authorize, clock=self.clock)
        base = ApprovedPlanExecutor(
            effects,
            required_obligations=self.required_obligations,
            authenticate_approval=self.authenticate_approval,
            authenticate_evidence=self.authenticate_evidence,
            governance_guard=self.governance_guard,
            clock=self.clock,
        )
        stored = StoredMigrationPhaseExecutor(
            self.programs,
            base,
            action_registry_provider=self.action_registry_provider,
            authenticate_registry=self.authenticate_registry,
            authenticate_program=self.authenticate_program,
        )
        state = admitted.state
        completion = None
        adapters = {}

        def checked():
            return stored.check_plan(
                application_id,
                plan.plan_id,
                admitted.request.approval_id,
                evidence=evidence,
            )

        def deadline(verification):
            used = {
                d.evidence_id
                for d in verification.gate.decisions
                if d.obligation.required
                and d.obligation.due_gate <= verification.gate.gate
            }
            ends = [
                lease.valid_until,
                plan.valid_until,
                approved.approval.valid_until,
                *(e.valid_until for e in evidence if e.evidence_id in used),
            ]
            if verification.security_deadline is not None:
                ends.append(verification.security_deadline)
            return min(ends)

        def grant(command):
            verification = checked()
            if journal.get(command).status != EffectStatus.IN_FLIGHT:
                raise ContractError(
                    "Mutation grant requires this effect's active claim"
                )
            permit = ExecutionPermit(
                command.scope,
                operation_id,
                plan.fingerprint,
                command.fingerprint,
                lease.epoch,
                deadline(verification),
            )
            journal.authorize(command, permit, self.clock(), True)
            return permit

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
            checked()
            advance(OperationStatus.PHASE_RUNNING)
            for step in plan.steps:
                lease = self.ownership.renew(lease, lease_seconds=180)
                expected_command = plan.command(
                    step.step_id, operation_id=operation_id, epoch=lease.epoch
                )

                def step_grant(current, expected=expected_command):
                    if current != expected:
                        raise ContractError(
                            "Adapter requested a grant for another step"
                        )
                    return grant(current)

                adapter = adapter_factory(step, step_grant)
                adapters[step.step_id] = adapter
                receipt = stored.execute_step(
                    application_id,
                    plan.plan_id,
                    admitted.request.approval_id,
                    step.step_id,
                    operation_id=operation_id,
                    epoch=lease.epoch,
                    evidence=evidence,
                    adapter=adapter,
                )
                if receipt.status != EffectStatus.APPLIED:
                    raise UncertainEffect("Phase effect not confirmed")
            advance(OperationStatus.VERIFYING)
            observations = []
            for step in plan.steps:
                lease = self.ownership.renew(lease, lease_seconds=180)
                checked()
                command = plan.command(
                    step.step_id, operation_id=operation_id, epoch=lease.epoch
                )
                observed = effects._observe(command, adapters[step.step_id])
                if observed.status != EffectStatus.APPLIED:
                    raise UncertainEffect("Final phase readback did not confirm state")
                observations.append(observed)
            final = checked()
            completion = PhaseCompletion(
                lifecycle.tenant_id,
                application_id,
                operation_id,
                plan.fingerprint,
                binding.program.fingerprint,
                binding.phase,
                lease.epoch,
                owner_id,
                deadline(final),
                tuple(observations),
            )
            committed, proof = self.programs.finish_phase(
                self.operations,
                self.ownership,
                lease,
                completion,
                expected_revision=state.revision,
                action_registry=self.registry(application_id),
            )
            state = committed.state
            return self.outcome(committed, proof)
        except Exception:
            if completion is not None:
                try:
                    committed, proof = self.programs.get_phase_completion(
                        self.operations, application_id, operation_id
                    )
                    if proof != completion:
                        raise ContractError(
                            "Recovered phase receipt differs from requested completion"
                        )
                    return self.outcome(committed, proof, True)
                except RecordNotFound:
                    pass
            if state.status in {
                OperationStatus.PHASE_RUNNING,
                OperationStatus.VERIFYING,
            }:
                advance(OperationStatus.RECOVERY_REQUIRED)
            elif state.status == OperationStatus.REGISTERED:
                advance(OperationStatus.BLOCKED)
                self.ownership.release(lease)
            # Retain ownership/pending effects for independent recovery; no replay.
            raise
