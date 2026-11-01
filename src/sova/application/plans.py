"""Approved plan steps use the same effect journal for change and recovery.

Identity and evidence issuer authentication are injected responsibilities; this
use case does not replace the future hosted authentication/approval service.
"""

from datetime import UTC, datetime
from dataclasses import dataclass
from typing import Callable

from sova.application.effects import EffectExecutor
from sova.domain.contracts import ContractError, EffectStatus, ExecutionPermit
from sova.domain.evidence import (
    EvidenceRecord,
    Gate,
    VerificationObligation,
    evaluate_gate,
    GateDecision,
)
from sova.domain.plans import LifecyclePlan, PlanApproval
from sova.ports.effects import EffectAdapter


@dataclass(frozen=True)
class CheckedPlan:
    gate: GateDecision
    security_deadline: datetime | None


class ApprovedPlanExecutor:
    def __init__(
        self,
        effects: EffectExecutor,
        *,
        required_obligations: Callable[
            [LifecyclePlan], tuple[VerificationObligation, ...]
        ],
        authenticate_approval: Callable[[LifecyclePlan, PlanApproval], None],
        authenticate_evidence: Callable[[EvidenceRecord], None],
        governance_guard: Callable[[LifecyclePlan, datetime], datetime] | None = None,
        execution_gate: Callable[[LifecyclePlan, datetime], Gate] | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.effects = effects
        self.required_obligations = required_obligations
        self.authenticate_approval = authenticate_approval
        self.authenticate_evidence = authenticate_evidence
        self.governance_guard = governance_guard
        # A trusted server-side phase binding may admit preparation before G7.
        # Never read a gate number from uploaded parameters or an approval.
        self.execution_gate = execution_gate
        self.clock = clock

    def check_plan(self, plan, approval, evidence, now):
        approval.require_valid(plan, now)
        self.authenticate_approval(plan, approval)
        execution_gate = (
            Gate.PREFLIGHT
            if self.execution_gate is None
            else self.execution_gate(plan, now)
        )
        if not isinstance(execution_gate, Gate):
            raise ContractError("Trusted execution policy must return a typed gate")
        security_deadline = None
        if self.governance_guard is not None:
            security_deadline = self.governance_guard(plan, now)
            if (
                not isinstance(security_deadline, datetime)
                or security_deadline.tzinfo is None
                or self.clock() >= security_deadline
            ):
                raise ContractError(
                    "Governance did not grant a current security deadline"
                )
        # Mandatory obligations come from trusted policy, never only the plan's
        # own list. Removing or weakening them must not open an empty gate.
        mandatory = self.required_obligations(plan)
        if (
            type(mandatory) is not tuple
            or not mandatory
            or any(
                not isinstance(o, VerificationObligation)
                or not o.required
                or o.due_gate > execution_gate
                for o in mandatory
            )
        ):
            raise ContractError("Policy must define required preflight obligations")
        if len({o.obligation_id for o in mandatory}) != len(mandatory):
            raise ContractError("Duplicate mandatory policy obligations")
        for obligation in mandatory:
            if obligation not in plan.obligations:
                raise ContractError("Plan omitted or weakened a policy obligation")
        for record in evidence:
            self.authenticate_evidence(record)
        gate = evaluate_gate(
            execution_gate, plan.obligations, evidence, plan.revisions, now=now
        )
        if not gate.accepted:
            raise ContractError("Required plan verification has not passed")
        return CheckedPlan(gate, security_deadline)

    def execute_step(
        self,
        plan: LifecyclePlan,
        approval: PlanApproval,
        step_id: str,
        *,
        operation_id: str,
        epoch: int,
        evidence: tuple[EvidenceRecord, ...],
        adapter: EffectAdapter,
    ):
        if type(evidence) is not tuple:
            raise ContractError("Immutable evidence collection required")
        checked = self.check_plan(plan, approval, evidence, self.clock())
        gate = checked.gate
        command = plan.command(step_id, operation_id=operation_id, epoch=epoch)
        step = next(item for item in plan.steps if item.step_id == step_id)
        for dependency in step.depends_on:
            prior = plan.command(dependency, operation_id=operation_id, epoch=epoch)
            if self.effects.journal.get(prior).status != EffectStatus.APPLIED:
                raise ContractError("Dependency has not completed")
        used = {
            d.evidence_id
            for d in gate.decisions
            if d.obligation.required and d.obligation.due_gate <= gate.gate
        }
        evidence_deadline = min(
            record.valid_until for record in evidence if record.evidence_id in used
        )
        if checked.security_deadline is not None:
            evidence_deadline = min(evidence_deadline, checked.security_deadline)
        permit = ExecutionPermit(
            command.scope,
            operation_id,
            plan.fingerprint,
            command.fingerprint,
            epoch,
            min(approval.valid_until, plan.valid_until, evidence_deadline),
        )

        def authorize(current_command, current_permit, now, mutation):
            current = self.check_plan(plan, approval, evidence, now)
            if current.gate.gate != gate.gate:
                raise ContractError("Execution phase changed during dispatch")
            self.effects.authorize(current_command, current_permit, now, mutation)
            if (
                current.security_deadline is not None
                and self.clock() >= current.security_deadline
            ):
                raise ContractError("Security grant expired during authorization")

        # A per-call executor avoids changing the shared executor's authorizer.
        # Recheck revocation, policy and evidence immediately before apply too.
        guarded = EffectExecutor(
            self.effects.journal, authorize=authorize, clock=self.clock
        )
        return guarded.execute(command, permit, adapter)
