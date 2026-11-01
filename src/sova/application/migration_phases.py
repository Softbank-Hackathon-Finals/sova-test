"""Compile independently approved phases without dropping future obligations.

The action registry and returned binding belong to trusted control-plane policy,
not the agent, upload, HTTP request or approver. Reconstruct that binding from
authenticated program/policy storage after restart; plan.reason is only a label.
This module neither authenticates registrations nor provisions a destination.
"""

from dataclasses import dataclass
from datetime import datetime

from sova.domain.contracts import ContractError, identifier, utc
from sova.domain.evidence import Gate
from sova.domain.migration_program import MigrationProgram
from sova.domain.migration_phases import MigrationPhase
from sova.domain.plans import LifecyclePlan, PlanPurpose, PlanStep


_GATES = {
    MigrationPhase.PREPARE: Gate.CHANGE,
    MigrationPhase.SYNCHRONIZE: Gate.STARTUP,
    MigrationPhase.REHEARSE: Gate.PROTECTION,
    MigrationPhase.QUIESCE: Gate.PROTECTION,
    MigrationPhase.CUTOVER: Gate.PREFLIGHT,
    MigrationPhase.POSTCHECK: Gate.POSTFLIGHT,
}


@dataclass(frozen=True, slots=True)
class PhaseAction:
    """Operator-owned action classification, separate from adapter parameters."""

    adapter_id: str
    action: str
    phase: MigrationPhase

    def __post_init__(self):
        identifier(self.adapter_id, "adapter_id")
        identifier(self.action, "action")
        if not isinstance(self.phase, MigrationPhase):
            raise ContractError("Typed migration phase required")


def phase_action_digest(action_registry):
    """Fingerprint the complete trusted registry, including rejected alternatives."""
    from hashlib import sha256
    from sova.domain.contracts import canonical_json

    if (
        type(action_registry) is not tuple
        or not 1 <= len(action_registry) <= 256
        or any(not isinstance(a, PhaseAction) for a in action_registry)
    ):
        raise ContractError("Bounded trusted phase action registry required")
    keys = {(a.adapter_id, a.action) for a in action_registry}
    if len(keys) != len(action_registry):
        raise ContractError("Ambiguous phase action registry")
    document = {
        "actions": [
            {"adapter_id": a.adapter_id, "action": a.action, "phase": str(a.phase)}
            for a in sorted(action_registry, key=lambda a: (a.adapter_id, a.action))
        ]
    }
    return sha256(canonical_json(document, limit=131072).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class MigrationPhaseBinding:
    program: MigrationProgram
    phase: MigrationPhase
    plan: LifecyclePlan

    def __post_init__(self):
        if (
            not isinstance(self.program, MigrationProgram)
            or not isinstance(self.phase, MigrationPhase)
            or not isinstance(self.plan, LifecyclePlan)
        ):
            raise ContractError("Typed migration phase binding required")
        if (
            self.plan.purpose != PlanPurpose.MIGRATION_PHASE
            or self.plan.revisions != self.program.revisions
            or self.plan.valid_until > self.program.valid_until
            or self.plan.obligations
            != tuple(r.obligation for r in self.program.requirements)
        ):
            raise ContractError("Phase must preserve the complete migration program")
        environments = {
            self.program.source_scope.environment_id,
            self.program.target_scope.environment_id,
        }
        for step in self.plan.steps:
            if (
                step.scope.tenant_id != self.program.source_scope.tenant_id
                or step.scope.application_id != self.program.source_scope.application_id
                or step.scope.environment_id not in environments
            ):
                raise ContractError("Phase action crosses registered environments")

    def execution_gate(self, plan: LifecyclePlan, now: datetime) -> Gate:
        if plan != self.plan or plan.fingerprint != self.plan.fingerprint:
            raise ContractError("Plan is not bound to this migration phase")
        if not self.program.issued_at <= utc(now) < self.program.valid_until:
            raise ContractError("Migration phase program is not current")
        return _GATES[self.phase]

    def required_obligations(self, plan: LifecyclePlan):
        if plan != self.plan:
            raise ContractError("Plan is not bound to this migration phase")
        return tuple(
            r.obligation
            for r in self.program.requirements
            if r.obligation.due_gate <= _GATES[self.phase]
        )


def compile_migration_phase(
    program: MigrationProgram,
    phase: MigrationPhase,
    *,
    plan_id: str,
    created_by: str,
    steps: tuple[PlanStep, ...],
    action_registry: tuple[PhaseAction, ...],
    valid_until: datetime,
) -> MigrationPhaseBinding:
    """Only registered actions may run in an independently approved phase."""
    if not isinstance(program, MigrationProgram) or not isinstance(
        phase, MigrationPhase
    ):
        raise ContractError("Typed program and migration phase required")
    phase_action_digest(action_registry)
    actions = {(a.adapter_id, a.action): a.phase for a in action_registry}
    if (
        type(steps) is not tuple
        or not 1 <= len(steps) <= 128
        or any(not isinstance(s, PlanStep) for s in steps)
    ):
        raise ContractError("Bounded immutable phase steps required")
    for step in steps:
        if actions.get((step.adapter_id, step.action)) != phase:
            raise ContractError("Action is not registered for this migration phase")
    deadline = utc(valid_until)
    if not program.issued_at < deadline <= program.valid_until:
        raise ContractError("Phase validity exceeds the migration program")
    plan = LifecyclePlan(
        plan_id,
        program.source_scope.tenant_id,
        program.source_scope.application_id,
        created_by,
        PlanPurpose.MIGRATION_PHASE,
        program.revisions,
        deadline,
        steps,
        tuple(r.obligation for r in program.requirements),
        reason=f"migration:{program.fingerprint}:{phase}",
    )
    return MigrationPhaseBinding(program, phase, plan)
