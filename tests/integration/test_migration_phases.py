"""Phase admission with real effect persistence; adapters are test doubles."""

import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest

from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.migration_phases import (
    MigrationPhase as Phase,
    PhaseAction,
    compile_migration_phase,
)
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.domain.contracts import ContractError, EffectStatus
from sova.domain.evidence import EvidenceRecord, Gate, RevisionSet, VerificationResult
from sova.domain.migration_program import six_area_program
from sova.domain.plans import PlanApproval, PlanStep


@pytest.fixture
def setup(scope, now):
    target = replace(scope, environment_id="destination")
    program = six_area_program(
        scope,
        target,
        RevisionSet(*("a" * 64, "b" * 64, "c" * 64, "d" * 64)),
        issued_at=now - timedelta(seconds=1),
        valid_until=now + timedelta(minutes=10),
    )
    step = PlanStep(
        "prepare", target, "test-ingress", "set_ingress", '{"blocked":true}', "r1"
    )
    registry = (PhaseAction("test-ingress", "set_ingress", Phase.PREPARE),)

    def compile(phase=Phase.PREPARE, **changes):
        args = dict(
            plan_id="phase-plan",
            created_by="planner",
            steps=(step,),
            action_registry=registry,
            valid_until=program.valid_until,
        )
        args.update(changes)
        return compile_migration_phase(program, phase, **args)

    return program, step, compile


def records(binding, now, *, through=Gate.CHANGE):
    return tuple(
        EvidenceRecord(
            f"e-{index}",
            row.obligation.obligation_id,
            row.obligation.scope,
            binding.program.revisions,
            row.obligation.verifier_version,
            now - timedelta(microseconds=1),
            now + timedelta(minutes=1),
            VerificationResult.PASS,
            "test-artifact",
            "f" * 64,
        )
        for index, row in enumerate(binding.program.requirements)
        if row.obligation.due_gate <= through
    )


def executor(binding, connection, now, **changes):
    args = dict(
        required_obligations=binding.required_obligations,
        execution_gate=binding.execution_gate,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    args.update(changes)
    return ApprovedPlanExecutor(
        EffectExecutor(
            SQLiteEffectJournal(connection),
            authorize=lambda *_: None,
            clock=lambda: now,
        ),
        **args,
    )


def approval(binding):
    p = binding.plan
    return PlanApproval(p.fingerprint, "independent-approver", p.purpose, p.valid_until)


def test_preparation_can_execute_without_claiming_cutover(setup, now, adapter):
    _, _, compile = setup
    binding = compile()
    with sqlite3.connect(":memory:") as connection:
        runner = executor(binding, connection, now)
        evidence = records(binding, now)
        checked = runner.check_plan(binding.plan, approval(binding), evidence, now)
        assert checked.gate.gate == Gate.CHANGE
        assert "migration:final-data" in checked.gate.carry_forward
        assert len(binding.plan.obligations) == 24
        result = runner.execute_step(
            binding.plan,
            approval(binding),
            "prepare",
            operation_id="op",
            epoch=1,
            evidence=evidence,
            adapter=adapter,
        )
        assert result.status == EffectStatus.APPLIED
        assert len(adapter.calls) == 1
        assert not binding.program.assess(evidence, Gate.PREFLIGHT, now=now)[
            "gate_accepted"
        ]


@pytest.mark.parametrize("phase", [Phase.REHEARSE, Phase.CUTOVER, Phase.POSTCHECK])
def test_later_phases_cannot_use_only_preparation_evidence(setup, now, phase):
    _, _, compile = setup
    binding = compile(
        phase, action_registry=(PhaseAction("test-ingress", "set_ingress", phase),)
    )
    with sqlite3.connect(":memory:") as connection:
        with pytest.raises(ContractError, match="verification"):
            executor(binding, connection, now).check_plan(
                binding.plan, approval(binding), records(binding, now), now
            )


def test_cutover_action_cannot_be_relabelled_preparation(setup):
    _, _, compile = setup
    with pytest.raises(ContractError, match="not registered"):
        compile(
            action_registry=(PhaseAction("test-ingress", "set_ingress", Phase.CUTOVER),)
        )


def test_registry_conflict_is_rejected(setup):
    _, _, compile = setup
    with pytest.raises(ContractError, match="Ambiguous"):
        compile(
            action_registry=(
                PhaseAction("test-ingress", "set_ingress", Phase.CUTOVER),
                PhaseAction("test-ingress", "set_ingress", Phase.PREPARE),
            )
        )


@pytest.mark.parametrize("change", ["parameters", "obligations", "revision", "plan_id"])
def test_phase_binding_rejects_changed_plan_even_with_new_approval(setup, now, change):
    _, step, compile = setup
    binding = compile()
    plan = binding.plan
    changes = {
        "parameters": dict(steps=(replace(step, parameters_json='{"blocked":false}'),)),
        "obligations": dict(obligations=plan.obligations[:-1]),
        "revision": dict(revisions=replace(plan.revisions, source="e" * 64)),
        "plan_id": dict(plan_id="different"),
    }
    altered = replace(plan, **changes[change])
    with pytest.raises(ContractError, match="not bound"):
        binding.execution_gate(altered, now)


def test_program_expiry_and_future_are_rejected(setup, now):
    program, _, compile = setup
    binding = compile()
    for clock in (program.issued_at - timedelta(seconds=1), program.valid_until):
        with pytest.raises(ContractError, match="not current"):
            binding.execution_gate(binding.plan, clock)


def test_default_executor_still_requires_g7(setup, now):
    _, _, compile = setup
    binding = compile()
    with sqlite3.connect(":memory:") as connection:
        with pytest.raises(ContractError, match="verification"):
            executor(binding, connection, now, execution_gate=None).check_plan(
                binding.plan, approval(binding), records(binding, now), now
            )


def test_phase_policy_is_rechecked_before_mutation(setup, now, adapter):
    _, _, compile = setup
    binding = compile()
    count = 0

    def revoked(plan, clock):
        nonlocal count
        count += 1
        if count >= 3:
            raise ContractError("Phase binding revoked")
        return binding.execution_gate(plan, clock)

    with sqlite3.connect(":memory:") as connection:
        runner = executor(binding, connection, now, execution_gate=revoked)
        with pytest.raises(ContractError, match="revoked"):
            runner.execute_step(
                binding.plan,
                approval(binding),
                "prepare",
                operation_id="op",
                epoch=1,
                evidence=records(binding, now),
                adapter=adapter,
            )
        assert not adapter.calls


def test_phase_cannot_cross_registered_environment(setup):
    _, step, compile = setup
    with pytest.raises(ContractError, match="registered environments"):
        compile(
            steps=(
                replace(step, scope=replace(step.scope, environment_id="unregistered")),
            )
        )


@pytest.mark.postgres
def test_stored_phase_survives_restart_and_honors_revocation(
    postgres_bundle, now, adapter, tmp_path
):
    repo, template, _, _, _ = postgres_bundle
    source = template.steps[0].scope
    target = replace(source, environment_id="destination")
    program = six_area_program(
        source,
        target,
        template.revisions,
        issued_at=now - timedelta(seconds=1),
        valid_until=template.valid_until,
    )
    step = replace(template.steps[0], scope=target)
    binding = compile_migration_phase(
        program,
        Phase.PREPARE,
        plan_id="prepare-plan",
        created_by="planner",
        steps=(step,),
        action_registry=(PhaseAction("test-ingress", "set_ingress", Phase.PREPARE),),
        valid_until=program.valid_until,
    )
    repo.save_plan(binding.plan)
    repo.save_approval(
        "app", binding.plan.plan_id, "prepare-approved", approval(binding)
    )
    restarted = PostgresLifecycleRepository(
        repo.connect, tenant_id=repo.tenant_id, clock=lambda: now
    )
    with sqlite3.connect(tmp_path / "effects.sqlite") as connection:
        runner = StoredPlanExecutor(restarted, executor(binding, connection, now))
        checked = runner.check_plan(
            "app",
            binding.plan.plan_id,
            "prepare-approved",
            evidence=records(binding, now),
        )
        assert checked.gate.gate == Gate.CHANGE
        assert "migration:final-data" in checked.gate.carry_forward
        result = runner.execute_step(
            "app",
            binding.plan.plan_id,
            "prepare-approved",
            step.step_id,
            operation_id="prepare-operation",
            epoch=1,
            evidence=records(binding, now),
            adapter=adapter,
        )
        assert result.status == EffectStatus.APPLIED
        repo.revoke_approval(
            "app", "prepare-approved", expected_revision=1, actor_id="security"
        )
        with pytest.raises(ContractError, match="revoked"):
            runner.execute_step(
                "app",
                binding.plan.plan_id,
                "prepare-approved",
                step.step_id,
                operation_id="prepare-operation",
                epoch=1,
                evidence=records(binding, now),
                adapter=adapter,
            )
        assert len(adapter.calls) == 1
