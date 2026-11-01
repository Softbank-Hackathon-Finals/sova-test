"""Durable phase orchestration; verifier authentication remains a test double."""

from datetime import timedelta
from dataclasses import replace

import pytest

from test_postgres_migration_programs import saved as saved
from test_postgres_write_gate import gate as gate
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_governance import PostgresSecurityHolds
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.application.migration_phase_runner import MigrationPhaseRunner
from sova.application.migration_phases import PhaseAction, compile_migration_phase
from sova.domain.contracts import ContractError, EffectStatus
from sova.domain.evidence import EvidenceRecord, Gate, VerificationResult
from sova.domain.governance import SecurityHold
from sova.domain.migration_phases import MigrationPhase
from sova.domain.operations import OperationRequest
from sova.domain.plans import PlanApproval, PlanStep
from sova.domain.workflows import OperationProfile, OperationStatus
from sova.ports.execution import RecoveryRequired
from sova.ports.plans import RecordNotFound

pytestmark = pytest.mark.postgres


def setup(saved):
    programs, binding, registry, evidence = saved
    operations = PostgresOperationRepository(programs.lifecycle)
    operations.submit(
        OperationRequest(
            programs.tenant_id,
            "app",
            "phase-op",
            binding.plan.plan_id,
            binding.plan.fingerprint,
            "approved",
            1,
            "operator",
            "phase-request",
        )
    )
    return programs, operations, PostgresExecutionOwnership(programs.lifecycle)


def runner(saved, services, now, **changes):
    _, binding, registry, _ = saved
    ownership = next(
        o for o in binding.plan.obligations if o.due_gate == Gate.REGISTRATION
    )
    args = dict(
        journal_factory=PostgresEffectJournal,
        required_obligations=lambda _: (ownership,),
        action_registry_provider=lambda *_: registry,
        authenticate_registry=lambda _: None,
        authenticate_program=lambda _: None,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        governance_guard=lambda *_: now + timedelta(minutes=1),
        clock=lambda: now,
    )
    args.update(changes)
    return MigrationPhaseRunner(*services, **args)


def test_completed_phase_is_not_full_migration_and_duplicate_delivery_is_read_only(
    saved, now, adapter
):
    services = setup(saved)
    engine = runner(saved, services, now)
    result = engine.run(
        "app",
        "phase-op",
        owner_id="worker",
        evidence=saved[3],
        adapter_factory=lambda *_: adapter,
    )
    assert result["status"] == "phase_verified" and result["phase"] == "prepare"
    assert result["receipt_only"] and not result["full_migration_verified"]
    programs, operations, _ = services
    state = operations.get("app", "phase-op").state
    assert state.profile == OperationProfile.MIGRATION_PHASE
    with programs.lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT owner_id,token FROM sova_control.app_execution"
        ).fetchone() == (None, None)
        assert conn.execute(
            "SELECT suppressed_at IS NOT NULL FROM sova_control.operation_outbox"
        ).fetchone() == (True,)

    def forbidden(*_):
        raise AssertionError("duplicate delivery must not construct an adapter")

    again = engine.run(
        "app", "phase-op", owner_id="worker-2", evidence=(), adapter_factory=forbidden
    )
    assert (
        again["completion_digest"] == result["completion_digest"]
        and again["completion_recovered_read_only"]
    )
    assert len(adapter.calls) == 1


def test_committed_completion_reply_loss_reads_receipt_without_replaying(
    saved, now, adapter, monkeypatch
):
    services = setup(saved)
    programs, _, _ = services
    original = programs.finish_phase

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise ConnectionError("controlled completion reply loss")

    monkeypatch.setattr(programs, "finish_phase", lost)
    result = runner(saved, services, now).run(
        "app",
        "phase-op",
        owner_id="worker",
        evidence=saved[3],
        adapter_factory=lambda *_: adapter,
    )
    assert (
        result["status"] == "phase_verified"
        and result["completion_recovered_read_only"]
    )
    assert len(adapter.calls) == 1


def test_audit_failure_rolls_back_completion_state_and_lease_release(
    saved, now, adapter, monkeypatch
):
    services = setup(saved)
    programs, operations, _ = services
    original = programs.lifecycle.audit

    def failed(*args):
        if args[4] == "migration_phase_completed":
            raise RuntimeError("controlled completion audit failure")
        return original(*args)

    monkeypatch.setattr(programs.lifecycle, "audit", failed)
    with pytest.raises(RuntimeError, match="audit failure"):
        runner(saved, services, now).run(
            "app",
            "phase-op",
            owner_id="worker",
            evidence=saved[3],
            adapter_factory=lambda *_: adapter,
        )
    assert (
        operations.get("app", "phase-op").state.status
        == OperationStatus.RECOVERY_REQUIRED
    )
    with pytest.raises(RecordNotFound):
        programs.get_phase_completion(operations, "app", "phase-op")
    with programs.lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT owner_id FROM sova_control.app_execution"
        ).fetchone() == ("worker",)
    assert len(adapter.calls) == 1


def test_unknown_effect_retains_recovery_barrier_and_is_never_replayed(
    saved, now, adapter
):
    services = setup(saved)
    programs, operations, ownership = services

    def lost(_):
        raise ConnectionError("controlled reply loss")

    adapter.after_apply = lost
    engine = runner(saved, services, now)
    with pytest.raises(RuntimeError):
        engine.run(
            "app",
            "phase-op",
            owner_id="worker",
            evidence=saved[3],
            adapter_factory=lambda *_: adapter,
        )
    assert (
        operations.get("app", "phase-op").state.status
        == OperationStatus.RECOVERY_REQUIRED
    )
    with pytest.raises(ContractError, match="newly admitted"):
        engine.run(
            "app",
            "phase-op",
            owner_id="second",
            evidence=saved[3],
            adapter_factory=lambda *_: adapter,
        )
    with programs.lifecycle.transaction() as conn:
        assert conn.execute("SELECT status FROM sova_control.effects").fetchone() == (
            "unknown",
        )
        conn.execute(
            "UPDATE sova_control.app_execution SET valid_until=clock_timestamp()-interval '1 second'"
        )
    # A distinct accepted operation cannot bypass the unresolved app effect.
    operations.submit(
        OperationRequest(
            programs.tenant_id,
            "app",
            "next-op",
            saved[1].plan.plan_id,
            saved[1].plan.fingerprint,
            "approved",
            1,
            "operator",
            "different-request",
        )
    )
    with pytest.raises(RecoveryRequired):
        ownership.acquire("app", "next-op", "second")
    assert len(adapter.calls) == 1


def test_missing_gate_evidence_blocks_without_effect_and_releases_clean_lease(
    saved, now, adapter
):
    services = setup(saved)
    with pytest.raises(ContractError, match="verification"):
        runner(saved, services, now).run(
            "app",
            "phase-op",
            owner_id="worker",
            evidence=(),
            adapter_factory=lambda *_: adapter,
        )
    programs, operations, _ = services
    assert operations.get("app", "phase-op").state.status == OperationStatus.BLOCKED
    with programs.lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT owner_id FROM sova_control.app_execution"
        ).fetchone() == (None,)
        assert conn.execute("SELECT count(*) FROM sova_control.effects").fetchone() == (
            0,
        )
    assert not adapter.calls


def test_hold_opened_after_effect_blocks_atomic_completion(saved, now, adapter):
    services = setup(saved)
    programs, operations, _ = services
    holds = PostgresSecurityHolds(
        programs.lifecycle.connect, tenant_id=programs.tenant_id
    )
    adapter.after_apply = lambda _: holds.open_hold(
        SecurityHold(
            "incident",
            saved[1].plan.steps[0].scope,
            "security",
            "controlled incident",
            now,
        )
    )
    with pytest.raises(ContractError, match="hold"):
        runner(saved, services, now).run(
            "app",
            "phase-op",
            owner_id="worker",
            evidence=saved[3],
            adapter_factory=lambda *_: adapter,
        )
    assert (
        operations.get("app", "phase-op").state.status
        == OperationStatus.RECOVERY_REQUIRED
    )
    with pytest.raises(RecordNotFound):
        programs.get_phase_completion(operations, "app", "phase-op")


def test_final_readback_failure_does_not_become_phase_success(saved, now, adapter):
    services = setup(saved)

    def changed(_):
        if adapter.reads >= 2:
            adapter.blocked = False

    adapter.before_read = changed
    with pytest.raises(RuntimeError, match="Final phase readback"):
        runner(saved, services, now).run(
            "app",
            "phase-op",
            owner_id="worker",
            evidence=saved[3],
            adapter_factory=lambda *_: adapter,
        )
    assert (
        services[1].get("app", "phase-op").state.status
        == OperationStatus.RECOVERY_REQUIRED
    )


def test_adapter_cannot_request_another_steps_grant(saved, now, adapter):
    services = setup(saved)

    def factory(step, grant):
        adapter.before_apply = lambda command: grant(
            replace(command, step_id="unapproved-step")
        )
        return adapter

    with pytest.raises(RuntimeError):
        runner(saved, services, now).run(
            "app",
            "phase-op",
            owner_id="worker",
            evidence=saved[3],
            adapter_factory=factory,
        )
    assert not adapter.calls


def writer_phase_profile(saved, gate, now):
    programs, old, _, _ = saved
    adapter, _, _ = gate
    scope = old.program.source_scope
    adapter.registration = replace(adapter.registration, scope=scope)
    registry = (
        PhaseAction(adapter.adapter_id, "pause_writes", MigrationPhase.QUIESCE),
    )
    binding = compile_migration_phase(
        old.program,
        MigrationPhase.QUIESCE,
        plan_id="pause-phase",
        created_by="planner",
        steps=(
            PlanStep(
                "pause", scope, adapter.adapter_id, "pause_writes", "{}", "writer:1"
            ),
        ),
        action_registry=registry,
        valid_until=old.program.valid_until,
    )
    programs.lifecycle.save_plan(binding.plan)
    programs.lifecycle.save_approval(
        "app",
        binding.plan.plan_id,
        "pause-approved",
        PlanApproval(
            binding.plan.fingerprint,
            "approver",
            binding.plan.purpose,
            binding.plan.valid_until,
        ),
    )
    programs.save_binding(binding, action_registry=registry, actor_id="publisher")
    evidence = tuple(
        EvidenceRecord(
            f"e-{i}",
            o.obligation_id,
            o.scope,
            binding.program.revisions,
            o.verifier_version,
            now - timedelta(microseconds=1),
            now + timedelta(minutes=1),
            VerificationResult.PASS,
            "test-only",
            "e" * 64,
        )
        for i, o in enumerate(binding.plan.obligations)
        if o.due_gate <= Gate.PROTECTION
    )
    new_saved = (programs, binding, registry, evidence)
    operations = PostgresOperationRepository(programs.lifecycle)
    operations.submit(
        OperationRequest(
            programs.tenant_id,
            "app",
            "phase-op",
            binding.plan.plan_id,
            binding.plan.fingerprint,
            "pause-approved",
            1,
            "operator",
            "pause-request",
        )
    )
    services = (programs, operations, PostgresExecutionOwnership(programs.lifecycle))

    def factory(step, grant):
        adapter.authorize_mutation = grant
        return adapter

    return new_saved, services, factory


def test_actual_database_writer_is_executed_by_phase_worker(saved, gate, now):
    new_saved, services, factory = writer_phase_profile(saved, gate, now)
    programs, operations, _ = services
    result = runner(new_saved, services, now).run(
        "app",
        "phase-op",
        owner_id="worker",
        evidence=new_saved[3],
        adapter_factory=factory,
    )
    assert result["phase"] == "quiesce" and result["status"] == "phase_verified"
    _, proof = programs.get_phase_completion(operations, "app", "phase-op")
    assert proof.observations[0].status == EffectStatus.APPLIED
    assert proof.observations[0].evidence["all_writers_fenced"] is False


def test_terminal_phase_state_cannot_be_claimed_through_generic_advance(saved, now):
    services = setup(saved)
    _, operations, ownership = services
    lease = ownership.acquire("app", "phase-op", "worker")
    for call in (
        lambda: operations.advance(
            "app",
            "phase-op",
            OperationStatus.PHASE_VERIFIED,
            expected_revision=1,
            actor_id="worker",
        ),
        lambda: operations.advance_owned(
            ownership,
            lease,
            OperationStatus.PHASE_VERIFIED,
            expected_revision=1,
            actor_id="worker",
        ),
    ):
        with pytest.raises(ContractError, match="atomic"):
            call()
