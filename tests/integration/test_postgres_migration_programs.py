"""Real immutable program storage and reload-before-dispatch policy tests."""

from dataclasses import replace
from datetime import timedelta
import sqlite3

import psycopg
from psycopg import sql
import pytest
from uuid import uuid4

from sova.adapters.postgres_migration_programs import PostgresMigrationProgramRepository
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.migration_phases import (
    MigrationPhase as Phase,
    PhaseAction,
    compile_migration_phase,
)
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_migration_phases import StoredMigrationPhaseExecutor
from sova.domain.contracts import ContractError, EffectStatus
from sova.domain.evidence import EvidenceRecord, Gate, VerificationResult
from sova.domain.migration_program import six_area_program
from sova.domain.plans import PlanApproval
from sova.ports.plans import RecordNotFound, RepositoryConflict

pytestmark = pytest.mark.postgres


@pytest.fixture
def saved(postgres_bundle, now):
    lifecycle, template, _, _, _ = postgres_bundle
    source = template.steps[0].scope
    target = replace(source, environment_id="destination")
    program = six_area_program(
        source,
        target,
        template.revisions,
        issued_at=now - timedelta(seconds=1),
        valid_until=now + timedelta(minutes=5),
    )
    registry = (PhaseAction("test-ingress", "set_ingress", Phase.PREPARE),)
    binding = compile_migration_phase(
        program,
        Phase.PREPARE,
        plan_id="prepare",
        created_by="planner",
        steps=(replace(template.steps[0], scope=target),),
        action_registry=registry,
        valid_until=program.valid_until,
    )
    repository = PostgresMigrationProgramRepository(lifecycle)
    repository.save_program(program, actor_id="registered-publisher")
    lifecycle.save_plan(binding.plan)
    approval = PlanApproval(
        binding.plan.fingerprint,
        "approver",
        binding.plan.purpose,
        binding.plan.valid_until,
    )
    lifecycle.save_approval("app", "prepare", "approved", approval)
    repository.save_binding(
        binding, action_registry=registry, actor_id="registered-publisher"
    )
    evidence = tuple(
        EvidenceRecord(
            f"e-{i}",
            o.obligation_id,
            o.scope,
            program.revisions,
            o.verifier_version,
            now - timedelta(microseconds=1),
            now + timedelta(minutes=1),
            VerificationResult.PASS,
            "test-only",
            "e" * 64,
        )
        for i, o in enumerate(binding.plan.obligations)
        if o.due_gate <= Gate.CHANGE
    )
    return repository, binding, registry, evidence


def runner(saved, connection, now, **changes):
    repository, binding, registry, _ = saved
    ownership = next(
        o for o in binding.plan.obligations if o.due_gate == Gate.REGISTRATION
    )
    base = ApprovedPlanExecutor(
        EffectExecutor(
            SQLiteEffectJournal(connection),
            authorize=lambda *_: None,
            clock=lambda: now,
        ),
        required_obligations=lambda _: (ownership,),
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    args = dict(
        action_registry_provider=lambda *_: registry,
        authenticate_registry=lambda _: None,
        authenticate_program=lambda _: None,
    )
    args.update(changes)
    return StoredMigrationPhaseExecutor(repository, base, **args)


def test_immutable_program_binding_restarts_with_complete_obligations(saved, now):
    repository, binding, registry, _ = saved
    restarted = PostgresMigrationProgramRepository(
        PostgresLifecycleRepository(
            repository.lifecycle.connect,
            tenant_id=repository.tenant_id,
            clock=lambda: now,
        )
    )
    assert restarted.get_program("app", binding.program.fingerprint) == binding.program
    assert restarted.get_binding("app", "prepare", action_registry=registry) == binding
    repository.save_program(binding.program, actor_id="registered-publisher")
    repository.save_binding(
        binding, action_registry=registry, actor_id="registered-publisher"
    )
    with repository.lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.lifecycle_audit WHERE action IN ('migration_program_created','migration_phase_bound')"
        ).fetchone() == (2,)


def test_stored_phase_dispatch_reloads_policy_and_does_not_drop_future_checks(
    saved, now, adapter
):
    _, binding, _, evidence = saved
    with sqlite3.connect(":memory:") as connection:
        engine = runner(saved, connection, now)
        checked = engine.check_plan("app", "prepare", "approved", evidence=evidence)
        assert checked.gate.gate == Gate.CHANGE
        assert "migration:single-writer" in checked.gate.carry_forward
        assert (
            engine.execute_step(
                "app",
                "prepare",
                "approved",
                binding.plan.steps[0].step_id,
                operation_id="op",
                epoch=1,
                evidence=evidence,
                adapter=adapter,
            ).status
            == EffectStatus.APPLIED
        )


def test_changed_registry_requires_new_binding_and_approval(saved, now, adapter):
    repository, binding, registry, evidence = saved
    changed = (*registry, PhaseAction("other", "switch_traffic", Phase.CUTOVER))
    with pytest.raises(RepositoryConflict, match="replaced"):
        repository.save_binding(
            binding, action_registry=changed, actor_id="registered-publisher"
        )
    with sqlite3.connect(":memory:") as connection:
        engine = runner(
            saved, connection, now, action_registry_provider=lambda *_: changed
        )
        with pytest.raises(ContractError, match="registry differs"):
            engine.execute_step(
                "app",
                "prepare",
                "approved",
                binding.plan.steps[0].step_id,
                operation_id="op",
                epoch=1,
                evidence=evidence,
                adapter=adapter,
            )
    assert not adapter.calls


def test_registry_changed_after_claim_blocks_external_mutation(
    saved, now, adapter, monkeypatch
):
    _, binding, registry, evidence = saved
    current = [registry]
    with sqlite3.connect(":memory:") as connection:
        engine = runner(
            saved, connection, now, action_registry_provider=lambda *_: current[0]
        )
        journal = engine.executor.effects.journal
        original = journal.transition

        def change_after_claim(*args, **kwargs):
            result = original(*args, **kwargs)
            if result.status == EffectStatus.IN_FLIGHT:
                current[0] = (
                    *registry,
                    PhaseAction("other", "switch_traffic", Phase.CUTOVER),
                )
            return result

        monkeypatch.setattr(journal, "transition", change_after_claim)
        with pytest.raises(ContractError, match="registry differs"):
            engine.execute_step(
                "app",
                "prepare",
                "approved",
                binding.plan.steps[0].step_id,
                operation_id="op",
                epoch=1,
                evidence=evidence,
                adapter=adapter,
            )
        command = binding.plan.command(
            binding.plan.steps[0].step_id, operation_id="op", epoch=1
        )
        assert journal.get(command).status == EffectStatus.NOT_APPLIED
    assert not adapter.calls


def test_program_authentication_failure_and_security_hold_still_block(
    saved, now, adapter
):
    _, binding, _, evidence = saved

    def denied(*_):
        raise ContractError("program registration revoked")

    with sqlite3.connect(":memory:") as connection:
        engine = runner(saved, connection, now, authenticate_program=denied)
        with pytest.raises(ContractError, match="revoked"):
            engine.execute_step(
                "app",
                "prepare",
                "approved",
                binding.plan.steps[0].step_id,
                operation_id="op",
                epoch=1,
                evidence=evidence,
                adapter=adapter,
            )
        engine = runner(saved, connection, now)
        engine.executor.governance_guard = denied
        with pytest.raises(ContractError, match="revoked"):
            engine.execute_step(
                "app",
                "prepare",
                "approved",
                binding.plan.steps[0].step_id,
                operation_id="op",
                epoch=1,
                evidence=evidence,
                adapter=adapter,
            )
    assert not adapter.calls


def test_wrong_tenant_or_application_cannot_read_bindings(saved, now):
    repository, binding, registry, _ = saved
    other = PostgresMigrationProgramRepository(
        PostgresLifecycleRepository(
            repository.lifecycle.connect, tenant_id="another-tenant", clock=lambda: now
        )
    )
    for repo, app in ((repository, "another-app"), (other, "app")):
        with pytest.raises(RecordNotFound):
            repo.get_program(app, binding.program.fingerprint)
        with pytest.raises(RecordNotFound):
            repo.get_binding(app, "prepare", action_registry=registry)
    with repository.lifecycle.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.migration_programs"
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT count(*) FROM sova_control.migration_phase_bindings"
        ).fetchone() == (0,)


@pytest.mark.parametrize("table", ["migration_programs", "migration_phase_bindings"])
def test_runtime_cannot_overwrite_or_delete_published_policy(saved, table):
    repository, *_ = saved
    for query in (
        f"UPDATE sova_control.{table} SET created_by='forged'",
        f"DELETE FROM sova_control.{table}",
    ):
        with repository.lifecycle.transaction() as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(query)


def test_failed_audit_rolls_back_program_publish(saved, monkeypatch):
    repository, binding, _, _ = saved
    program = replace(
        binding.program, valid_until=binding.program.valid_until - timedelta(seconds=1)
    )

    def fail(*_):
        raise RuntimeError("controlled audit failure")

    monkeypatch.setattr(repository.lifecycle, "audit", fail)
    with pytest.raises(RuntimeError, match="audit failure"):
        repository.save_program(program, actor_id="registered-publisher")
    with pytest.raises(RecordNotFound):
        repository.get_program("app", program.fingerprint)


def test_worker_with_select_only_rights_can_restore_but_not_publish(
    saved, postgres_database, now
):
    repository, binding, registry, _ = saved
    dsn, _ = postgres_database
    role = "phase_reader_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEDB NOCREATEROLE"
            ).format(sql.Identifier(role))
        )
        owner.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        owner.execute(
            sql.SQL(
                "GRANT SELECT ON sova_control.plans,sova_control.migration_programs,sova_control.migration_phase_bindings TO {}"
            ).format(sql.Identifier(role))
        )
    worker = PostgresMigrationProgramRepository(
        PostgresLifecycleRepository(
            lambda: psycopg.connect(dsn, user=role),
            tenant_id=repository.tenant_id,
            clock=lambda: now,
        )
    )
    try:
        assert worker.get_binding("app", "prepare", action_registry=registry) == binding
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.save_program(binding.program, actor_id="worker")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            worker.save_binding(binding, action_registry=registry, actor_id="worker")
    finally:
        with psycopg.connect(dsn, autocommit=True) as owner:
            owner.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            owner.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


@pytest.mark.parametrize("future", [False, True], ids=["expired", "future"])
def test_database_clock_denies_noncurrent_program_before_dispatch(saved, now, future):
    repository, binding, registry, _ = saved
    program = replace(
        binding.program,
        issued_at=now + timedelta(minutes=1) if future else now - timedelta(minutes=2),
        valid_until=now + timedelta(minutes=2)
        if future
        else now - timedelta(minutes=1),
    )
    phase = compile_migration_phase(
        program,
        Phase.PREPARE,
        plan_id="noncurrent",
        created_by="planner",
        steps=binding.plan.steps,
        action_registry=registry,
        valid_until=program.valid_until,
    )
    repository.save_program(program, actor_id="publisher")
    repository.lifecycle.save_plan(phase.plan)
    repository.save_binding(phase, action_registry=registry, actor_id="publisher")
    with pytest.raises(ContractError, match="not current"):
        repository.get_binding("app", "noncurrent", action_registry=registry)
