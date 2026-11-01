"""Real database effects; authorization callbacks here are isolated test policy."""

from dataclasses import replace
from datetime import timedelta
import sqlite3
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest

from sova.adapters.postgres_write_gate import (
    PostgresWriteGateAdapter,
    PostgresWriteGateRegistration,
)
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor, UncertainEffect
from sova.domain.contracts import ContractError, EffectStatus
from support import permit_for

pytestmark = pytest.mark.postgres


@pytest.fixture
def gate(postgres_database, scope, now):
    dsn, _ = postgres_database
    suffix = uuid4().hex
    schema, role = "gate_" + suffix, "gate_executor_" + suffix
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION"
            ).format(sql.Identifier(role))
        )
        owner.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        owner.execute(
            sql.SQL(
                "CREATE TABLE {}.control(singleton boolean PRIMARY KEY CHECK(singleton), writes_enabled boolean NOT NULL, writer_epoch bigint NOT NULL, execution_epoch bigint NOT NULL, last_command_digest text)"
            ).format(sql.Identifier(schema))
        )
        owner.execute(
            sql.SQL("INSERT INTO {}.control VALUES(true,true,1,0,NULL)").format(
                sql.Identifier(schema)
            )
        )
        owner.execute(
            sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(role)
            )
        )
        owner.execute(
            sql.SQL(
                "GRANT SELECT,UPDATE(writes_enabled,writer_epoch,execution_epoch,last_command_digest) ON {}.control TO {}"
            ).format(sql.Identifier(schema), sql.Identifier(role))
        )
        owner.execute(
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}"
            ).format(sql.Identifier(role))
        )
        identity = owner.execute(
            "SELECT current_database(),d.oid,c.system_identifier::text FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_control_system() c WHERE d.datname=current_database()"
        ).fetchone()
        oid = owner.execute(
            "SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname='control'",
            (schema,),
        ).fetchone()[0]
    registration = PostgresWriteGateRegistration(
        scope,
        "registered-writer",
        *identity,
        role,
        schema,
        oid,
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
        True,
    )
    adapter = PostgresWriteGateAdapter(
        registration,
        connect=lambda _: psycopg.connect(dsn, user=role),
        authenticate_registration=lambda _: None,
        authorize_mutation=permit_for,
        clock=lambda: now,
    )
    try:
        yield adapter, dsn, schema
    finally:
        with psycopg.connect(dsn, autocommit=True) as owner:
            owner.execute(
                sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role))
            )
            owner.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )
            owner.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def writer_command(command, adapter, **changes):
    args = dict(
        adapter_id=adapter.adapter_id,
        action="pause_writes",
        parameters_json="{}",
        expected_revision="writer:1",
        expires_at=adapter.registration.valid_until,
    )
    args.update(changes)
    return replace(command, **args)


def test_real_writer_pause_is_journaled_and_exactly_read_back(gate, command, now):
    adapter, dsn, schema = gate
    command = writer_command(command, adapter)
    with sqlite3.connect(":memory:") as db:
        runner = EffectExecutor(
            SQLiteEffectJournal(db), authorize=lambda *_: None, clock=lambda: now
        )
        result = runner.execute(command, permit_for(command), adapter)
        assert result.status == EffectStatus.APPLIED
        assert runner.execute(command, permit_for(command), adapter) == result
    with psycopg.connect(dsn) as owner:
        assert owner.execute(
            sql.SQL(
                "SELECT writes_enabled,writer_epoch,execution_epoch,last_command_digest FROM {}.control"
            ).format(sql.Identifier(schema))
        ).fetchone() == (False, 2, command.fencing_epoch, command.fingerprint)


def test_stale_writer_revision_or_executor_epoch_cannot_change_state(gate, command):
    adapter, _, _ = gate
    command = writer_command(command, adapter, fencing_epoch=3)
    adapter.apply(command)
    for altered in (
        replace(command, action="resume_writes"),
        replace(
            command,
            action="resume_writes",
            expected_revision="writer:2",
            fencing_epoch=2,
        ),
    ):
        with pytest.raises(ContractError, match="revision or executor epoch"):
            adapter.apply(altered)
    assert adapter.readback(command, adapter.clock()).status == EffectStatus.APPLIED


def test_unrelated_matching_state_is_not_a_receipt(gate, command, now):
    adapter, dsn, schema = gate
    command = writer_command(command, adapter)
    with psycopg.connect(dsn) as owner:
        owner.execute(
            sql.SQL(
                "UPDATE {}.control SET writes_enabled=false,writer_epoch=2,execution_epoch=%s"
            ).format(sql.Identifier(schema)),
            (command.fencing_epoch,),
        )
    assert adapter.readback(command, now).status == EffectStatus.UNKNOWN


def test_committed_response_loss_reconciles_without_reapplying(gate, command, now):
    adapter, _, _ = gate
    command = writer_command(command, adapter)

    class LostResponse:
        adapter_id = adapter.adapter_id
        validate = adapter.validate
        readback = adapter.readback

        def apply(self, current):
            adapter.apply(current)
            raise ConnectionError("controlled response loss after database commit")

    with sqlite3.connect(":memory:") as db:
        runner = EffectExecutor(
            SQLiteEffectJournal(db), authorize=lambda *_: None, clock=lambda: now
        )
        with pytest.raises(UncertainEffect):
            runner.execute(command, permit_for(command), LostResponse())
        with pytest.raises(UncertainEffect):
            runner.execute(command, permit_for(command), LostResponse())
        # Test policy establishes no remote in-flight request; the production
        # coordinator must provide that fencing proof before reconciliation.
        assert (
            runner.reconcile(command, permit_for(command), adapter).status
            == EffectStatus.APPLIED
        )


@pytest.mark.parametrize(
    "field", ["database_oid", "control_oid", "system_identifier", "executor_role"]
)
def test_registration_identity_drift_denies_mutation(gate, command, field):
    adapter, _, _ = gate
    value = getattr(adapter.registration, field)
    changed = value + 1 if isinstance(value, int) else value + "-drift"
    adapter.registration = replace(adapter.registration, **{field: changed})
    with pytest.raises(ContractError, match="identity"):
        adapter.apply(writer_command(command, adapter))


def test_owner_credentials_and_unregistered_sql_parameters_are_rejected(gate, command):
    adapter, dsn, _ = gate
    command = writer_command(command, adapter)
    adapter.connect = lambda _: psycopg.connect(dsn)
    with pytest.raises(ContractError, match="identity"):
        adapter.apply(command)
    with pytest.raises(ContractError, match="explicit"):
        adapter.validate(replace(command, parameters_json='{"sql":"DELETE"}'))


def test_runtime_executor_cannot_create_or_delete_control_rows(gate):
    adapter, _, schema = gate
    for statement in ("DELETE FROM {}.control", "DROP TABLE {}.control"):
        with adapter.connect("registered-writer") as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(sql.SQL(statement).format(sql.Identifier(schema)))


def test_unregistered_trigger_and_broad_table_grants_block_dispatch(gate, command):
    adapter, dsn, schema = gate
    command = writer_command(command, adapter)
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "CREATE FUNCTION {}.unregistered() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NEW; END$$"
            ).format(sql.Identifier(schema))
        )
        owner.execute(
            sql.SQL(
                "CREATE TRIGGER unregistered BEFORE UPDATE ON {}.control FOR EACH ROW EXECUTE FUNCTION {}.unregistered()"
            ).format(sql.Identifier(schema), sql.Identifier(schema))
        )
    with pytest.raises(ContractError, match="unregistered behavior"):
        adapter.apply(command)
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL("DROP TRIGGER unregistered ON {}.control").format(
                sql.Identifier(schema)
            )
        )
        owner.execute(
            sql.SQL("GRANT UPDATE ON {}.control TO {}").format(
                sql.Identifier(schema),
                sql.Identifier(adapter.registration.executor_role),
            )
        )
    with pytest.raises(ContractError, match="broad privileges"):
        adapter.apply(command)


def test_database_clock_rejects_expired_command_despite_skewed_process_clock(
    gate, command, now
):
    adapter, dsn, schema = gate
    # The injected test clock claims the grant is current; real PG is authoritative.
    registration = replace(adapter.registration, issued_at=now - timedelta(minutes=2))
    adapter.registration = registration
    adapter.clock = lambda: now - timedelta(minutes=1)
    command = writer_command(command, adapter, expires_at=now - timedelta(seconds=1))
    with pytest.raises(ContractError, match="revision or executor epoch"):
        adapter.apply(command)
    with psycopg.connect(dsn) as owner:
        assert owner.execute(
            sql.SQL("SELECT writes_enabled,writer_epoch FROM {}.control").format(
                sql.Identifier(schema)
            )
        ).fetchone() == (True, 1)


@pytest.mark.parametrize("kind", ["wrong-command", "hold", "missing"])
def test_mutation_needs_current_authenticated_command_grant(gate, command, kind):
    adapter, _, _ = gate
    command = writer_command(command, adapter)
    grants = {
        "wrong-command": replace(permit_for(command), command_digest="f" * 64),
        "hold": replace(permit_for(command), security_hold=True),
        "missing": None,
    }
    adapter.authorize_mutation = lambda _: grants[kind]
    with pytest.raises(ContractError):
        adapter.apply(command)


def test_database_clock_limits_mutation_to_grant_not_longer_plan_lifetime(
    gate, command, now
):
    adapter, dsn, schema = gate
    adapter.registration = replace(
        adapter.registration, issued_at=now - timedelta(minutes=2)
    )
    adapter.clock = lambda: now - timedelta(minutes=1)
    command = writer_command(command, adapter)
    adapter.authorize_mutation = lambda current: permit_for(
        current, expires_at=now - timedelta(seconds=1)
    )
    with pytest.raises(ContractError, match="revision or executor epoch"):
        adapter.apply(command)
    with psycopg.connect(dsn) as owner:
        assert owner.execute(
            sql.SQL("SELECT writes_enabled,writer_epoch FROM {}.control").format(
                sql.Identifier(schema)
            )
        ).fetchone() == (True, 1)


def test_stored_quiesce_phase_uses_postgres_lease_journal_and_actual_writer(
    gate, postgres_bundle, now
):
    from sova.adapters.postgres_effects import PostgresEffectJournal
    from sova.adapters.postgres_execution import PostgresExecutionOwnership
    from sova.adapters.postgres_operations import PostgresOperationRepository
    from sova.application.migration_phases import (
        MigrationPhase,
        PhaseAction,
        compile_migration_phase,
    )
    from sova.application.plans import ApprovedPlanExecutor
    from sova.application.stored_plans import StoredPlanExecutor
    from sova.domain.evidence import EvidenceRecord, Gate, VerificationResult
    from sova.domain.migration_program import six_area_program
    from sova.domain.operations import OperationRequest
    from sova.domain.plans import PlanApproval, PlanStep

    adapter, _, _ = gate
    repo, template, _, _, _ = postgres_bundle
    source = template.steps[0].scope
    adapter.registration = replace(adapter.registration, scope=source)
    program = six_area_program(
        source,
        replace(source, environment_id="destination"),
        template.revisions,
        issued_at=now - timedelta(seconds=1),
        valid_until=adapter.registration.valid_until,
    )
    binding = compile_migration_phase(
        program,
        MigrationPhase.QUIESCE,
        plan_id="cutover-phase",
        created_by="planner",
        steps=(
            PlanStep(
                "pause-source",
                source,
                adapter.adapter_id,
                "pause_writes",
                "{}",
                "writer:1",
            ),
        ),
        action_registry=(
            PhaseAction(adapter.adapter_id, "pause_writes", MigrationPhase.QUIESCE),
        ),
        valid_until=program.valid_until,
    )
    plan = binding.plan
    approval = PlanApproval(
        plan.fingerprint, "approver", plan.purpose, plan.valid_until
    )
    repo.save_plan(plan)
    repo.save_approval("app", plan.plan_id, "cutover-approved", approval)
    operations = PostgresOperationRepository(repo)
    operations.submit(
        OperationRequest(
            repo.tenant_id,
            "app",
            "cutover-operation",
            plan.plan_id,
            plan.fingerprint,
            "cutover-approved",
            1,
            "operator",
            "cutover-request",
        )
    )
    ownership = PostgresExecutionOwnership(repo)
    lease = ownership.acquire("app", "cutover-operation", "worker")
    journal = PostgresEffectJournal(ownership, lease)

    def current_grant(current):
        permit = permit_for(
            current, expires_at=min(current.expires_at, lease.valid_until)
        )
        journal.authorize(current, permit, now, True)
        return permit

    adapter.authorize_mutation = current_grant
    executor = ApprovedPlanExecutor(
        EffectExecutor(journal, authorize=journal.authorize, clock=lambda: now),
        required_obligations=binding.required_obligations,
        execution_gate=binding.execution_gate,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    # Synthetic verification records test dispatch wiring, not data/HA qualification.
    evidence = tuple(
        EvidenceRecord(
            f"e-{index}",
            o.obligation_id,
            o.scope,
            plan.revisions,
            o.verifier_version,
            now - timedelta(microseconds=1),
            now + timedelta(minutes=1),
            VerificationResult.PASS,
            "test-evidence",
            "e" * 64,
        )
        for index, o in enumerate(plan.obligations)
        if o.due_gate <= Gate.PROTECTION
    )
    runner = StoredPlanExecutor(repo, executor)
    checked = runner.check_plan(
        "app", plan.plan_id, "cutover-approved", evidence=evidence
    )
    assert checked.gate.gate == Gate.PROTECTION
    assert "migration:final-data" in checked.gate.carry_forward
    assert "migration:post-cutover-write" in checked.gate.carry_forward
    result = runner.execute_step(
        "app",
        plan.plan_id,
        "cutover-approved",
        "pause-source",
        operation_id="cutover-operation",
        epoch=lease.epoch,
        evidence=evidence,
        adapter=adapter,
    )
    assert result.status == EffectStatus.APPLIED
    assert PostgresEffectJournal(ownership, lease).get(result.command) == result
    repo.revoke_approval(
        "app", "cutover-approved", expected_revision=1, actor_id="security"
    )
    with pytest.raises(ContractError, match="revoked"):
        runner.execute_step(
            "app",
            plan.plan_id,
            "cutover-approved",
            "pause-source",
            operation_id="cutover-operation",
            epoch=lease.epoch,
            evidence=evidence,
            adapter=adapter,
        )
