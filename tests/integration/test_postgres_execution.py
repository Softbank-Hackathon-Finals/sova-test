"""Real PG ownership/effect barriers. Provider/quiescence evidence is a fake."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
import json
import os
import subprocess
import sys

import psycopg
from psycopg import sql
import pytest

from support import IngressAdapter, permit_for
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.application.effects import EffectExecutor, UncertainEffect
from sova.application.execution_recovery import ExecutionRecovery
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import ContractError, EffectStatus
from sova.domain.execution import (
    ExecutionLease,
    ExecutionMode,
    QuiescenceProof,
    pending_digest,
)
from sova.domain.evidence import EvidenceRecord, VerificationResult
from sova.domain.operations import OperationRequest
from sova.domain.plans import PlanApproval
from sova.ports.execution import ExecutionBusy, RecoveryRequired
from sova.ports.operations import LeaseLost

pytestmark = pytest.mark.postgres


@pytest.fixture
def setup(postgres_bundle, now):
    lifecycle, plan, approval, _, _ = postgres_bundle
    lifecycle.save_plan(plan)
    lifecycle.save_approval("app", "plan", "approval", approval)
    operations = PostgresOperationRepository(lifecycle)
    request = OperationRequest(
        lifecycle.tenant_id,
        "app",
        "operation",
        "plan",
        plan.fingerprint,
        "approval",
        1,
        "operator",
        "request",
    )
    operations.submit(request)
    return lifecycle, plan, operations, PostgresExecutionOwnership(lifecycle)


def acquire(setup, owner="worker"):
    return setup[3].acquire("app", "operation", owner)


def executor(setup, lease, now):
    journal = PostgresEffectJournal(setup[3], lease)
    return EffectExecutor(journal, authorize=journal.authorize, clock=lambda: now)


def expire(setup):
    with setup[0].transaction() as conn:
        conn.execute(
            "UPDATE sova_control.app_execution SET valid_until=clock_timestamp()-interval '1 second'"
        )


def proof(setup, lease):
    with setup[0].transaction() as conn:
        at = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        pending = setup[3].pending(conn, "app")
    return QuiescenceProof(
        lease.tenant_id,
        "app",
        "operation",
        lease.epoch,
        pending_digest(pending),
        "e" * 64,
        at,
        at + timedelta(minutes=1),
    )


def recover(setup, lease):
    return ExecutionRecovery(setup[3], authenticate_proof=lambda _: None).acquire(
        proof(setup, lease), "recovery-worker"
    )


def test_app_has_only_one_active_owner(setup):
    with ThreadPoolExecutor(max_workers=2) as pool:

        def attempt(owner):
            try:
                return acquire(setup, owner)
            except ExecutionBusy:
                return None

        results = list(pool.map(attempt, ("one", "two")))
    assert sum(result is not None for result in results) == 1


def test_effect_claim_and_receipt_are_shared_by_new_connection(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    engine = executor(setup, lease, now)
    adapter = IngressAdapter()

    def before_apply(command):
        with setup[0].transaction() as conn:
            # External work must not run while holding the control DB row lock.
            conn.execute(
                "SELECT epoch FROM sova_control.app_execution FOR UPDATE NOWAIT"
            ).fetchone()
            assert conn.execute(
                "SELECT status FROM sova_control.effects"
            ).fetchone() == ("in_flight",)

    adapter.before_apply = before_apply
    result = engine.execute(cmd, permit_for(cmd), adapter)
    assert result.status == EffectStatus.APPLIED
    assert PostgresEffectJournal(setup[3], lease).get(cmd) == result
    engine.execute(cmd, permit_for(cmd), adapter)
    assert len(adapter.calls) == 1


def test_old_owner_cannot_mutate_after_clean_takeover(setup, now):
    first = acquire(setup)
    expire(setup)
    second = acquire(setup, "new-worker")
    assert second.epoch == first.epoch + 1
    old = setup[1].command("isolate", operation_id="operation", epoch=first.epoch)
    with pytest.raises(LeaseLost):
        executor(setup, first, now).execute(old, permit_for(old), IngressAdapter())


def test_expired_owner_cannot_renew_or_release(setup):
    lease = acquire(setup)
    expire(setup)
    with pytest.raises(LeaseLost):
        setup[3].renew(lease)
    with pytest.raises(LeaseLost):
        setup[3].release(lease)


def test_renew_keeps_epoch_and_token(setup):
    lease = acquire(setup)
    renewed = setup[3].renew(lease, lease_seconds=60)
    assert renewed.epoch == lease.epoch and renewed.token == lease.token
    assert renewed.valid_until > lease.valid_until


@pytest.mark.parametrize(
    "status", [EffectStatus.PREPARED, EffectStatus.IN_FLIGHT, EffectStatus.UNKNOWN]
)
def test_pending_effect_blocks_takeover_even_after_expiry(setup, now, status):
    lease = acquire(setup)
    command = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    journal = executor(setup, lease, now).journal
    record = journal.reserve(command)
    if status != EffectStatus.PREPARED:
        record = journal.transition(
            command, record.revision, record.status, EffectStatus.IN_FLIGHT
        )
    if status == EffectStatus.UNKNOWN:
        journal.transition(
            command, record.revision, record.status, EffectStatus.UNKNOWN
        )
    expire(setup)
    with pytest.raises(RecoveryRequired):
        acquire(setup, "replacement")


def test_live_owner_cannot_be_bypassed_by_recovery_proof(setup):
    lease = acquire(setup)
    with pytest.raises(ExecutionBusy):
        recover(setup, lease)


def test_unknown_result_needs_verified_readonly_recovery(setup, now):
    lease = acquire(setup)
    command = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    adapter = IngressAdapter()

    def lost(_):
        raise TimeoutError("provider changed resource but response lost")

    adapter.after_apply = lost
    engine = executor(setup, lease, now)
    with pytest.raises(UncertainEffect):
        engine.execute(command, permit_for(command), adapter)
    with pytest.raises(ContractError, match="recovery"):
        engine.reconcile(command, permit_for(command), adapter)
    assert len(adapter.calls) == 1
    expire(setup)
    recovery = recover(setup, lease)
    assert recovery.mode == ExecutionMode.RECONCILE
    readonly = executor(setup, recovery, now)
    with pytest.raises(ContractError):
        readonly.execute(command, permit_for(command), adapter)
    recovered = readonly.reconcile(command, permit_for(command), adapter)
    assert recovered.status == EffectStatus.APPLIED and len(adapter.calls) == 1
    setup[3].release(recovery)
    assert acquire(setup, "next-owner").epoch > recovery.epoch


def test_recovery_proof_is_bound_to_epoch_pending_set_and_expiry(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    executor(setup, lease, now).journal.reserve(cmd)
    expire(setup)
    bound = proof(setup, lease)
    for changed in [
        replace(bound, source_epoch=lease.epoch + 1),
        replace(bound, pending_effects_digest="a" * 64),
        replace(
            bound,
            observed_at=bound.observed_at - timedelta(minutes=2),
            valid_until=bound.observed_at - timedelta(minutes=1),
        ),
    ]:
        with pytest.raises(ContractError):
            ExecutionRecovery(setup[3], authenticate_proof=lambda _: None).acquire(
                changed, "recovery"
            )


def test_untrusted_recovery_proof_never_issues_grant(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    executor(setup, lease, now).journal.reserve(cmd)
    expire(setup)

    def reject(_):
        raise ContractError("untrusted proof")

    with pytest.raises(ContractError):
        ExecutionRecovery(setup[3], authenticate_proof=reject).acquire(
            proof(setup, lease), "recovery"
        )


def test_recovery_can_cancel_unissued_intent_but_not_issue_mutations(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    executor(setup, lease, now).journal.reserve(cmd)
    expire(setup)
    recovery = recover(setup, lease)
    engine = executor(setup, recovery, now)
    adapter = IngressAdapter()
    assert (
        engine.cancel_prepared(cmd, permit_for(cmd), adapter).status
        == EffectStatus.NOT_APPLIED
    )
    assert not adapter.calls
    setup[3].release(recovery)


def test_historical_applied_receipt_survives_new_epoch_without_replay(setup, now):
    lease = acquire(setup)
    command = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    adapter = IngressAdapter()
    old = executor(setup, lease, now).execute(command, permit_for(command), adapter)
    setup[3].release(lease)
    following = acquire(setup, "new-owner")
    current = setup[1].command(
        "isolate", operation_id="operation", epoch=following.epoch
    )
    result = executor(setup, following, now).execute(
        current, permit_for(current), adapter
    )
    assert result == old and result.command.fencing_epoch == lease.epoch
    assert len(adapter.calls) == 1
    with pytest.raises(ContractError):
        executor(setup, following, now).execute(
            replace(current, parameters_json='{"blocked":false}'),
            permit_for(replace(current, parameters_json='{"blocked":false}')),
            adapter,
        )


def test_expired_owner_cannot_complete_inflight_effect(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    journal = executor(setup, lease, now).journal
    record = journal.reserve(cmd)
    journal.transition(cmd, record.revision, record.status, EffectStatus.IN_FLIGHT)
    expire(setup)
    with pytest.raises(LeaseLost):
        journal.transition(cmd, 2, EffectStatus.IN_FLIGHT, EffectStatus.UNKNOWN)
    with pytest.raises(RecoveryRequired):
        acquire(setup, "replacement")


def test_audit_failure_rolls_back_effect_claim(setup, now, postgres_database):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    dsn, role = postgres_database
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("REVOKE INSERT ON sova_control.effect_events FROM {}").format(
                sql.Identifier(role)
            )
        )
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                executor(setup, lease, now).journal.reserve(cmd)
        finally:
            admin.execute(
                sql.SQL("GRANT INSERT ON sova_control.effect_events TO {}").format(
                    sql.Identifier(role)
                )
            )
    with setup[0].transaction() as conn:
        assert conn.execute("SELECT count(*) FROM sova_control.effects").fetchone() == (
            0,
        )


def test_other_app_command_is_rejected_before_effect(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    wrong = replace(cmd, scope=replace(cmd.scope, application_id="other"))
    adapter = IngressAdapter()
    with pytest.raises(ContractError):
        executor(setup, lease, now).execute(wrong, permit_for(wrong), adapter)
    assert not adapter.calls


def test_stored_plan_executes_with_pg_ownership_and_pg_effects(
    setup, postgres_bundle, now
):
    lifecycle, plan, _, ownership = setup
    obligation = postgres_bundle[4]
    lease = acquire(setup)
    engine = executor(setup, lease, now)
    proof = EvidenceRecord(
        "evidence",
        "owned",
        obligation.scope,
        plan.revisions,
        "v1",
        now,
        plan.valid_until,
        VerificationResult.PASS,
        "artifact",
        "e" * 64,
    )
    planning = ApprovedPlanExecutor(
        engine,
        required_obligations=lambda _: (obligation,),
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    result = StoredPlanExecutor(lifecycle, planning).execute_step(
        "app",
        "plan",
        "approval",
        "isolate",
        operation_id="operation",
        epoch=lease.epoch,
        evidence=(proof,),
        adapter=IngressAdapter(),
    )
    assert result.status == EffectStatus.APPLIED
    with lifecycle.transaction() as conn:
        assert conn.execute("SELECT status FROM sova_control.effects").fetchone() == (
            "confirmed_applied",
        )
        assert conn.execute(
            "SELECT count(*) FROM sova_control.effect_events"
        ).fetchone() == (3,)
    ownership.release(lease)


def test_real_worker_exit_blocks_takeover_until_verified_recovery(
    setup, postgres_database, now, tmp_path
):
    lifecycle, plan, _, ownership = setup
    dsn, role = postgres_database
    from psycopg.conninfo import make_conninfo

    marker = tmp_path / "effect.txt"
    script = """
import os,sys,json,psycopg
from datetime import datetime
sys.path.insert(0,sys.argv[1])
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.application.effects import EffectExecutor
config=json.loads(sys.stdin.read())
repo=PostgresLifecycleRepository(lambda:psycopg.connect(os.environ['SOVA_CHILD_DSN']),
 tenant_id=config['tenant'],clock=lambda:datetime.fromisoformat(config['now']))
owner=PostgresExecutionOwnership(repo);lease=owner.acquire('app','operation','child-worker')
plan=repo.get_plan('app','plan');command=plan.command('isolate',operation_id='operation',epoch=lease.epoch)
from sova.domain.contracts import ExecutionPermit
permit=ExecutionPermit(command.scope,command.operation_id,command.plan_digest,command.fingerprint,
 command.fencing_epoch,command.expires_at)
class Adapter:
 adapter_id='test-ingress'
 def validate(self,command):pass
 def apply(self,command):
  with open(config['marker'],'a') as stream:
   stream.write('once\\n');stream.flush();os.fsync(stream.fileno())
  os._exit(44)
 def readback(self,command,now):raise AssertionError('must exit first')
journal=PostgresEffectJournal(owner,lease)
EffectExecutor(journal,authorize=journal.authorize,clock=lambda:datetime.fromisoformat(config['now'])).execute(command,permit,Adapter())
"""
    config = {
        "tenant": lifecycle.tenant_id,
        "now": now.isoformat(),
        "marker": str(marker),
    }
    child = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(Path(__file__).resolve().parents[2] / "src"),
        ],
        input=json.dumps(config),
        env={**os.environ, "SOVA_CHILD_DSN": make_conninfo(dsn, user=role)},
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert child.returncode == 44, child.stderr
    assert marker.read_text() == "once\n"
    with lifecycle.transaction() as conn:
        row = conn.execute(
            "SELECT operation_id,owner_id,token,epoch,valid_until,mode FROM sova_control.app_execution"
        ).fetchone()
    original = ExecutionLease(
        lifecycle.tenant_id,
        "app",
        row[0],
        row[1],
        row[2],
        row[3],
        row[4],
        ExecutionMode(row[5]),
    )
    command = plan.command("isolate", operation_id="operation", epoch=original.epoch)
    expire(setup)
    with pytest.raises(RecoveryRequired):
        acquire(setup, "replacement")

    def verify_test_proof(_):
        assert child.returncode == 44 and marker.read_text() == "once\n"

    recovery = ExecutionRecovery(
        ownership, authenticate_proof=verify_test_proof
    ).acquire(proof(setup, original), "recovery")
    adapter = IngressAdapter()
    adapter.blocked = True
    assert (
        executor(setup, recovery, now)
        .reconcile(command, permit_for(command), adapter)
        .status
        == EffectStatus.APPLIED
    )
    assert adapter.calls == [] and marker.read_text() == "once\n"
    ownership.release(recovery)


def test_revocation_before_claim_stops_pg_effect(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    setup[0].revoke_approval(
        "app", "approval", expected_revision=1, actor_id="approver"
    )
    adapter = IngressAdapter()
    with pytest.raises(ContractError):
        executor(setup, lease, now).execute(cmd, permit_for(cmd), adapter)
    assert adapter.calls == []


def test_lost_owner_cannot_dispatch_between_claim_and_apply(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    journal = PostgresEffectJournal(setup[3], lease)
    checks = 0

    def guard(command, permit, at, mutation):
        nonlocal checks
        checks += 1
        if checks == 2:
            expire(setup)
        journal.authorize(command, permit, at, mutation)

    adapter = IngressAdapter()
    with pytest.raises(LeaseLost):
        EffectExecutor(journal, authorize=guard, clock=lambda: now).execute(
            cmd, permit_for(cmd), adapter
        )
    assert adapter.calls == []
    with pytest.raises(RecoveryRequired):
        acquire(setup, "replacement")


def test_recovery_lease_cannot_outlive_proof(setup, now):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    executor(setup, lease, now).journal.reserve(cmd)
    expire(setup)
    bound = proof(setup, lease)
    recovery = ExecutionRecovery(setup[3], authenticate_proof=lambda _: None).acquire(
        bound, "recovery", lease_seconds=300
    )
    assert recovery.valid_until <= bound.valid_until
    assert setup[3].renew(recovery, lease_seconds=300).valid_until <= bound.valid_until


@pytest.mark.parametrize("tamper", ["parameters", "key", "resource", "expiry"])
def test_plan_digest_alone_cannot_authorize_a_changed_command(setup, now, tamper):
    lease = acquire(setup)
    cmd = setup[1].command("isolate", operation_id="operation", epoch=lease.epoch)
    if tamper == "parameters":
        cmd = replace(cmd, parameters_json='{"blocked":false}')
    elif tamper == "key":
        cmd = replace(cmd, idempotency_key="another-key")
    elif tamper == "resource":
        cmd = replace(cmd, scope=replace(cmd.scope, resource_id="another-resource"))
    else:
        cmd = replace(cmd, expires_at=cmd.expires_at + timedelta(minutes=1))
    adapter = IngressAdapter()
    with pytest.raises(ContractError, match="stored approved plan"):
        executor(setup, lease, now).execute(cmd, permit_for(cmd), adapter)
    assert adapter.calls == []


def test_different_operation_in_same_app_cannot_bypass_owner(setup):
    lease = acquire(setup)
    operations = setup[2]
    request = replace(
        operations.get("app", "operation").request,
        operation_id="second",
        idempotency_key="second",
    )
    operations.submit(request)
    with pytest.raises(ExecutionBusy):
        setup[3].acquire("app", "second", "different-worker")
    setup[3].release(lease)
    following = setup[3].acquire("app", "second", "different-worker")
    assert following.operation_id == "second" and following.epoch > lease.epoch


def test_skewed_application_clock_cannot_extend_expired_approval(setup, now):
    lifecycle, plan, operations, ownership = setup
    lifecycle.clock = lambda: now - timedelta(seconds=30)
    expired = PlanApproval(
        plan.fingerprint, "approver", plan.purpose, now - timedelta(seconds=1)
    )
    lifecycle.save_approval("app", "plan", "expired", expired)
    request = replace(
        operations.get("app", "operation").request,
        operation_id="skewed-operation",
        idempotency_key="skewed-request",
        approval_id="expired",
    )
    operations.submit(request)
    lease = ownership.acquire("app", "skewed-operation", "skewed-worker")
    command = plan.command(
        "isolate", operation_id=lease.operation_id, epoch=lease.epoch
    )
    adapter = IngressAdapter()
    with pytest.raises(ContractError, match="expired"):
        executor(setup, lease, now - timedelta(seconds=30)).execute(
            command, permit_for(command), adapter
        )
    assert adapter.calls == []
