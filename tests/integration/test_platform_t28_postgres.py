"""Actual T28/PG lease boundary; the only external effect is a local test file."""

from dataclasses import replace
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import psycopg
from psycopg.conninfo import make_conninfo
import pytest

from sova.adapters.platform_t28 import DurableT28Port, OperatorBinding, load_driver
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.application.effects import EffectExecutor
from sova.application.execution_recovery import ExecutionRecovery
from sova.domain.contracts import EffectObservation, EffectStatus, canonical_json
from sova.domain.execution import QuiescenceProof, pending_digest
from sova.domain.operations import OperationRequest
from sova.domain.plans import PlanApproval, PlanStep
from sova.ports.execution import RecoveryRequired
from support import permit_for

pytestmark = pytest.mark.postgres


def composition(root, work, repository, lease, now, *, crash=False):
    driver = load_driver(root)
    driver.STEPS = (driver.Step("s4-fault-inject", "S4", "operator", "T28", "synthetic effect", ("synthetic-effect",)),)
    command = repository.get_plan("app", "plan").command("s4-fault-inject", operation_id="operation", epoch=lease.epoch)
    marker = Path(work) / "effect.txt"

    class Adapter:
        adapter_id = "synthetic-t28"

        def validate(self, command):
            assert command.parameters["argv"] == ["synthetic-effect"]

        def apply(self, command):
            with marker.open("a") as stream:
                stream.write("once\n")
                stream.flush()
                os.fsync(stream.fileno())
            if crash:
                os._exit(44)

        def readback(self, command, now):
            return EffectObservation(command.scope, command.fingerprint,
                EffectStatus.APPLIED if marker.read_text() == "once\n" else EffectStatus.UNKNOWN,
                now, canonical_json({"synthetic_readback": True}))

    journal = PostgresEffectJournal(PostgresExecutionOwnership(repository), lease)
    engine = EffectExecutor(journal, authorize=journal.authorize, clock=lambda: now)
    binding = OperatorBinding(command, permit_for(command), Adapter())
    port = DurableT28Port(root, "plan", "test-application", (binding,), engine)
    args = SimpleNamespace(record=str(Path(work) / "run.jsonl"), plan_id="plan", profile="mock",
        application_id="test-application", kubeconfig=None, fault_record="unused", receipts=None,
        wait=0, interval=1, step_timeout=30, plan_state_command=None)
    return driver, args, port, binding


@pytest.fixture
def registered(postgres_bundle, now):
    root = os.environ.get("SOVA_T28_PLATFORM_SOURCE")
    if not root:
        pytest.skip("Explicit qualified T28 platform source required")
    repo, original, _, _, _ = postgres_bundle
    parameters = canonical_json({"argv": ["synthetic-effect"], "platform_commit": load_driver(root).__sova_platform_commit__,
        "plan_id": "plan", "application_id": "test-application", "diff_digest": "b" * 64, "profile": "mock",
        "image_digest": "sha256:" + "c" * 64})
    step = PlanStep("s4-fault-inject", original.steps[0].scope, "synthetic-t28", "t28_operator", parameters, "revision-1")
    plan = replace(original, steps=(step,))
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", PlanApproval(plan.fingerprint, "approver", plan.purpose, plan.valid_until))
    PostgresOperationRepository(repo).submit(OperationRequest(repo.tenant_id, "app", "operation", "plan",
        plan.fingerprint, "approval", 1, "operator", "request"))
    return root, repo, plan, PostgresExecutionOwnership(repo)


def child():
    config = json.loads(sys.stdin.read())
    now = datetime.fromisoformat(config["now"])
    repo = PostgresLifecycleRepository(lambda: psycopg.connect(os.environ["SOVA_CHILD_DSN"]),
        tenant_id=config["tenant"], clock=lambda: now)
    lease = PostgresExecutionOwnership(repo).acquire("app", "operation", "child-worker")
    driver, args, port, _ = composition(config["root"], config["work"], repo, lease, now, crash=True)
    raise SystemExit(port.run(driver, args))


def test_t28_process_death_requires_pg_recovery_and_never_replays(registered, postgres_database, tmp_path, now):
    root, repo, plan, ownership = registered
    config = dict(root=root, work=str(tmp_path), tenant=repo.tenant_id, now=now.isoformat())
    code = "import sys; sys.path.insert(0,sys.argv[1]); sys.path.insert(0,sys.argv[2]); from test_platform_t28_postgres import child; child()"
    result = subprocess.run([sys.executable, "-c", code, str(Path(__file__).parent), str(Path(__file__).parents[1])],
        input=json.dumps(config), text=True, capture_output=True, timeout=15,
        env=os.environ | {"SOVA_CHILD_DSN": make_conninfo(postgres_database[0], user=postgres_database[1])})
    assert result.returncode == 44, result.stderr
    assert len((tmp_path / "run.jsonl").read_text().splitlines()) == 1
    with repo.transaction() as conn:
        epoch = conn.execute("SELECT epoch FROM sova_control.app_execution").fetchone()[0]
        conn.execute("UPDATE sova_control.app_execution SET valid_until=clock_timestamp()-interval '1 second'")
    with pytest.raises(RecoveryRequired):
        ownership.acquire("app", "operation", "replacement")
    with repo.transaction() as conn:
        at = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        pending = ownership.pending(conn, "app")
    command = plan.command("s4-fault-inject", operation_id="operation", epoch=epoch)
    proof = QuiescenceProof(repo.tenant_id, "app", "operation", epoch, pending_digest(pending),
        "e" * 64, at, at + timedelta(minutes=1))

    def confirm_local_child_quiescence(_):
        assert result.returncode == 44 and (tmp_path / "effect.txt").read_text() == "once\n"

    recovery = ExecutionRecovery(ownership, authenticate_proof=confirm_local_child_quiescence).acquire(proof, "reconciler")
    driver, args, port, binding = composition(root, tmp_path, repo, recovery, now)
    # Recovery permits readback of the original epoch, never another mutation.
    assert port.run(driver, args) == 3
    recovered = port.executor.reconcile(command, permit_for(command), binding.adapter)
    assert recovered.status == EffectStatus.APPLIED
    assert (tmp_path / "effect.txt").read_text() == "once\n"
    ownership.release(recovery)


def test_t28_current_pg_approval_revocation_denies_effect(registered, tmp_path, now):
    root, repo, _, ownership = registered
    lease = ownership.acquire("app", "operation", "worker")
    driver, args, port, _ = composition(root, tmp_path, repo, lease, now)
    repo.revoke_approval("app", "approval", expected_revision=1, actor_id="approver")
    assert port.run(driver, args) == 3
    assert not (tmp_path / "effect.txt").exists()
