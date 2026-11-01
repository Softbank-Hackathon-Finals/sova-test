"""Real PG atomic admission, event history and outbox lease failure tests."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from dataclasses import asdict
from pathlib import Path
import json
import os
import subprocess
import sys

import psycopg
from psycopg import sql
import pytest

from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.application.outbox import OutboxRelay
from sova.domain.contracts import ContractError
from sova.domain.operations import OperationRequest, PublishReceipt
from sova.domain.workflows import OperationStatus as S
from sova.ports.operations import LeaseLost
from sova.ports.plans import RecordNotFound, RepositoryConflict

pytestmark = pytest.mark.postgres


@pytest.fixture
def setup(postgres_bundle):
    lifecycle, plan, approval, _, _ = postgres_bundle
    lifecycle.save_plan(plan)
    lifecycle.save_approval("app", "plan", "approval", approval)
    repository = PostgresOperationRepository(lifecycle)
    request = OperationRequest(
        lifecycle.tenant_id,
        "app",
        "operation",
        "plan",
        plan.fingerprint,
        "approval",
        1,
        "operator",
        "request-key",
    )
    return repository, request


def count(repo, table):
    with repo.lifecycle.transaction() as conn:
        return conn.execute(
            sql.SQL("SELECT count(*) FROM sova_control.{}").format(
                sql.Identifier(table)
            )
        ).fetchone()[0]


class Publisher:
    publisher_id = "test-broker"

    def __init__(self):
        self.events = []
        self.fail = False

    def publish(self, event):
        assert not hasattr(event, "lease_token") and not hasattr(event, "owner_id")
        self.events.append(event)
        if self.fail:
            raise TimeoutError("broker outcome unknown")
        return PublishReceipt(
            event.event_id, self.publisher_id, "message-" + str(len(self.events))
        )


def expire(repo, event_id):
    with repo.lifecycle.transaction() as conn:
        conn.execute(
            "UPDATE sova_control.operation_outbox SET lease_until=clock_timestamp()-interval '1 second' WHERE event_id=%s",
            (event_id,),
        )


def test_operation_and_outbox_survive_new_repository(setup):
    repo, request = setup
    saved = repo.submit(request)
    assert saved.state.status == S.REGISTERED
    assert (
        count(repo, "operations")
        == count(repo, "operation_events")
        == count(repo, "operation_outbox")
        == 1
    )
    restarted = PostgresOperationRepository(repo.lifecycle)
    assert restarted.get("app", "operation") == saved
    assert restarted.claim("app", "worker") is not None


def test_duplicate_request_returns_original_id_and_single_event(setup):
    repo, request = setup
    one = repo.submit(request)
    two = repo.submit(replace(request, operation_id="fresh-generated-id"))
    assert one == two
    assert count(repo, "operation_events") == count(repo, "operation_outbox") == 1
    with pytest.raises(RepositoryConflict):
        repo.submit(replace(request, requested_by="other-actor"))


def test_atomic_rollback_if_event_record_fails(setup, postgres_database):
    repo, request = setup
    dsn, role = postgres_database
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("REVOKE INSERT ON sova_control.operation_events FROM {}").format(
                sql.Identifier(role)
            )
        )
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                repo.submit(request)
        finally:
            admin.execute(
                sql.SQL("GRANT INSERT ON sova_control.operation_events TO {}").format(
                    sql.Identifier(role)
                )
            )
    assert count(repo, "operations") == count(repo, "operation_outbox") == 0
    assert repo.claim("app", "worker") is None


def test_invalid_or_revoked_approval_never_admits_work(setup):
    repo, request = setup
    with pytest.raises(ContractError):
        repo.submit(replace(request, approval_revision=2))
    repo.lifecycle.revoke_approval(
        "app", "approval", expected_revision=1, actor_id="approver"
    )
    with pytest.raises(ContractError):
        repo.submit(request)
    assert count(repo, "operations") == 0


def test_concurrent_duplicate_admission_has_single_operation(setup):
    repo, request = setup
    with ThreadPoolExecutor(max_workers=2) as pool:
        receipts = list(
            pool.map(repo.submit, (request, replace(request, operation_id="other-id")))
        )
    assert receipts[0] == receipts[1]
    assert count(repo, "operation_outbox") == 1


def test_concurrent_workers_cannot_claim_same_event(setup):
    repo, request = setup
    repo.submit(request)
    with ThreadPoolExecutor(max_workers=2) as pool:
        deliveries = list(
            pool.map(lambda owner: repo.claim("app", owner), ("worker-a", "worker-b"))
        )
    assert sum(d is not None for d in deliveries) == 1


def test_expired_claim_is_recovered_with_same_event_and_new_token(setup):
    repo, request = setup
    repo.submit(request)
    first = repo.claim("app", "old-worker")
    expire(repo, first.event_id)
    second = repo.claim("app", "new-worker")
    assert first.event_id == second.event_id and first.lease_token != second.lease_token
    assert second.attempt == first.attempt + 1
    with pytest.raises(LeaseLost):
        repo.acknowledge(first, PublishReceipt(first.event_id, "broker", "old-message"))
    repo.acknowledge(second, PublishReceipt(second.event_id, "broker", "new-message"))
    assert repo.claim("app", "third-worker") is None


def test_publish_outcome_unknown_retries_stable_event_not_operation(setup):
    repo, request = setup
    repo.submit(request)
    publisher = Publisher()
    publisher.fail = True
    relay = OutboxRelay(repo, publisher)
    with pytest.raises(TimeoutError):
        relay.publish_one("app", "worker")
    assert relay.publish_one("app", "other-worker") is None
    event = publisher.events[0]
    expire(repo, event.event_id)
    publisher.fail = False
    relay.publish_one("app", "retry-worker")
    assert (
        len(publisher.events) == 2
        and publisher.events[0].event_id == publisher.events[1].event_id
    )
    assert repo.get("app", "operation").state.status == S.REGISTERED
    assert (
        count(repo, "operation_events") == 1
    )  # Publication does not complete execution.


def test_wrong_broker_receipt_never_marks_delivery_published(setup):
    repo, request = setup
    repo.submit(request)
    publisher = Publisher()
    publisher.publish = lambda event: PublishReceipt(
        "wrong-event", "test-broker", "message"
    )
    with pytest.raises(ContractError):
        OutboxRelay(repo, publisher).publish_one("app", "worker")
    with repo.lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT published_at FROM sova_control.operation_outbox"
        ).fetchone() == (None,)


def test_cancel_suppresses_unpublished_notification(setup):
    repo, request = setup
    repo.submit(request)
    cancelled = repo.advance(
        "app", "operation", S.CANCELLED, expected_revision=1, actor_id="operator"
    )
    assert cancelled.state.revision == 2 and repo.claim("app", "worker") is None
    assert count(repo, "operation_events") == 2


def test_cancel_after_claim_rejects_late_ack(setup):
    repo, request = setup
    repo.submit(request)
    delivery = repo.claim("app", "worker")
    repo.advance(
        "app", "operation", S.CANCELLED, expected_revision=1, actor_id="operator"
    )
    with pytest.raises(LeaseLost):
        repo.acknowledge(delivery, PublishReceipt(delivery.event_id, "broker", "late"))


def test_revision_and_state_machine_survive_restart(setup):
    repo, request = setup
    repo.submit(request)
    changed = repo.advance(
        "app", "operation", S.ASSESSING, expected_revision=1, actor_id="worker"
    )
    with pytest.raises(RepositoryConflict):
        repo.advance(
            "app", "operation", S.REHEARSING, expected_revision=1, actor_id="old-worker"
        )
    with pytest.raises(ContractError):
        repo.advance(
            "app", "operation", S.SWITCHING, expected_revision=2, actor_id="worker"
        )
    assert (
        PostgresOperationRepository(repo.lifecycle).get("app", "operation") == changed
    )


def test_tenant_and_application_isolation_on_operations_and_claims(setup, now):
    repo, request = setup
    repo.submit(request)
    other = PostgresOperationRepository(
        PostgresLifecycleRepository(
            repo.lifecycle.connect, tenant_id="other", clock=lambda: now
        )
    )
    with pytest.raises(RecordNotFound):
        other.get("app", "operation")
    with pytest.raises(RecordNotFound):
        repo.get("other-app", "operation")
    assert other.claim("app", "worker") is None
    with pytest.raises(ContractError):
        other.submit(request)


@pytest.mark.parametrize("seconds", [0, 301, True])
def test_unbounded_or_boolean_lease_is_rejected(setup, seconds):
    repo, _ = setup
    with pytest.raises(ContractError):
        repo.claim("app", "worker", lease_seconds=seconds)


def test_api_process_exit_after_commit_leaves_dispatchable_outbox(
    setup, postgres_database, now
):
    repo, request = setup
    dsn, role = postgres_database
    from psycopg.conninfo import make_conninfo

    script = """
import os,sys,json,psycopg
from datetime import datetime
sys.path.insert(0,sys.argv[1])
from sova.domain.operations import OperationRequest
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.postgres_operations import PostgresOperationRepository
request=OperationRequest(**json.loads(sys.argv[2]))
repo=PostgresOperationRepository(PostgresLifecycleRepository(
 lambda:psycopg.connect(os.environ['SOVA_CHILD_DSN']),tenant_id=request.tenant_id,
 clock=lambda:datetime.fromisoformat(sys.argv[3])))
repo.submit(request)
os._exit(43)
"""
    child = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(Path(__file__).resolve().parents[2] / "src"),
            json.dumps(asdict(request)),
            now.isoformat(),
        ],
        env={**os.environ, "SOVA_CHILD_DSN": make_conninfo(dsn, user=role)},
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert child.returncode == 43, child.stderr
    assert repo.get("app", "operation").request == request
    assert repo.claim("app", "surviving-worker") is not None
    assert count(repo, "operation_events") == count(repo, "operation_outbox") == 1


def test_cancelled_request_retry_is_receipt_not_new_work(setup):
    repo, request = setup
    repo.submit(request)
    repo.advance(
        "app", "operation", S.CANCELLED, expected_revision=1, actor_id="operator"
    )
    result = repo.submit(replace(request, operation_id="fresh-id"))
    assert result.state.status == S.CANCELLED and repo.claim("app", "worker") is None
    assert count(repo, "operation_outbox") == 1


def test_outbox_payload_corruption_does_not_reach_publisher(setup, postgres_database):
    repo, request = setup
    repo.submit(request)
    with psycopg.connect(postgres_database[0]) as admin:
        admin.execute(
            "UPDATE sova_control.operation_outbox SET payload='{}' WHERE tenant_id=%s",
            (repo.tenant_id,),
        )
    publisher = Publisher()
    with pytest.raises(ContractError, match="payload"):
        OutboxRelay(repo, publisher).publish_one("app", "worker")
    assert publisher.events == []


def test_post_fence_failure_retains_recovery_requirement(setup):
    repo, request = setup
    repo.submit(request)
    phases = [
        S.ASSESSING,
        S.REHEARSING,
        S.AWAITING_APPROVAL,
        S.PREPARING,
        S.SYNCING,
        S.CUTOVER_READY,
        S.FENCING,
    ]
    revision = 1
    for phase in phases:
        result = repo.advance(
            "app", "operation", phase, expected_revision=revision, actor_id="worker"
        )
        revision = result.state.revision
    with pytest.raises(ContractError):
        repo.advance(
            "app", "operation", S.FAILED, expected_revision=revision, actor_id="worker"
        )
    result = repo.advance(
        "app",
        "operation",
        S.RECOVERY_REQUIRED,
        expected_revision=revision,
        actor_id="worker",
    )
    assert result.state.status == S.RECOVERY_REQUIRED
