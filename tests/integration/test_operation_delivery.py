"""Actual PG authority plus a transport double; live SQS is separately opt-in."""

from dataclasses import replace
import json
from types import SimpleNamespace

import pytest

from test_postgres_migration_programs import saved as saved
from test_migration_phase_runner import setup, runner
from sova.application.operation_delivery import (
    MigrationOperationDelivery,
    SQSPhaseWorker,
)
from sova.domain.contracts import ContractError, canonical_json
from sova.domain.workflows import OperationStatus
from sova.ports.plans import RecordNotFound

pytestmark = pytest.mark.postgres


class Transport:
    def __init__(self, event, tenant):
        self.registration = SimpleNamespace(allowed_tenants=(tenant,))
        self.delivery = SimpleNamespace(event=event)
        self.acked = []
        self.deferred = []

    def receive_one(self, **_):
        return self.delivery

    def acknowledge(self, delivery):
        self.acked.append(delivery)

    def defer(self, delivery):
        self.deferred.append(delivery)


def worker(saved, services, now, adapter, **changes):
    programs, operations, _ = services
    engine = runner(saved, services, now)
    args = dict(
        allowed_tenants=(programs.tenant_id,),
        repository_for_tenant=lambda _: operations,
        runner_for_tenant=lambda _: engine,
        evidence_for_operation=lambda _: saved[3],
        adapter_factory_for_operation=lambda _: lambda *_: adapter,
    )
    args.update(changes)
    handler = MigrationOperationDelivery(**args)
    transport = Transport(operations.get_event("app", "phase-op"), programs.tenant_id)
    return SQSPhaseWorker(transport, handler), engine


def test_delivery_rechecks_pg_then_acknowledges_durable_phase_completion(
    saved, now, adapter
):
    services = setup(saved)
    consumer, _ = worker(saved, services, now, adapter)
    outcome = consumer.poll_once(owner_id="worker", wait_seconds=0)
    assert outcome.acknowledge and outcome.status == "phase_verified"
    assert (
        outcome.result["receipt_only"] and not outcome.result["full_migration_verified"]
    )
    assert len(consumer.transport.acked) == 1 and not consumer.transport.deferred


@pytest.mark.parametrize("change", ["event-id", "plan", "approval-revision"])
def test_mutated_message_cannot_dispatch_an_admitted_operation(
    saved, now, adapter, change
):
    services = setup(saved)
    consumer, _ = worker(saved, services, now, adapter)
    event = consumer.transport.delivery.event
    if change == "event-id":
        event = replace(event, event_id="forged")
    else:
        payload = json.loads(event.payload_json)
        if change == "plan":
            payload["plan_digest"] = "f" * 64
        else:
            payload["approval_revision"] += 1
        event = replace(event, payload_json=canonical_json(payload))
    consumer.transport.delivery.event = event
    with pytest.raises(ContractError, match="immutable"):
        consumer.poll_once(owner_id="worker")
    assert not consumer.transport.acked and not adapter.calls
    assert services[1].get("app", "phase-op").state.status == OperationStatus.REGISTERED


def test_unregistered_tenant_cannot_select_repository_credentials(saved, now, adapter):
    services = setup(saved)
    calls = []
    consumer, _ = worker(
        saved,
        services,
        now,
        adapter,
        repository_for_tenant=lambda tenant: calls.append(tenant),
    )
    event = consumer.transport.delivery.event
    payload = json.loads(event.payload_json)
    payload["tenant_id"] = "other-tenant"
    consumer.transport.delivery.event = replace(
        event, payload_json=canonical_json(payload)
    )
    with pytest.raises(ContractError, match="tenant"):
        consumer.poll_once(owner_id="worker")
    assert calls == [] and consumer.transport.acked == []


def test_duplicate_completed_delivery_does_not_resolve_credentials_or_evidence_again(
    saved, now, adapter
):
    services = setup(saved)
    calls = []

    def evidence(_):
        calls.append("evidence")
        return saved[3]

    def factory(_):
        calls.append("adapter")
        return lambda *_: adapter

    consumer, _ = worker(
        saved,
        services,
        now,
        adapter,
        evidence_for_operation=evidence,
        adapter_factory_for_operation=factory,
    )
    first = consumer.poll_once(owner_id="one")
    second = consumer.poll_once(owner_id="two")
    assert first.result["completion_digest"] == second.result["completion_digest"]
    assert second.result["completion_recovered_read_only"]
    assert calls == ["evidence", "adapter"] and len(adapter.calls) == 1
    assert len(consumer.transport.acked) == 2


def test_known_recovery_state_defers_delivery_without_reapplying_effect(
    saved, now, adapter
):
    services = setup(saved)

    def lost(_):
        raise ConnectionError("controlled provider reply loss")

    adapter.after_apply = lost
    consumer, _ = worker(saved, services, now, adapter)
    with pytest.raises(RuntimeError):
        consumer.poll_once(owner_id="one")
    outcome = consumer.poll_once(owner_id="two")
    assert not outcome.acknowledge and outcome.status == "recovery_required"
    assert not consumer.transport.acked and len(consumer.transport.deferred) == 1
    assert len(adapter.calls) == 1


def test_cancelled_operation_is_acknowledged_as_cancelled_without_execution(
    saved, now, adapter
):
    services = setup(saved)
    services[1].advance(
        "app",
        "phase-op",
        OperationStatus.CANCELLED,
        expected_revision=1,
        actor_id="operator",
    )
    consumer, _ = worker(saved, services, now, adapter)
    outcome = consumer.poll_once(owner_id="worker")
    assert (
        outcome.status == "cancelled" and outcome.acknowledge and outcome.result is None
    )
    assert not adapter.calls


def test_runner_success_json_without_database_receipt_cannot_acknowledge_delivery(
    saved, now, adapter, monkeypatch
):
    services = setup(saved)
    consumer, engine = worker(saved, services, now, adapter)
    monkeypatch.setattr(
        engine,
        "run",
        lambda *_, **kw: {
            "status": "phase_verified",
            "operation_id": "phase-op",
            "completion_digest": "f" * 64,
        },
    )
    with pytest.raises(RecordNotFound):
        consumer.poll_once(owner_id="worker")
    assert not consumer.transport.acked and not adapter.calls
