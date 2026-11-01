"""Opt-in owned AWS SQS + real PG effects. Never creates cloud resources.

The operator must provision two disposable queues, a private registration and
cleanup supervision. Verifier records are fixture evidence, not deployment
qualification; only immutable operation references go to AWS.
"""

from dataclasses import replace
from datetime import datetime
import json
import os
import time

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
import pytest

from test_postgres_migration_programs import saved as saved
from test_postgres_write_gate import gate as gate
from test_migration_phase_runner import writer_phase_profile, runner
from sova.adapters.kubernetes.https import private_text
from sova.adapters.sqs_operations import SQSQueueRegistration, SQSOperationTransport
from sova.application.operation_delivery import (
    MigrationOperationDelivery,
    SQSPhaseWorker,
)
from sova.application.outbox import OutboxRelay
from sova.domain.contracts import ContractError

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(
        not os.environ.get("SOVA_TEST_SQS_REGISTRATION"),
        reason="explicit owned AWS SQS registration required",
    ),
]


def test_real_sqs_outbox_to_worker_to_pg_completion_duplicate_and_dead_letter(
    saved, gate, now
):
    config = json.loads(private_text(os.environ["SOVA_TEST_SQS_REGISTRATION"]))
    config["issued_at"] = datetime.fromisoformat(config["issued_at"])
    config["valid_until"] = datetime.fromisoformat(config["valid_until"])
    config["allowed_tenants"] = tuple(config["allowed_tenants"])
    registration = SQSQueueRegistration(**config)
    session = boto3.Session(region_name=registration.region)
    assert (
        session.client("sts").get_caller_identity()["Account"]
        == registration.account_id
        == "265233844540"
    )
    client = session.client(
        "sqs",
        endpoint_url=registration.endpoint,
        config=Config(connect_timeout=5, read_timeout=10, retries={"max_attempts": 1}),
    )
    new_saved, services, factory = writer_phase_profile(saved, gate, now)
    programs, operations, _ = services
    registration = replace(registration, allowed_tenants=(programs.tenant_id,))
    transport = SQSOperationTransport(
        registration, client, authenticate_registration=lambda _: None
    )
    engine = runner(new_saved, services, now)
    handler = MigrationOperationDelivery(
        allowed_tenants=registration.allowed_tenants,
        repository_for_tenant=lambda _: operations,
        runner_for_tenant=lambda _: engine,
        evidence_for_operation=lambda _: new_saved[3],
        adapter_factory_for_operation=lambda _: factory,
    )
    consumer = SQSPhaseWorker(transport, handler)
    published = OutboxRelay(operations, transport).publish_one("app", "relay")
    assert published is not None
    first = consumer.poll_once(owner_id="worker", wait_seconds=2)
    assert first is not None and first.status == "phase_verified"
    assert (
        first.result["phase"] == "quiesce"
        and not first.result["full_migration_verified"]
    )
    _, proof = programs.get_phase_completion(operations, "app", "phase-op")
    event = operations.get_event("app", "phase-op")
    transport.publish(event)
    second = consumer.poll_once(owner_id="worker-duplicate", wait_seconds=2)
    assert (
        second is not None and second.result["completion_digest"] == proof.fingerprint
    )
    assert second.result["completion_recovered_read_only"]
    adapter = gate[0]
    command = new_saved[1].plan.command(
        "pause", operation_id="phase-op", epoch=proof.epoch
    )
    assert adapter.readback(command, now).evidence["confirmed"]
    # Even an authenticated publisher cannot manufacture an admitted event ID.
    poison = replace(event, event_id="unregistered-event")
    transport.publish(poison)
    deadline = time.monotonic() + 60
    rejected = 0
    while time.monotonic() < deadline and rejected < registration.max_receives:
        delivery = transport.receive_one(wait_seconds=2)
        if delivery is None:
            continue
        if delivery.event == event:
            assert (
                handler.handle(event, owner_id="duplicate").status == "phase_verified"
            )
            transport.acknowledge(delivery)
            continue
        assert delivery.event == poison
        with pytest.raises(ContractError, match="immutable"):
            handler.handle(delivery.event, owner_id="rejected")
        rejected += 1
        transport.defer(delivery, seconds=1)
        time.sleep(1.1)
    assert rejected == registration.max_receives
    dead_message = None
    while time.monotonic() < deadline and dead_message is None:
        # A further source receive drives SQS's redrive threshold observation.
        stray = transport.receive_one(wait_seconds=1)
        if stray is not None:
            assert stray.event in (event, poison)
            if stray.event == event:
                transport.acknowledge(stray)
            else:
                transport.defer(stray, seconds=1)
        result = client.receive_message(
            QueueUrl=registration.dead_letter_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=2,
            VisibilityTimeout=5,
        )
        messages = result.get("Messages", [])
        if messages:
            dead_message = messages[0]
    assert dead_message is not None
    assert json.loads(dead_message["Body"])["event_id"] == poison.event_id
    client.delete_message(
        QueueUrl=registration.dead_letter_url,
        ReceiptHandle=dead_message["ReceiptHandle"],
    )
    anonymous = boto3.client(
        "sqs",
        region_name=registration.region,
        endpoint_url=registration.endpoint,
        config=Config(
            signature_version=UNSIGNED,
            connect_timeout=5,
            read_timeout=5,
            retries={"max_attempts": 0},
        ),
    )
    with pytest.raises(ClientError):
        anonymous.send_message(
            QueueUrl=registration.queue_url,
            MessageBody="controlled anonymous access probe",
        )
    assert programs.get_phase_completion(operations, "app", "phase-op")[1] == proof
