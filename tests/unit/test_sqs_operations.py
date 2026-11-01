"""AWS SDK contract/negative tests; no network and no actual queue claims."""

from dataclasses import replace
from datetime import timedelta
import hashlib
import json

import boto3
from botocore.stub import Stubber
import pytest

from sova.adapters.sqs_operations import (
    SQSDelivery,
    SQSOperationTransport,
    SQSQueueRegistration,
)
from sova.domain.contracts import ContractError, canonical_json
from sova.domain.operations import OutboxEvent


@pytest.fixture
def registration(now):
    return SQSQueueRegistration(
        "111111111111",
        "ap-northeast-2",
        "sova-operations",
        "sova-operations-dead",
        "arn:aws:iam::111111111111:role/publisher",
        "arn:aws:iam::111111111111:role/consumer",
        ("tenant-a",),
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )


@pytest.fixture
def event():
    return OutboxEvent(
        "event-a",
        "operation.requested.v1",
        canonical_json(
            {
                "tenant_id": "tenant-a",
                "application_id": "app",
                "operation_id": "op",
                "plan_id": "plan",
                "plan_digest": "a" * 64,
                "approval_id": "approved",
                "approval_revision": 1,
            }
        ),
    )


@pytest.fixture
def client(registration):
    return boto3.client(
        "sqs",
        region_name=registration.region,
        endpoint_url=registration.endpoint,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )


def attributes(stub, r, source_changes=None, dead_changes=None):
    source = {
        "QueueArn": r.queue_arn,
        "Policy": json.dumps(r.policy),
        "SqsManagedSseEnabled": "true",
        "RedrivePolicy": json.dumps(
            {
                "deadLetterTargetArn": r.dead_letter_arn,
                "maxReceiveCount": str(r.max_receives),
            }
        ),
        "VisibilityTimeout": str(r.visibility_seconds),
        "MessageRetentionPeriod": "3600",
    }
    dead = {
        "QueueArn": r.dead_letter_arn,
        "RedriveAllowPolicy": json.dumps(
            {"redrivePermission": "byQueue", "sourceQueueArns": [r.queue_arn]}
        ),
        "SqsManagedSseEnabled": "true",
        "MessageRetentionPeriod": "86400",
    }
    source.update(source_changes or {})
    dead.update(dead_changes or {})
    stub.add_response(
        "get_queue_attributes",
        {"Attributes": source},
        {
            "QueueUrl": r.queue_url,
            "AttributeNames": [
                "QueueArn",
                "Policy",
                "SqsManagedSseEnabled",
                "KmsMasterKeyId",
                "RedrivePolicy",
                "VisibilityTimeout",
                "MessageRetentionPeriod",
            ],
        },
    )
    stub.add_response(
        "get_queue_attributes",
        {"Attributes": dead},
        {
            "QueueUrl": r.dead_letter_url,
            "AttributeNames": [
                "QueueArn",
                "RedriveAllowPolicy",
                "SqsManagedSseEnabled",
                "KmsMasterKeyId",
                "MessageRetentionPeriod",
            ],
        },
    )


def body(event):
    return canonical_json(
        {
            "event_id": event.event_id,
            "topic": event.topic,
            "payload_json": event.payload_json,
        },
        limit=16384,
    )


def received(stub, r, event, raw=None, checksum=None, count="1"):
    raw = body(event) if raw is None else raw
    stub.add_response(
        "receive_message",
        {
            "Messages": [
                {
                    "MessageId": "message-a",
                    "ReceiptHandle": "opaque-receipt-handle",
                    "Body": raw,
                    "MD5OfBody": checksum
                    or hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest(),
                    "Attributes": {"ApproximateReceiveCount": count},
                }
            ]
        },
        {
            "QueueUrl": r.queue_url,
            "MaxNumberOfMessages": 1,
            "WaitTimeSeconds": 20,
            "VisibilityTimeout": r.visibility_seconds,
            "MessageSystemAttributeNames": ["ApproximateReceiveCount"],
        },
    )


def transport(r, client, now):
    return SQSOperationTransport(
        r, client, authenticate_registration=lambda _: None, clock=lambda: now
    )


def test_publish_binds_exact_queue_policy_reference_and_checksum(
    registration, event, client, now
):
    r = registration
    with Stubber(client) as stub:
        attributes(stub, r)
        raw = body(event)
        stub.add_response(
            "send_message",
            {
                "MessageId": "message-a",
                "MD5OfMessageBody": hashlib.md5(
                    raw.encode(), usedforsecurity=False
                ).hexdigest(),
            },
            {"QueueUrl": r.queue_url, "MessageBody": raw},
        )
        receipt = transport(r, client, now).publish(event)
        assert (
            receipt.event_id == event.event_id and receipt.publisher_id == r.queue_arn
        )
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "key,value",
    [
        ("lease_token", "not-allowed"),
        ("source", "code"),
        ("OPENAI_API_KEY", "forbidden"),
    ],
)
def test_private_or_executable_fields_never_enter_queue(
    registration, event, client, now, key, value
):
    payload = json.loads(event.payload_json)
    payload[key] = value
    with Stubber(client) as stub:
        with pytest.raises(ContractError, match="references"):
            transport(registration, client, now).publish(
                replace(event, payload_json=canonical_json(payload))
            )
        stub.assert_no_pending_responses()


def test_cross_tenant_event_is_rejected_before_any_aws_request(
    registration, event, client, now
):
    payload = json.loads(event.payload_json)
    payload["tenant_id"] = "another-tenant"
    with Stubber(client) as stub:
        with pytest.raises(ContractError, match="tenant"):
            transport(registration, client, now).publish(
                replace(event, payload_json=canonical_json(payload))
            )
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "side,key,value",
    [
        ("source", "QueueArn", "arn:aws:sqs:ap-northeast-2:222222222222:other"),
        ("source", "Policy", "{}"),
        ("source", "SqsManagedSseEnabled", "false"),
        ("source", "KmsMasterKeyId", "unexpected"),
        ("source", "RedrivePolicy", "{}"),
        ("source", "VisibilityTimeout", "0"),
        ("source", "MessageRetentionPeriod", "30"),
        ("dead", "RedriveAllowPolicy", '{"redrivePermission":"allowAll"}'),
        ("dead", "MessageRetentionPeriod", "3600"),
    ],
)
def test_policy_identity_encryption_or_redrive_drift_blocks_publish(
    registration, event, client, now, side, key, value
):
    with Stubber(client) as stub:
        attributes(
            stub,
            registration,
            source_changes={key: value} if side == "source" else None,
            dead_changes={key: value} if side == "dead" else None,
        )
        with pytest.raises(ContractError):
            transport(registration, client, now).publish(event)
        stub.assert_no_pending_responses()


def test_send_checksum_mismatch_does_not_ack_outbox(registration, event, client, now):
    with Stubber(client) as stub:
        attributes(stub, registration)
        stub.add_response(
            "send_message", {"MessageId": "message-a", "MD5OfMessageBody": "bad"}
        )
        with pytest.raises(ContractError, match="checksum"):
            transport(registration, client, now).publish(event)


def test_received_reference_has_private_queue_bound_receipt(
    registration, event, client, now
):
    with Stubber(client) as stub:
        attributes(stub, registration)
        received(stub, registration, event)
        delivery = transport(registration, client, now).receive_one()
        assert delivery.event == event and delivery.queue_arn == registration.queue_arn
        assert delivery.receive_count == 1 and "opaque-receipt-handle" not in repr(
            delivery
        )


@pytest.mark.parametrize(
    "change", ["unknown-field", "duplicate-key", "checksum", "count", "oversize"]
)
def test_received_invalid_envelope_never_becomes_executable_reference(
    registration, event, client, now, change
):
    raw = body(event)
    if change == "unknown-field":
        raw = json.dumps(
            {
                "event_id": event.event_id,
                "topic": event.topic,
                "payload_json": event.payload_json,
                "command": "not allowed",
            }
        )
    if change == "duplicate-key":
        raw = '{"event_id":"a","event_id":"b","topic":"operation.requested.v1","payload_json":"{}"}'
    if change == "oversize":
        raw = "x" * 16385
    with Stubber(client) as stub:
        attributes(stub, registration)
        received(
            stub,
            registration,
            event,
            raw=raw,
            checksum="bad" if change == "checksum" else None,
            count="0" if change == "count" else "1",
        )
        with pytest.raises(ContractError):
            transport(registration, client, now).receive_one()


def test_expiry_during_long_poll_prevents_dispatch(registration, event, client, now):
    t = transport(registration, client, now)
    ticks = iter([now, now, registration.valid_until])
    t.clock = lambda: next(ticks)
    with Stubber(client) as stub:
        attributes(stub, registration)
        received(stub, registration, event)
        with pytest.raises(ContractError, match="expired"):
            t.receive_one()


def test_foreign_queue_receipt_cannot_be_acknowledged_or_deferred(
    registration, event, client, now
):
    delivery = SQSDelivery(registration.dead_letter_arn, "message", event, 1, "opaque")
    with Stubber(client) as stub:
        t = transport(registration, client, now)
        with pytest.raises(ContractError):
            t.acknowledge(delivery)
        with pytest.raises(ContractError):
            t.defer(delivery)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize(
    "endpoint,verify",
    [("http://127.0.0.1:1", True), ("https://sqs.ap-northeast-2.amazonaws.com", False)],
)
def test_custom_or_certificate_unverified_endpoint_is_rejected(
    registration, now, endpoint, verify
):
    client = boto3.client(
        "sqs",
        region_name=registration.region,
        endpoint_url=endpoint,
        verify=verify,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    with pytest.raises(ContractError, match="certificate-verified"):
        transport(registration, client, now)
