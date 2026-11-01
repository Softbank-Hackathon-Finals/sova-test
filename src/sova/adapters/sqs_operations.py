"""Bounded reference-only operation transport on explicitly registered AWS queues.

SQS acceptance is not execution success. Standard-queue duplicates are expected;
the consumer must re-read the immutable PG event/operation before any effect.
No resource creation, credentials, code, source archives or delivery leases are
included in messages. Queue administration belongs to the operator/IaC boundary.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import re

from sova.domain.contracts import (
    ContractError,
    canonical_json,
    identifier,
    public_json,
    utc,
)
from sova.domain.operations import OutboxEvent, PublishReceipt, OperationEventReference


@dataclass(frozen=True, slots=True)
class SQSQueueRegistration:
    account_id: str
    region: str
    queue_name: str
    dead_letter_name: str
    publisher_principal_arn: str
    consumer_principal_arn: str
    allowed_tenants: tuple[str, ...]
    issued_at: datetime
    valid_until: datetime
    visibility_seconds: int = 240
    max_receives: int = 5
    kms_key_arn: str | None = None

    def __post_init__(self):
        if not re.fullmatch(r"[0-9]{12}", self.account_id) or not re.fullmatch(
            r"[a-z]{2}(?:-[a-z]+)+-[1-9][0-9]?", self.region
        ):
            raise ContractError("Registered AWS account/region required")
        for name in (self.queue_name, self.dead_letter_name):
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", name):
                raise ContractError("Registered standard queue name required")
        if self.queue_name == self.dead_letter_name:
            raise ContractError("Distinct source and dead-letter queues required")
        for principal in (self.publisher_principal_arn, self.consumer_principal_arn):
            if not re.fullmatch(
                rf"arn:aws:iam::{self.account_id}:(?:role|user)/[A-Za-z0-9+=,.@_/-]{{1,512}}",
                principal,
            ):
                raise ContractError(
                    "Exact same-account IAM role/user principal required"
                )
        if (
            type(self.allowed_tenants) is not tuple
            or not 1 <= len(self.allowed_tenants) <= 64
            or len(set(self.allowed_tenants)) != len(self.allowed_tenants)
        ):
            raise ContractError("Bounded unique immutable tenant allowlist required")
        for tenant in self.allowed_tenants:
            identifier(tenant, "tenant")
        if (
            type(self.visibility_seconds) is not int
            or not 180 <= self.visibility_seconds <= 900
            or type(self.max_receives) is not int
            or not 3 <= self.max_receives <= 20
        ):
            raise ContractError(
                "Bounded phase visibility and dead-letter retry policy required"
            )
        if self.kms_key_arn is not None and not re.fullmatch(
            rf"arn:aws:kms:{self.region}:{self.account_id}:key/[A-Za-z0-9-]{{1,128}}",
            self.kms_key_arn,
        ):
            raise ContractError("Same-account explicit queue KMS key required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Positive queue registration lifetime required")

    @property
    def endpoint(self):
        return f"https://sqs.{self.region}.amazonaws.com"

    @property
    def queue_url(self):
        return f"{self.endpoint}/{self.account_id}/{self.queue_name}"

    @property
    def dead_letter_url(self):
        return f"{self.endpoint}/{self.account_id}/{self.dead_letter_name}"

    @property
    def queue_arn(self):
        return f"arn:aws:sqs:{self.region}:{self.account_id}:{self.queue_name}"

    @property
    def dead_letter_arn(self):
        return f"arn:aws:sqs:{self.region}:{self.account_id}:{self.dead_letter_name}"

    @property
    def policy(self):
        consumers = [
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:ChangeMessageVisibility",
        ]
        return {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RegisteredPublisher",
                    "Effect": "Allow",
                    "Principal": {"AWS": self.publisher_principal_arn},
                    "Action": "sqs:SendMessage",
                    "Resource": self.queue_arn,
                },
                {
                    "Sid": "RegisteredConsumer",
                    "Effect": "Allow",
                    "Principal": {"AWS": self.consumer_principal_arn},
                    "Action": consumers,
                    "Resource": self.queue_arn,
                },
                {
                    "Sid": "DenyOtherPublishers",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "sqs:SendMessage",
                    "Resource": self.queue_arn,
                    "Condition": {
                        "ArnNotEquals": {
                            "aws:PrincipalArn": self.publisher_principal_arn
                        }
                    },
                },
                {
                    "Sid": "DenyOtherConsumers",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": consumers,
                    "Resource": self.queue_arn,
                    "Condition": {
                        "ArnNotEquals": {
                            "aws:PrincipalArn": self.consumer_principal_arn
                        }
                    },
                },
                {
                    "Sid": "DenyInsecureTransport",
                    "Effect": "Deny",
                    "Principal": "*",
                    "Action": "sqs:*",
                    "Resource": self.queue_arn,
                    "Condition": {"Bool": {"aws:SecureTransport": "false"}},
                },
            ],
        }


@dataclass(frozen=True, slots=True)
class SQSDelivery:
    queue_arn: str
    message_id: str
    event: OutboxEvent
    receive_count: int
    receipt_handle: str = field(repr=False)

    def __post_init__(self):
        identifier(self.queue_arn, "queue ARN")
        identifier(self.message_id, "SQS message ID")
        if (
            not isinstance(self.event, OutboxEvent)
            or type(self.receive_count) is not int
            or not 1 <= self.receive_count <= 1000
        ):
            raise ContractError("Typed bounded SQS delivery required")
        identifier(self.receipt_handle, "SQS receipt", limit=8192)


class SQSOperationTransport:
    def __init__(
        self,
        registration,
        client,
        *,
        authenticate_registration,
        clock=lambda: datetime.now(UTC),
    ):
        if not isinstance(registration, SQSQueueRegistration):
            raise ContractError("Typed queue registration required")
        self.registration, self.client = registration, client
        self.authenticate_registration, self.clock = authenticate_registration, clock
        self.publisher_id = registration.queue_arn
        self._current()

    def _current(self):
        r = self.registration
        self.authenticate_registration(r)
        if not r.issued_at <= utc(self.clock()) < r.valid_until:
            raise ContractError("Queue registration expired or from future")
        if (
            self.client.meta.service_model.service_name != "sqs"
            or self.client.meta.region_name != r.region
            or self.client.meta.endpoint_url.rstrip("/") != r.endpoint
            or self.client._endpoint.http_session._verify is not True
        ):
            raise ContractError(
                "Only registered certificate-verified regional SQS endpoint is allowed"
            )

    def verify(self):
        self._current()
        r = self.registration
        source = self.client.get_queue_attributes(
            QueueUrl=r.queue_url,
            AttributeNames=[
                "QueueArn",
                "Policy",
                "SqsManagedSseEnabled",
                "KmsMasterKeyId",
                "RedrivePolicy",
                "VisibilityTimeout",
                "MessageRetentionPeriod",
            ],
        )["Attributes"]
        dead = self.client.get_queue_attributes(
            QueueUrl=r.dead_letter_url,
            AttributeNames=[
                "QueueArn",
                "RedriveAllowPolicy",
                "SqsManagedSseEnabled",
                "KmsMasterKeyId",
                "MessageRetentionPeriod",
            ],
        )["Attributes"]
        if (
            source.get("QueueArn") != r.queue_arn
            or dead.get("QueueArn") != r.dead_letter_arn
        ):
            raise ContractError("Queue account/resource identity drift")
        if public_json(source.get("Policy", "{}")) != r.policy:
            raise ContractError("Queue publisher/consumer policy drift")
        for attributes in (source, dead):
            if r.kms_key_arn is None:
                if attributes.get("SqsManagedSseEnabled") != "true" or attributes.get(
                    "KmsMasterKeyId"
                ):
                    raise ContractError("Queue SSE-SQS configuration drift")
            elif attributes.get("KmsMasterKeyId") != r.kms_key_arn:
                raise ContractError("Queue KMS configuration drift")
        redrive = public_json(source.get("RedrivePolicy", "{}"))
        try:
            count = redrive.get("maxReceiveCount")
            if type(count) is str and re.fullmatch(r"[0-9]{1,3}", count):
                count = int(count)
            retention = int(source.get("MessageRetentionPeriod", "0"))
            dead_retention = int(dead.get("MessageRetentionPeriod", "0"))
            if (
                set(redrive) != {"deadLetterTargetArn", "maxReceiveCount"}
                or redrive["deadLetterTargetArn"] != r.dead_letter_arn
                or type(count) is not int
                or count != r.max_receives
                or source.get("VisibilityTimeout") != str(r.visibility_seconds)
                or retention < r.visibility_seconds * r.max_receives
                or dead_retention <= retention
            ):
                raise ContractError("Queue redrive/visibility/retention drift")
        except (ValueError, TypeError) as exc:
            raise ContractError("Invalid queue delivery bounds") from exc
        if public_json(dead.get("RedriveAllowPolicy", "{}")) != {
            "redrivePermission": "byQueue",
            "sourceQueueArns": [r.queue_arn],
        }:
            raise ContractError("Dead-letter queue allows unregistered sources")
        self._current()

    def _reference(self, event):
        reference = OperationEventReference.from_event(event)
        if reference.tenant_id not in self.registration.allowed_tenants:
            raise ContractError("Operation tenant is outside registered queue")
        return reference

    def publish(self, event):
        self._reference(event)
        self.verify()
        body = canonical_json(
            {
                "event_id": event.event_id,
                "topic": event.topic,
                "payload_json": event.payload_json,
            },
            limit=16384,
        )
        response = self.client.send_message(
            QueueUrl=self.registration.queue_url, MessageBody=body
        )
        if (
            response.get("MD5OfMessageBody")
            != hashlib.md5(body.encode(), usedforsecurity=False).hexdigest()
        ):
            raise ContractError("SQS body checksum does not match submitted event")
        return PublishReceipt(event.event_id, self.publisher_id, response["MessageId"])

    def receive_one(self, *, wait_seconds=20):
        if type(wait_seconds) is not int or not 0 <= wait_seconds <= 20:
            raise ContractError("Bounded SQS long poll required")
        self.verify()
        r = self.registration
        result = self.client.receive_message(
            QueueUrl=r.queue_url,
            MaxNumberOfMessages=1,
            WaitTimeSeconds=wait_seconds,
            VisibilityTimeout=r.visibility_seconds,
            MessageSystemAttributeNames=["ApproximateReceiveCount"],
        )
        self._current()
        messages = result.get("Messages", [])
        if type(messages) is not list or len(messages) > 1:
            raise ContractError("Bounded SQS receive response required")
        if not messages:
            return None
        message = messages[0]
        body = message.get("Body")
        if (
            type(body) is not str
            or len(body.encode()) > 16384
            or message.get("MD5OfBody")
            != hashlib.md5(body.encode(), usedforsecurity=False).hexdigest()
        ):
            raise ContractError("Invalid SQS event body/checksum")
        from sova.adapters.registration.graph_codec import json_document

        document = json_document(body)
        if type(document) is not dict or set(document) != {
            "event_id",
            "topic",
            "payload_json",
        }:
            raise ContractError("Unexpected SQS envelope fields")
        event = OutboxEvent(**document)
        self._reference(event)
        count = message.get("Attributes", {}).get("ApproximateReceiveCount")
        if type(count) is not str or not re.fullmatch(r"[1-9][0-9]{0,2}", count):
            raise ContractError("Bounded SQS receive count required")
        return SQSDelivery(
            r.queue_arn,
            message["MessageId"],
            event,
            int(count),
            message["ReceiptHandle"],
        )

    def acknowledge(self, delivery):
        if (
            not isinstance(delivery, SQSDelivery)
            or delivery.queue_arn != self.registration.queue_arn
        ):
            raise ContractError("Typed SQS delivery required")
        self._reference(delivery.event)
        self._current()
        self.client.delete_message(
            QueueUrl=self.registration.queue_url, ReceiptHandle=delivery.receipt_handle
        )

    def defer(self, delivery, *, seconds=30):
        if (
            not isinstance(delivery, SQSDelivery)
            or delivery.queue_arn != self.registration.queue_arn
            or type(seconds) is not int
            or not 1 <= seconds <= self.registration.visibility_seconds
        ):
            raise ContractError("Bounded registered delivery backoff required")
        self._reference(delivery.event)
        self._current()
        self.client.change_message_visibility(
            QueueUrl=self.registration.queue_url,
            ReceiptHandle=delivery.receipt_handle,
            VisibilityTimeout=seconds,
        )
