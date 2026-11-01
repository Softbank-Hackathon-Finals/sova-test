"""Admission is not execution; outbox delivery is not deployment success."""

import hashlib
from dataclasses import asdict, dataclass
from datetime import datetime

from sova.domain.contracts import (
    ContractError,
    canonical_json,
    digest,
    identifier,
    public_json,
    utc,
)
from sova.domain.workflows import OperationState


@dataclass(frozen=True, slots=True)
class OperationRequest:
    tenant_id: str
    application_id: str
    operation_id: str
    plan_id: str
    plan_digest: str
    approval_id: str
    approval_revision: int
    requested_by: str
    idempotency_key: str

    def __post_init__(self):
        for field in (
            "tenant_id",
            "application_id",
            "operation_id",
            "plan_id",
            "approval_id",
            "requested_by",
            "idempotency_key",
        ):
            identifier(getattr(self, field), field)
        digest(self.plan_digest)
        if type(self.approval_revision) is not int or self.approval_revision < 1:
            raise ContractError("Positive approval revision required")

    @property
    def fingerprint(self):
        data = asdict(self)
        # A retry may allocate a new ID before discovering its original receipt.
        # Identity belongs to the saved operation, not to the deduplication key.
        del data["operation_id"]
        return hashlib.sha256(canonical_json(data).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class StoredOperation:
    request: OperationRequest
    state: OperationState

    def __post_init__(self):
        if not isinstance(self.request, OperationRequest) or not isinstance(
            self.state, OperationState
        ):
            raise ContractError("Typed operation request and state required")
        if (
            self.request.tenant_id,
            self.request.application_id,
            self.request.operation_id,
            self.request.plan_digest,
        ) != (
            self.state.scope.tenant_id,
            self.state.scope.application_id,
            self.state.operation_id,
            self.state.plan_digest,
        ):
            raise ContractError("Stored operation state binding mismatch")


@dataclass(frozen=True, slots=True)
class OutboxDelivery:
    tenant_id: str
    application_id: str
    operation_id: str
    event_id: str
    owner_id: str
    lease_token: str
    attempt: int
    lease_until: datetime
    payload_json: str
    topic: str = "operation.requested.v1"

    def __post_init__(self):
        for field in (
            "tenant_id",
            "application_id",
            "operation_id",
            "event_id",
            "owner_id",
            "lease_token",
        ):
            identifier(getattr(self, field), field)
        if type(self.attempt) is not int or self.attempt < 1:
            raise ContractError("Positive delivery attempt required")
        if self.topic != "operation.requested.v1":
            raise ContractError("Unknown outbox topic")
        object.__setattr__(self, "lease_until", utc(self.lease_until))
        object.__setattr__(
            self, "payload_json", canonical_json(public_json(self.payload_json))
        )


@dataclass(frozen=True, slots=True)
class OutboxEvent:
    """Broker-visible envelope; never contains the internal delivery lease."""

    event_id: str
    topic: str
    payload_json: str

    def __post_init__(self):
        identifier(self.event_id, "event_id")
        if self.topic != "operation.requested.v1":
            raise ContractError("Unknown outbox topic")
        object.__setattr__(
            self, "payload_json", canonical_json(public_json(self.payload_json))
        )


@dataclass(frozen=True, slots=True)
class PublishReceipt:
    event_id: str
    publisher_id: str
    message_id: str

    def __post_init__(self):
        for field in ("event_id", "publisher_id", "message_id"):
            identifier(getattr(self, field), field)


@dataclass(frozen=True, slots=True)
class OperationEventReference:
    tenant_id: str
    application_id: str
    operation_id: str
    plan_id: str
    plan_digest: str
    approval_id: str
    approval_revision: int

    def __post_init__(self):
        for field in (
            "tenant_id",
            "application_id",
            "operation_id",
            "plan_id",
            "approval_id",
        ):
            identifier(getattr(self, field), field)
        digest(self.plan_digest)
        if type(self.approval_revision) is not int or self.approval_revision < 1:
            raise ContractError("Positive event approval revision required")

    @classmethod
    def from_event(cls, event):
        if not isinstance(event, OutboxEvent):
            raise ContractError("Typed outbox event required")
        payload = public_json(event.payload_json)
        if set(payload) != {
            "tenant_id",
            "application_id",
            "operation_id",
            "plan_id",
            "plan_digest",
            "approval_id",
            "approval_revision",
        }:
            raise ContractError(
                "Only immutable operation references belong in messages"
            )
        return cls(**payload)
