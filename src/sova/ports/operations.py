from typing import Protocol

from sova.domain.operations import (
    OperationRequest,
    OutboxDelivery,
    OutboxEvent,
    PublishReceipt,
    StoredOperation,
)
from sova.domain.workflows import OperationStatus
from sova.domain.execution import ExecutionLease
from sova.domain.response_completion import ResponseCompletion


class LeaseLost(RuntimeError):
    pass


class OperationRepository(Protocol):
    tenant_id: str

    def submit(self, request: OperationRequest) -> StoredOperation: ...
    def get(self, application_id: str, operation_id: str) -> StoredOperation: ...
    def advance(
        self,
        application_id: str,
        operation_id: str,
        status: OperationStatus,
        *,
        expected_revision: int,
        actor_id: str,
    ) -> StoredOperation: ...
    def claim(
        self, application_id: str, owner_id: str, *, lease_seconds: int = 30
    ) -> OutboxDelivery | None: ...
    def acknowledge(
        self, delivery: OutboxDelivery, receipt: PublishReceipt
    ) -> None: ...
    def advance_owned(
        self,
        ownership,
        lease: ExecutionLease,
        status: OperationStatus,
        *,
        expected_revision: int,
        actor_id: str,
    ) -> StoredOperation: ...
    def finish_response(
        self,
        ownership,
        lease: ExecutionLease,
        completion: ResponseCompletion,
        *,
        expected_revision: int,
    ) -> tuple[StoredOperation, ResponseCompletion]: ...
    def get_response_completion(
        self, application_id: str, operation_id: str
    ) -> tuple[StoredOperation, ResponseCompletion]: ...


class EventPublisher(Protocol):
    publisher_id: str

    def publish(self, event: OutboxEvent) -> PublishReceipt:
        """Acknowledge broker acceptance, not resource execution.

        Consumers must deduplicate stable event_id and read authoritative
        operation/approval state before requesting effects. No lease token
        or credentials may be copied into the broker message.
        """
        ...
