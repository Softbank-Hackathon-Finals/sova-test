"""Publish outside the DB transaction; acknowledge only the held delivery."""

from sova.domain.contracts import ContractError
from sova.domain.operations import OutboxEvent, PublishReceipt
from sova.ports.operations import EventPublisher, OperationRepository


class OutboxRelay:
    def __init__(self, repository: OperationRepository, publisher: EventPublisher):
        self.repository, self.publisher = repository, publisher

    def publish_one(self, application_id, owner_id, *, lease_seconds=30):
        delivery = self.repository.claim(
            application_id, owner_id, lease_seconds=lease_seconds
        )
        if delivery is None:
            return None
        receipt = self.publisher.publish(
            OutboxEvent(delivery.event_id, delivery.topic, delivery.payload_json)
        )
        if (
            not isinstance(receipt, PublishReceipt)
            or receipt.event_id != delivery.event_id
            or receipt.publisher_id != self.publisher.publisher_id
        ):
            raise ContractError("Publisher receipt does not match delivery")
        self.repository.acknowledge(delivery, receipt)
        return receipt
