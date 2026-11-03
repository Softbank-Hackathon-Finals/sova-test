"""Bounded registered-sink relay; no destinations from findings or request data."""

from sova.domain.contracts import ContractError
from sova.monitoring.contracts import AlertReceipt
from sova_security.application.boundary import require_accept


class MonitorAlertRelay:
    def __init__(self, *, repository, sink, authorize):
        self.repository, self.sink, self.authorize = repository, sink, authorize

    def deliver_one(self, actor, application_id, owner_id):
        require_accept(
            self.authorize,
            actor,
            self.repository.tenant_id,
            application_id,
            "security:deliver-monitor-alert",
            self.sink.sink_id,
        )
        delivery = self.repository.claim_alert(application_id, owner_id)
        if delivery is None:
            return None
        # Receipt loss keeps the alert pending. Do not retry inside this lease;
        # a later invocation can deliver the same stable alert ID again.
        require_accept(
            self.authorize,
            actor,
            self.repository.tenant_id,
            application_id,
            "security:deliver-monitor-alert",
            self.sink.sink_id,
        )
        receipt = self.sink.deliver(delivery.event)
        if (
            not isinstance(receipt, AlertReceipt)
            or receipt.alert_id != delivery.alert_id
            or receipt.sink_id != self.sink.sink_id
        ):
            raise ContractError("Registered monitoring sink receipt mismatch")
        require_accept(
            self.authorize,
            actor,
            self.repository.tenant_id,
            application_id,
            "security:deliver-monitor-alert",
            self.sink.sink_id,
        )
        self.repository.acknowledge_alert(delivery, receipt)
        return receipt
