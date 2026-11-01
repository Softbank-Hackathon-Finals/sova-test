"""Authenticate a broker reference against PG before dispatching a phase.

Tenant repositories and runner/evidence/adapter factories come from authenticated
server configuration. A tenant string in a message does not choose credentials.
"""

from dataclasses import dataclass

from sova.domain.contracts import ContractError, identifier, canonical_json
from sova.domain.operations import OperationEventReference
from sova.domain.workflows import OperationProfile, OperationStatus


@dataclass(frozen=True, slots=True)
class DeliveryOutcome:
    acknowledge: bool
    status: str
    operation_id: str
    result: dict | None = None

    def __post_init__(self):
        if type(self.acknowledge) is not bool:
            raise ContractError("Explicit delivery acknowledgement required")
        identifier(self.status, "delivery status")
        identifier(self.operation_id, "operation ID")
        if self.result is not None:
            canonical_json(self.result)


class MigrationOperationDelivery:
    def __init__(
        self,
        *,
        allowed_tenants,
        repository_for_tenant,
        runner_for_tenant,
        evidence_for_operation,
        adapter_factory_for_operation,
    ):
        if type(allowed_tenants) is not tuple or not allowed_tenants:
            raise ContractError("Immutable transport tenant allowlist required")
        self.allowed_tenants = allowed_tenants
        self.repository_for_tenant = repository_for_tenant
        self.runner_for_tenant = runner_for_tenant
        self.evidence_for_operation = evidence_for_operation
        self.adapter_factory_for_operation = adapter_factory_for_operation

    def handle(self, event, *, owner_id):
        reference = OperationEventReference.from_event(event)
        if reference.tenant_id not in self.allowed_tenants:
            raise ContractError("Unregistered message tenant")
        repository = self.repository_for_tenant(reference.tenant_id)
        if repository.tenant_id != reference.tenant_id:
            raise ContractError("Message cannot select a different tenant repository")
        expected = repository.get_event(
            reference.application_id, reference.operation_id
        )
        if expected != event:
            raise ContractError(
                "Message does not match the immutable admitted outbox event"
            )
        operation = repository.get(reference.application_id, reference.operation_id)
        if operation.state.profile != OperationProfile.MIGRATION_PHASE:
            raise ContractError("This consumer only dispatches migration phases")
        if operation.state.status in {
            OperationStatus.CANCELLED,
            OperationStatus.BLOCKED,
            OperationStatus.FAILED,
            OperationStatus.RECOVERED,
        }:
            return DeliveryOutcome(
                True, str(operation.state.status), reference.operation_id
            )
        if operation.state.status not in {
            OperationStatus.REGISTERED,
            OperationStatus.PHASE_VERIFIED,
        }:
            return DeliveryOutcome(
                False, str(operation.state.status), reference.operation_id
            )
        runner = self.runner_for_tenant(reference.tenant_id)
        evidence = (
            ()
            if operation.state.status == OperationStatus.PHASE_VERIFIED
            else self.evidence_for_operation(operation)
        )

        def forbidden(*_):
            raise ContractError("Historical receipt must not construct an adapter")

        factory = (
            forbidden
            if operation.state.status == OperationStatus.PHASE_VERIFIED
            else self.adapter_factory_for_operation(operation)
        )
        result = runner.run(
            reference.application_id,
            reference.operation_id,
            owner_id=owner_id,
            evidence=evidence,
            adapter_factory=factory,
        )
        if (
            result.get("status") != "phase_verified"
            or result.get("operation_id") != reference.operation_id
        ):
            raise ContractError("Phase runner did not return its durable completion")
        confirmed, proof = runner.programs.get_phase_completion(
            repository, reference.application_id, reference.operation_id
        )
        if (
            confirmed.state.status != OperationStatus.PHASE_VERIFIED
            or proof.fingerprint != result.get("completion_digest")
            or proof.plan_digest != reference.plan_digest
        ):
            raise ContractError(
                "Runner response differs from authoritative phase receipt"
            )
        return DeliveryOutcome(True, "phase_verified", reference.operation_id, result)


class SQSPhaseWorker:
    """One bounded poll. Process supervision and DLQ alerting are separate."""

    def __init__(self, transport, handler):
        if handler.allowed_tenants != transport.registration.allowed_tenants:
            raise ContractError("Transport and handler tenant scopes must match")
        self.transport, self.handler = transport, handler

    def poll_once(self, *, owner_id, wait_seconds=20):
        delivery = self.transport.receive_one(wait_seconds=wait_seconds)
        if delivery is None:
            return None
        outcome = self.handler.handle(delivery.event, owner_id=owner_id)
        if not isinstance(outcome, DeliveryOutcome):
            raise ContractError("Typed delivery outcome required")
        if outcome.acknowledge:
            self.transport.acknowledge(delivery)
        else:
            self.transport.defer(delivery)
        return outcome
