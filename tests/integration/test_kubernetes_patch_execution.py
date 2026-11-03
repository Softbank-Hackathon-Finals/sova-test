"""Real stored approvals/PG effects with a synthetic Kubernetes API port.

Provider TLS/RBAC and real EKS qualification are independent checks. This test
asserts composition of the same adapter with the existing durable executor.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import pytest
from kubernetes_patch_support import image_patch_bundle
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.plans import LifecyclePlan, PlanStep, PlanPurpose, PlanApproval
from sova.domain.operations import OperationRequest
from sova.domain.evidence import (
    RevisionSet,
    VerificationObligation,
    Gate,
    EvidenceRecord,
    VerificationResult,
)
from sova.domain.contracts import ContractError, EffectStatus, canonical_json

pytestmark = pytest.mark.postgres


@pytest.fixture
def patch_execution(postgres_bundle):
    lifecycle = postgres_bundle[0]
    now = datetime.now(UTC)
    reg, _, adapter, state = image_patch_bundle(now)
    scope = replace(reg.scope, tenant_id=lifecycle.tenant_id)
    reg = replace(
        reg,
        scope=scope,
        reader=replace(reg.reader, tenant_id=scope.tenant_id),
        artifact=replace(reg.artifact, scope=scope),
    )
    state["registration"] = reg
    adapter.registration = reg
    adapter.transport.registration_digest = reg.fingerprint
    revisions = RevisionSet(
        reg.artifact.source_digest, reg.base_configuration_digest, "c" * 64, "d" * 64
    )
    obligation = VerificationObligation(
        "registered-image", scope, Gate.PREFLIGHT, "fixture-policy-v1"
    )
    params = canonical_json(
        {
            "request_digest": reg.request_digest,
            "receipt_digest": reg.receipt_digest,
            "proposal_digest": reg.proposal_digest,
            "artifact": reg.artifact.document,
        }
    )
    plan = LifecyclePlan(
        "k8s-image",
        scope.tenant_id,
        scope.application_id,
        "operator",
        PlanPurpose.CHANGE,
        revisions,
        now + timedelta(minutes=2),
        (
            PlanStep(
                "patch",
                scope,
                adapter.adapter_id,
                "apply-verified-patch",
                params,
                reg.resource_version,
            ),
        ),
        (obligation,),
    )
    approval = PlanApproval(
        plan.fingerprint, "separate-approver", plan.purpose, plan.valid_until
    )
    lifecycle.save_plan(plan)
    lifecycle.save_approval(scope.application_id, plan.plan_id, "approval", approval)
    PostgresOperationRepository(lifecycle).submit(
        OperationRequest(
            scope.tenant_id,
            scope.application_id,
            "operation",
            plan.plan_id,
            plan.fingerprint,
            "approval",
            1,
            "operator",
            "idempotent-patch",
        )
    )
    ownership = PostgresExecutionOwnership(lifecycle)
    lease = ownership.acquire(scope.application_id, "operation", "worker")
    journal = PostgresEffectJournal(ownership, lease)
    evidence = EvidenceRecord(
        "fixture-proof",
        obligation.obligation_id,
        scope,
        revisions,
        obligation.verifier_version,
        now,
        plan.valid_until,
        VerificationResult.PASS,
        "fixture-only",
        "a" * 64,
    )

    def clock():
        return datetime.now(UTC)

    executor = StoredPlanExecutor(
        lifecycle,
        ApprovedPlanExecutor(
            EffectExecutor(journal, authorize=journal.authorize, clock=clock),
            required_obligations=lambda _: plan.obligations,
            authenticate_approval=lambda *_: None,
            authenticate_evidence=lambda value: value == evidence,
            clock=clock,
        ),
    )

    def run():
        return executor.execute_step(
            scope.application_id,
            plan.plan_id,
            "approval",
            "patch",
            operation_id=lease.operation_id,
            epoch=lease.epoch,
            evidence=(evidence,),
            adapter=adapter,
        )

    return run, state, lifecycle, scope, journal


def test_registered_image_adapter_obeys_existing_durable_execution_and_no_replay(
    patch_execution,
):
    run, state, _, _, journal = patch_execution
    result = run()
    assert result.status == EffectStatus.APPLIED
    assert journal.get(result.command) == result
    assert run() == result and len(state["calls"]) == 1
    assert result.observation.observed_at.tzinfo is not None


def test_persisted_approval_revocation_blocks_provider_dispatch(patch_execution):
    run, state, lifecycle, scope, _ = patch_execution
    lifecycle.revoke_approval(
        scope.application_id, "approval", expected_revision=1, actor_id="approver"
    )
    with pytest.raises(ContractError):
        run()
    assert not state["calls"]
