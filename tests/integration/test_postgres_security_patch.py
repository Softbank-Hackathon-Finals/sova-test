"""Real PG repositories, approval, lease, effects and signatures; fake provider."""

from datetime import UTC, datetime, timedelta
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_patch_support import patch_bundle, patch_rescan, signed_input_authority
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import EffectObservation, EffectStatus, ContractError
from sova.domain.operations import OperationRequest
from sova.domain.plans import PlanApproval
from sova.security.application.patch_execution import (
    PatchPlanExecutionService,
    PatchPostflightRequired,
)
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_governance import PostgresSecurityHolds
from sova_security.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova_security.adapters.rehearsal_evidence import (
    RehearsalReceiptAuthority,
    rehearsal_evidence,
    VERIFIER_VERSION,
)
from sova_security.adapters.patch_evidence import (
    patch_rehearsal_records,
    patch_runtime_record,
    PatchRuntimeAuthority,
    RUNTIME_VERIFIER_VERSION,
    VERIFIER_VERSION as PATCH_VERSION,
)
from sova_security.application.remediation import RehearsalAdmissionService
from sova_security.application.patch_execution import PatchExecutionGuard
from sova_security.domain.patch_execution import compile_patch, PatchRuntimeObservation
from sova_security.domain.signed_evidence import VerifierTrust
from sova_security.contracts.evidence import VerificationResult as R, RevisionSet

pytestmark = pytest.mark.postgres


@pytest.fixture
def setup(postgres_bundle):
    lifecycle, base_plan, _, _, _ = postgres_bundle
    scope = base_plan.steps[0].scope
    origin = datetime.now(UTC) - timedelta(seconds=5)
    inputs, assessment, request, receipt = patch_bundle(scope, origin)

    def clock():
        return datetime.now(UTC)

    artifacts = PostgresSecurityArtifacts(lifecycle.connect, tenant_id=scope.tenant_id)
    holds = PostgresSecurityHolds(lifecycle.connect, tenant_id=scope.tenant_id)
    for value in (*inputs, assessment, request, receipt):
        artifacts.register(scope, value, actor_id="qualified-test-collector")
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id=request.verifier_issuer,
        key_id="isolated-test-key",
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (VERIFIER_VERSION, PATCH_VERSION, RUNTIME_VERIFIER_VERSION),
        origin - timedelta(seconds=1),
        origin + timedelta(minutes=10),
    )
    state = {
        "trust": trust,
        "runtime": R.PASS,
        "calls": 0,
        "timeout": False,
        "runtime_envelope": None,
    }

    def resolve(*_):
        return state["trust"]

    envelope = signer.sign(
        rehearsal_evidence(request, receipt, evidence_id="independent-rehearsal"),
        issued_at=receipt.issued_at,
    )
    receipt_authority = RehearsalReceiptAuthority(
        envelope_provider=lambda *_: envelope, resolve_trust=resolve, clock=clock
    )
    input_authority, revoke_input = signed_input_authority(
        lifecycle.connect,
        scope,
        (*inputs, assessment, request),
        revisions=RevisionSet(
            inputs[0].source_digest,
            inputs[0].configuration_digest,
            inputs[3].fingerprint,
            "e" * 64,
        ),
        clock=clock,
    )
    state["revoke_input"] = revoke_input
    admission = RehearsalAdmissionService(
        authorize=lambda *_: None,
        authenticate_input=input_authority,
        authenticate_receipt=receipt_authority,
        current_inputs=lambda _: inputs,
        current_request=lambda _, id: artifacts.request(scope, id),
        current_assessment=lambda _, hash: artifacts.get(scope, hash).value,
        target_inventory=lambda _: inputs[0],
        clock=clock,
    )
    decision = admission.verify("operator", request=request, receipt=receipt)
    adapters = {scope: "test-qualified-artifact-adapter"}
    plan, binding = compile_patch(
        request,
        receipt,
        decision,
        inventories=(inputs[0],),
        adapters=adapters,
        plan_id="patch-plan",
        created_by="operator",
        now=clock(),
    )
    lifecycle.save_plan(plan)
    artifacts.register(scope, binding, actor_id="operator")
    approval = PlanApproval(
        plan.fingerprint, "independent-approver", plan.purpose, plan.valid_until
    )
    lifecycle.save_approval(scope.application_id, plan.plan_id, "approval", approval)
    operations = PostgresOperationRepository(lifecycle)
    operations.submit(
        OperationRequest(
            scope.tenant_id,
            scope.application_id,
            "patch-operation",
            plan.plan_id,
            plan.fingerprint,
            "approval",
            1,
            "operator",
            "patch-idempotency",
        )
    )
    ownership = PostgresExecutionOwnership(lifecycle)
    lease = ownership.acquire(scope.application_id, "patch-operation", "patch-worker")
    journal = PostgresEffectJournal(ownership, lease)

    def binding_for(_):
        return artifacts.get(scope, binding.fingerprint).value

    guard = PatchExecutionGuard(
        admission=admission,
        binding_for=binding_for,
        inputs_for=lambda _: (request, receipt, (inputs[0],), adapters),
        authenticate_binding=lambda *_: None,
        authorize=lambda *_: None,
        require_no_holds=lambda _: not holds.active_holds(scope.application_id),
        clock=clock,
    )
    records = patch_rehearsal_records(
        plan, binding, request, receipt, evidence_prefix="independent-plan"
    )
    envelopes = {r.evidence_id: signer.sign(r, issued_at=clock()) for r in records}
    verifier = Ed25519EvidenceVerifier(resolve)

    def authenticate(record):
        verifier.verify(
            envelopes[record.evidence_id], expected_record=record, now=clock()
        )

    base = ApprovedPlanExecutor(
        EffectExecutor(journal, authorize=journal.authorize, clock=clock),
        required_obligations=lambda _: plan.obligations,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=authenticate,
        clock=clock,
    )

    class Adapter:
        adapter_id = "test-qualified-artifact-adapter"

        def validate(self, command):
            if command.parameters.get("artifact") != binding.artifacts[0].document:
                raise ContractError("Artifact mismatch")

        def apply(self, command):
            state["calls"] += 1
            if state.get("revoke-after-apply"):
                state["trust"] = replace(state["trust"], revoked=True)
            if state["timeout"]:
                raise TimeoutError("Synthetic provider response lost")

        def readback(self, command, at):
            return EffectObservation(
                scope,
                command.fingerprint,
                EffectStatus.APPLIED,
                at,
                '{"synthetic_provider_readback":true}',
            )

    def observe(command, current):
        reassessment, after_assessment, after_inputs = patch_rescan(
            inputs, assessment, request.proposal, current.artifacts[0], clock()
        )
        for value in (*after_inputs, after_assessment, reassessment):
            artifacts.register(scope, value, actor_id=signer.issuer_id)
        state["reassessment"] = reassessment
        proof = PatchRuntimeObservation(
            scope,
            plan.fingerprint,
            command.fingerprint,
            current.artifacts[0],
            "resource-v2",
            signer.issuer_id,
            "e" * 64,
            R.PASS,
            R.PASS,
            state["runtime"],
            clock(),
            binding.valid_until,
            reassessment.fingerprint,
        )
        record = patch_runtime_record(
            plan, binding, command, proof, evidence_id="independent-runtime"
        )
        state["runtime_envelope"] = signer.sign(record, issued_at=clock())
        return proof

    def record_hold(command, reason):
        holds.open_incident(command.scope, reason, "qualified-patch-verifier")

    service = PatchPlanExecutionService(
        stored_executor=StoredPlanExecutor(lifecycle, base),
        patch_guard=guard,
        binding_for=binding_for,
        observe_runtime=observe,
        reassessment_for=lambda proof: (
            artifacts.get(scope, proof.reassessment_digest).value
        ),
        authenticate_runtime=PatchRuntimeAuthority(
            plan_for=lambda _: lifecycle.get_plan(scope.application_id, plan.plan_id),
            envelope_provider=lambda *_: state["runtime_envelope"],
            resolve_trust=resolve,
            clock=clock,
        ),
        authenticate_binding=lambda *_: None,
        authorize=lambda *_: None,
        record_hold=record_hold,
        clock=clock,
    )

    def run():
        return service.execute_step(
            "operator",
            scope.application_id,
            plan.plan_id,
            "approval",
            "patch-1",
            operation_id=lease.operation_id,
            epoch=lease.epoch,
            evidence=records,
            adapter=Adapter(),
        )

    return state, run, holds, journal, plan, lease, lifecycle


def test_pg_approval_lease_signature_and_effect_are_shared_after_restart(setup):
    state, run, _, journal, _, _, _ = setup
    result = run()
    assert result.effect.status == EffectStatus.APPLIED
    assert journal.get(result.effect.command) == result.effect
    assert run().effect == result.effect and state["calls"] == 1


@pytest.mark.parametrize(
    "case", ["lost-response", "failed-protection", "verifier-revoked-after-apply"]
)
def test_pg_uncertainty_and_failed_postflight_persist_incident_hold(setup, case):
    state, run, holds, _, plan, _, _ = setup
    if case == "lost-response":
        state["timeout"] = True
    elif case == "failed-protection":
        state["runtime"] = R.FAIL
    else:
        state["revoke-after-apply"] = True
    with pytest.raises(PatchPostflightRequired):
        run()
    assert holds.active_holds(plan.application_id)
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 1


def test_pg_revoked_approval_is_checked_before_provider_apply(setup):
    state, run, _, _, plan, _, lifecycle = setup
    lifecycle.revoke_approval(
        plan.application_id, "approval", expected_revision=1, actor_id="reviewer"
    )
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 0


def test_pg_revoked_scan_issuer_blocks_approved_patch_before_provider_call(setup):
    state, run, _, _, _, _, _ = setup
    state["revoke_input"]("vulnerability-scan.v1")
    with pytest.raises(ContractError, match="revoked"):
        run()
    assert state["calls"] == 0


def test_authenticated_detection_hold_blocks_existing_patch_execution(setup):
    from sova_security.domain.detection import (
        DetectionRegistration,
        DetectionObservation,
    )
    from sova_security.application.detection import DetectionAdmission

    state, run, holds, _, plan, _, lifecycle = setup
    scope = plan.steps[0].scope
    now = datetime.now(UTC) - timedelta(milliseconds=100)
    registration = DetectionRegistration(
        scope,
        "falco",
        "onprem",
        "registered-cluster",
        "local",
        scope.resource_id,
        "runtime-v1",
        300,
        now,
        now + timedelta(minutes=2),
    )
    finding = DetectionObservation(
        registration,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "source_status",
        "coverage-unavailable",
        False,
        now,
        now + timedelta(minutes=1),
    )

    def clock():
        return datetime.now(UTC)

    authentication, _ = signed_input_authority(
        lifecycle.connect,
        scope,
        (registration, finding),
        revisions=plan.revisions,
        clock=clock,
    )
    admission = DetectionAdmission(
        current_registration=lambda *_: registration,
        authenticate_registration=lambda value: authentication(
            "detector", scope, value
        ),
        authenticate_observation=lambda value: authentication("detector", scope, value),
        artifacts=PostgresSecurityArtifacts(
            lifecycle.connect, tenant_id=scope.tenant_id
        ),
        holds=holds,
        authorize=lambda *_: None,
        clock=clock,
    )
    admission.admit("detector", finding)
    assert holds.active_holds(scope.application_id)
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 0
