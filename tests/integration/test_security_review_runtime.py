"""Sova PG approval/lease/effect -> actual TLS process -> separate security PG.

Image apply, scan/rehearsal facts and TokenReview provider are simulations. No
cloud, real image, kubelet, production account or network policy is qualified.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from test_postgres_security_patch import setup as patch_setup
from security_review_runtime_support import (
    producer_support as pinned_producer, security_database as isolated_security_db, independent_service,
)
from sova.domain.contracts import ContractError, EffectStatus
from sova.interfaces.security_program import example_program
from sova.security.application.patch_execution import PatchPostflightRequired
from sova.security.application.remote_program import RemoteProgramService
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.remote_review import RemoteReviewClient
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.review_service import HostReviewBinding, ReviewPrincipal, ReviewRegistration
from sova_security.domain.security_program import ProgramKind, ProgramPhase, obligation_id

setup, producer_support, security_database = patch_setup, pinned_producer, isolated_security_db
pytestmark = pytest.mark.postgres


@pytest.mark.parametrize("fault", [None, "service-offline", "approval-revoked", "host-registration-revoked",
    "post-service-offline", "post-producer-revoked", "post-old-observation", "provider-response-lost"])
def test_two_database_service_chain_keeps_approval_hold_and_single_effect(
    setup, producer_support, security_database, tmp_path, fault,
):
    state, run, holds, journal, plan, lease, lifecycle = setup
    service, scope, now = state["service"], plan.steps[0].scope, datetime.now(UTC)
    example = example_program(ProgramKind.PATCH, now).program
    bindings = tuple(replace(b, revisions=plan.revisions, obligation=replace(b.obligation, scope=scope,
        obligation_id=obligation_id(plan.fingerprint, b.check_id))) for b in example.bindings)
    program = replace(example, subject_digest=plan.fingerprint, source=scope, target=scope,
        bindings=bindings, valid_until=plan.valid_until)
    records = tuple(EvidenceRecord("synthetic:" + b.check_id, b.obligation.obligation_id, scope, b.revisions,
        b.obligation.verifier_version, now, plan.valid_until, VerificationResult.PASS,
        "owned-test-measurement:" + b.check_id, "d" * 64) for b in program.bindings)
    binding = HostReviewBinding("sova", "0c1888d7a5369dbf5efee704d1051a3989a24b99", plan.plan_id,
        plan.fingerprint, "6" * 64, "patch", "1")
    pre = ReviewRegistration(program, binding, ProgramPhase.PREFLIGHT, now, plan.valid_until)
    principal = ReviewPrincipal("operator", scope.tenant_id, (scope,), ("enforce", "shadow"),
        now, plan.valid_until, "7" * 64)
    host = PostgresSecurityArtifacts(lifecycle.connect, tenant_id=scope.tenant_id)
    host.register(scope, program, actor_id="host-registrar")
    host.register(scope, pre, actor_id="host-registrar")
    registrations = {ProgramPhase.PREFLIGHT: pre}
    state["review_started"] = None
    def clock():
        at = datetime.now(UTC)
        if state["review_started"] is None:
            state["review_started"] = at
        return at
    service.clock = clock
    def current_registration(target, subject, phase):
        assert target == scope and subject == plan.fingerprint
        value = registrations.get(phase)
        if value is None:
            return None
        stored = host.get(scope, value.fingerprint, require_active=False)
        return None if stored.revoked else stored.value
    def invoke():
        state["review_started"] = None
        return run()
    with independent_service(producer_support, security_database, tmp_path, pre, records, principal) as runtime:
        def post(path, body, credential):
            raw = runtime.transport.post(path, body, credential)
            if not state.get("injected"):
                if fault == "approval-revoked":
                    lifecycle.revoke_approval(plan.application_id, "approval", expected_revision=1, actor_id="reviewer")
                elif fault == "host-registration-revoked":
                    host.revoke(scope, pre.fingerprint, expected_revision=1, actor_id="registrar", reason="test")
                state["injected"] = True
            return raw
        client = RemoteReviewClient(transport=SimpleNamespace(post=post), credential_for=lambda: runtime.credential,
            current_registration=current_registration, subject_id="operator", clock=lambda: datetime.now(UTC))
        service.program_service, service.program_scope = RemoteProgramService(client), scope
        original_observe = service.observe_runtime
        def observe(command, current_binding):
            proof = original_observe(command, current_binding)
            previous = registrations.get(ProgramPhase.POSTFLIGHT)
            if previous is not None:
                for store in (host, runtime.publisher.artifacts):
                    store.revoke(scope, previous.fingerprint, expected_revision=1, actor_id="registrar", reason="fresh-postflight")
            observed = state["review_started"] - timedelta(seconds=1) if fault == "post-old-observation" else datetime.now(UTC)
            runtime.publisher.publish(ProgramPhase.POSTFLIGHT, observed_at=observed)
            current = ReviewRegistration(program, binding, ProgramPhase.POSTFLIGHT, datetime.now(UTC), plan.valid_until,
                lease.operation_id, state["review_started"])
            for store in (host, runtime.publisher.artifacts):
                store.register(scope, current, actor_id="registrar")
            registrations[current.phase] = current
            if fault == "post-service-offline":
                runtime.stop()
            elif fault == "post-producer-revoked":
                runtime.publisher.revoke()
            return proof
        service.observe_runtime = observe
        if fault == "service-offline":
            runtime.stop()
        elif fault == "provider-response-lost":
            state["timeout"] = True
        if fault in {"service-offline", "approval-revoked", "host-registration-revoked"}:
            with pytest.raises(ContractError):
                invoke()
            assert state["calls"] == 0
        elif fault is None:
            first, second = invoke(), invoke()
            assert first.program_review.passed and second.program_review.passed
            assert first.effect == second.effect and state["calls"] == 1
            assert journal.get(first.effect.command) == first.effect
            assert not holds.active_holds(plan.application_id)
        else:
            with pytest.raises(PatchPostflightRequired):
                invoke()
            assert state["calls"] == 1 and holds.active_holds(plan.application_id)
            command = plan.command("patch-1", operation_id=lease.operation_id, epoch=lease.epoch)
            expected = EffectStatus.UNKNOWN if fault == "provider-response-lost" else EffectStatus.APPLIED
            assert journal.get(command).status == expected
            with pytest.raises(ContractError):
                invoke()
            assert state["calls"] == 1
