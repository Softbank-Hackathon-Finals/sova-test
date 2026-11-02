"""Actual OPA, Ed25519 and SQLite dispatch; provider adapter is a test double."""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
import hashlib
import os
import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from support import IngressAdapter
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.plans import ApprovedPlanExecutor
from sova.domain.plans import LifecyclePlan, PlanApproval, PlanPurpose, PlanStep
from sova.domain.evidence import (
    EvidenceRecord,
    VerificationObligation,
    RevisionSet,
    Gate,
    VerificationResult as R,
)
from sova.domain.contracts import ContractError, EffectStatus
from sova_security.domain.governance import (
    GovernancePolicy,
    SecurityControl,
    ControlFamily,
)
from sova_security.domain.signed_evidence import VerifierTrust
from sova_security.domain.opa_policy import OPAPolicy, OPA_VERIFIER_VERSION
from sova_security.adapters.opa_local import (
    PinnedLocalOPA,
    preflight_policy_source,
    restricted_capabilities,
)
from sova_security.adapters.opa_evidence import opa_evidence
from sova_security.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova_security.application.opa_policy import OPAPlanPolicy
from sova_security.application.governance import GovernanceGuard

pytestmark = pytest.mark.policy_engine


@pytest.fixture
def setup(scope, now, tmp_path):
    path = os.environ.get("SOVA_TEST_OPA_PATH")
    digest = os.environ.get("SOVA_TEST_OPA_SHA256")
    if not path:
        pytest.skip("Explicit pinned OPA required for host integration")
    assert digest
    obligation = VerificationObligation(
        "native-tls", scope, Gate.PREFLIGHT, "tls-qualified-v1"
    )
    native_policy = GovernancePolicy(
        scope.tenant_id,
        scope.application_id,
        1,
        (SecurityControl(ControlFamily.ENCRYPTION, obligation),),
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    policy = OPAPolicy(
        scope,
        "qualified-operator-policy",
        1,
        preflight_policy_source(),
        digest,
        hashlib.sha256(restricted_capabilities()).hexdigest(),
        (scope,),
        (obligation,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    plan = LifecyclePlan(
        "opa-plan",
        scope.tenant_id,
        scope.application_id,
        "author",
        PlanPurpose.CHANGE,
        RevisionSet("a" * 64, "b" * 64, native_policy.fingerprint, "d" * 64),
        now + timedelta(minutes=5),
        (
            PlanStep(
                "isolate",
                scope,
                "test-ingress",
                "set_ingress",
                '{"blocked":true}',
                "revision-1",
            ),
        ),
        (obligation, policy.obligation),
    )
    native = EvidenceRecord(
        "native-proof",
        obligation.obligation_id,
        scope,
        plan.revisions,
        obligation.verifier_version,
        now,
        now + timedelta(minutes=1),
        R.PASS,
        "native-proof-artifact",
        "e" * 64,
    )
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id="qualified-independent-verifier",
        key_id="ephemeral-test-key",
    )
    state = {
        "policy": policy,
        "evidence": (native,),
        "trust": VerifierTrust(
            signer.issuer_id,
            signer.key_id,
            signer.public_key_hex,
            (scope,),
            (obligation.verifier_version, OPA_VERIFIER_VERSION),
            now - timedelta(seconds=1),
            now + timedelta(minutes=5),
        ),
    }
    envelopes = {native.evidence_id: signer.sign(native, issued_at=now)}
    verifier = Ed25519EvidenceVerifier(lambda *_: state["trust"])

    def authenticate(record):
        return verifier.verify(
            envelopes[record.evidence_id], expected_record=record, now=now
        )

    opa = OPAPlanPolicy(
        policy_provider=lambda _: state["policy"],
        evidence_provider=lambda _: state["evidence"],
        authenticate_policy=lambda _: None,
        authenticate_evidence=authenticate,
        authorize=lambda *_: None,
        evaluator=PinnedLocalOPA(path, expected_digest=digest),
        holds=SimpleNamespace(tenant_id=scope.tenant_id,active_holds=lambda _:()),
        clock=lambda: now,
    )
    decision = opa.evaluate("worker", plan)
    record = opa_evidence(plan, policy, decision, evidence_id="opa-proof")
    envelopes[record.evidence_id] = signer.sign(record, issued_at=now)

    class Holds:
        tenant_id = scope.tenant_id

        def active_holds(self, _):
            return ()

    native_guard = GovernanceGuard(
        Holds(),
        policy_provider=lambda _: native_policy,
        evidence_provider=lambda _: state["evidence"],
        authenticate_policy=lambda _: None,
        authenticate_evidence=authenticate,
        clock=lambda: now,
    )

    def combined(current, at):
        return min(native_guard(current, at), opa.for_actor("worker")(current, at))

    conn = sqlite3.connect(tmp_path / "opa-effects.sqlite")
    executor = ApprovedPlanExecutor(
        EffectExecutor(
            SQLiteEffectJournal(conn), authorize=lambda *_: None, clock=lambda: now
        ),
        required_obligations=lambda _: (obligation, policy.obligation),
        authenticate_approval=lambda *_: None,
        authenticate_evidence=authenticate,
        governance_guard=combined,
        clock=lambda: now,
    )
    adapter = IngressAdapter()
    approval = PlanApproval(
        plan.fingerprint, "separate-reviewer", plan.purpose, plan.valid_until
    )

    def run():
        return executor.execute_step(
            plan,
            approval,
            "isolate",
            operation_id="opa-operation",
            epoch=1,
            evidence=(*state["evidence"], record),
            adapter=adapter,
        )

    yield state, run, adapter, signer, envelopes
    conn.close()


def test_real_opa_and_native_checks_both_admit_the_signed_effect(setup):
    _, run, adapter, *_ = setup
    assert run().status == EffectStatus.APPLIED
    assert len(adapter.calls) == 1


@pytest.mark.parametrize(
    "case", ["operator-policy-changed", "native-proof-failed", "signer-revoked"]
)
def test_policy_or_security_failure_prevents_actual_effect_dispatch(setup, case):
    state, run, adapter, signer, envelopes = setup
    if case == "operator-policy-changed":
        state["policy"] = replace(state["policy"], revision=2)
    if case == "signer-revoked":
        state["trust"] = replace(state["trust"], revoked=True)
    if case == "native-proof-failed":
        record = replace(
            state["evidence"][0], evidence_id="new-native-failure", result=R.FAIL
        )
        envelopes[record.evidence_id] = signer.sign(
            record, issued_at=record.observed_at
        )
        state["evidence"] = (record,)
    with pytest.raises(ContractError):
        run()
    assert adapter.calls == []
