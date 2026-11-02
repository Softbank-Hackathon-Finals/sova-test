"""Real PostgreSQL + Ed25519 + execution gate; provider outcomes are test inputs."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import sqlite3
from uuid import uuid4
import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protection_support import protection_bundle, protection_profile
from support import IngressAdapter
from sova.adapters.postgres_protection_parity import PostgresProtectionParity
from sova.adapters.postgres_governance import PostgresSecurityHolds
from sova.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.signed_evidence import SignedEvidenceAuthority
from sova.application.protection_parity import ProtectionParityGuard
from sova.application.plans import ApprovedPlanExecutor
from sova.application.effects import EffectExecutor
from sova.domain.signed_evidence import VerifierTrust
from sova.domain.contracts import ContractError, EffectStatus
from sova.ports.plans import RepositoryConflict, RecordNotFound

pytestmark = pytest.mark.postgres


@pytest.fixture
def protection(postgres_bundle, now):
    lifecycle = postgres_bundle[0]
    policy, evidence, plan, approval, preflight = protection_bundle(
        postgres_bundle[3].scope, now
    )
    repo = PostgresProtectionParity(lifecycle.connect, tenant_id=lifecycle.tenant_id)
    repo.publish_policy(policy, actor="policy-authority", expected_revision=0)
    holds = PostgresSecurityHolds(lifecycle.connect, tenant_id=lifecycle.tenant_id)
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id="independent-verifier", key_id="key-1"
    )
    trust = [
        VerifierTrust(
            signer.issuer_id,
            signer.key_id,
            signer.public_key_hex,
            tuple(e.scope for e in evidence),
            tuple({e.verifier_version for e in evidence}),
            now - timedelta(seconds=1),
            now + timedelta(minutes=5),
        )
    ]
    authority = SignedEvidenceAuthority(
        PostgresSignedEvidence(lifecycle.connect, tenant_id=lifecycle.tenant_id),
        Ed25519EvidenceVerifier(lambda *_: trust[0]),
        clock=lambda: datetime.now(UTC),
    )
    for record in evidence:
        authority.ingest(signer.sign(record, issued_at=now))
    revisions = {
        ep.scope: ep.revisions(policy.fingerprint)
        for req in policy.requirements
        for ep in (req.source, req.target)
    }
    guard = ProtectionParityGuard(
        policy_provider=lambda p: repo.latest_policy(p.application_id),
        evidence_provider=lambda _: evidence,
        authenticate_policy=lambda _: None,
        authenticate_evidence=authority.authenticate,
        profile_provider=lambda _: protection_profile(),
        current_revisions=lambda s: revisions[s],
        holds=holds,
        clock=lambda: datetime.now(UTC),
        record_assessment=repo.record_assessment,
    )
    return lifecycle, repo, guard, policy, evidence, plan, approval, preflight, trust


def test_policies_reports_survive_restart_but_historical_pass_does_not_grant_execution(
    protection,
):
    lifecycle, repo, guard, policy, evidence, plan, *_ = protection
    report = guard.assess(plan, datetime.now(UTC))
    fingerprint = repo.record_assessment(plan, policy, evidence, report)
    restarted = PostgresProtectionParity(
        lifecycle.connect, tenant_id=lifecycle.tenant_id
    )
    assert restarted.latest_policy(plan.application_id) == policy
    assert (
        restarted.get_assessment(plan.application_id, fingerprint)["report"] == report
    )
    assert report["accepted"]
    # Merely publishing a new policy invalidates the old plan and its report.
    repo.publish_policy(
        replace(policy, revision=2), actor="policy-authority", expected_revision=1
    )
    assert restarted.get_assessment(plan.application_id, fingerprint)["report"][
        "accepted"
    ]
    with pytest.raises(ContractError, match="binding"):
        guard(plan, datetime.now(UTC))
    with pytest.raises(RepositoryConflict):
        repo.record_assessment(plan, policy, evidence, report)


def test_publication_is_cas_not_last_writer_wins(protection):
    _, repo, _, policy, *_ = protection

    def publish(variant):
        changed = replace(
            policy,
            revision=2,
            valid_until=policy.valid_until + timedelta(seconds=variant),
        )
        try:
            repo.publish_policy(changed, actor="policy-authority", expected_revision=1)
            return "published"
        except RepositoryConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, [1, 2]))
    assert sorted(results) == ["conflict", "published"]
    with pytest.raises(RepositoryConflict):
        repo.publish_policy(policy, actor="policy-authority", expected_revision=0)


def test_tenant_rls_and_no_runtime_history_mutation(protection):
    lifecycle, repo, guard, policy, evidence, plan, *_ = protection
    report = guard.assess(plan, datetime.now(UTC))
    fingerprint = repo.record_assessment(plan, policy, evidence, report)
    other = PostgresProtectionParity(
        lifecycle.connect, tenant_id="other-" + uuid4().hex
    )
    with pytest.raises(RecordNotFound):
        other.latest_policy(plan.application_id)
    with pytest.raises(RecordNotFound):
        other.get_assessment(plan.application_id, fingerprint)
    with pytest.raises(ContractError):
        other.publish_policy(policy, actor="attacker", expected_revision=0)
    for table in ["protection_policies", "protection_assessments"]:
        for verb in ["UPDATE", "DELETE"]:
            query = (
                f"UPDATE sova_control.{table} SET document='{{}}'"
                if verb == "UPDATE"
                else f"DELETE FROM sova_control.{table}"
            )
            with lifecycle.connect() as conn:
                conn.execute(
                    "SELECT set_config('sova.tenant_id',%s,true)", (repo.tenant_id,)
                )
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    conn.execute(query)


def executor(protection, tmp_path):
    *_, guard, policy, evidence, plan, approval, preflight, trust = protection
    journal = SQLiteEffectJournal(sqlite3.connect(tmp_path / "effects.db"))
    return ApprovedPlanExecutor(
        EffectExecutor(
            journal, authorize=lambda *_: None, clock=lambda: datetime.now(UTC)
        ),
        required_obligations=lambda _: plan.obligations,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        governance_guard=guard,
        clock=lambda: datetime.now(UTC),
    )


def test_actual_gate_composes_with_effect_executor_and_rejects_revoked_issuer(
    protection, tmp_path
):
    _, _, guard, _, _, plan, approval, preflight, trust = protection
    checked = executor(protection, tmp_path)
    adapter = IngressAdapter()
    assert guard(plan, datetime.now(UTC)) > datetime.now(UTC)
    trust[0] = replace(trust[0], revoked=True)
    with pytest.raises(ContractError, match="revoked"):
        checked.execute_step(
            plan,
            approval,
            "isolate",
            operation_id="op",
            epoch=1,
            evidence=(preflight,),
            adapter=adapter,
        )
    assert adapter.calls == []


def test_verified_parity_allows_one_effect_and_resource_drift_blocks_next(
    protection, tmp_path
):
    _, _, guard, policy, _, plan, approval, preflight, _ = protection
    checked = executor(protection, tmp_path)
    adapter = IngressAdapter()
    result = checked.execute_step(
        plan,
        approval,
        "isolate",
        operation_id="op",
        epoch=1,
        evidence=(preflight,),
        adapter=adapter,
    )
    assert result.status == EffectStatus.APPLIED and len(adapter.calls) == 1
    guard.current_revisions = lambda _: replace(plan.revisions, configuration="9" * 64)
    with pytest.raises(ContractError, match="revision changed"):
        checked.execute_step(
            plan,
            approval,
            "isolate",
            operation_id="op",
            epoch=1,
            evidence=(preflight,),
            adapter=adapter,
        )
    assert len(adapter.calls) == 1


def test_report_cannot_be_relabelled_as_pass(protection):
    _, repo, guard, policy, evidence, plan, *_ = protection
    report = guard.assess(plan, datetime.now(UTC))
    changed = {**report, "scope": "whole environment secure"}
    with pytest.raises(ContractError, match="altered"):
        repo.record_assessment(plan, policy, evidence, changed)
