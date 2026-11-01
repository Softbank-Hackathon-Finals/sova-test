from dataclasses import replace
from datetime import timedelta

import pytest

from sova.domain.contracts import ContractError
from sova.domain.evidence import (
    EvidenceRecord,
    Gate,
    RevisionSet,
    VerificationObligation,
    VerificationResult as R,
    evaluate_gate,
)


@pytest.fixture
def revisions():
    return RevisionSet("a" * 64, "b" * 64, "c" * 64, "d" * 64)


@pytest.fixture
def obligation(scope):
    return VerificationObligation("tls", scope, Gate.PROTECTION, "tls-verifier-v1")


@pytest.fixture
def evidence(scope, revisions, now):
    return EvidenceRecord(
        "evidence-1",
        "tls",
        scope,
        revisions,
        "tls-verifier-v1",
        now - timedelta(seconds=5),
        now + timedelta(minutes=1),
        R.PASS,
        "owned-artifact-id",
        "e" * 64,
    )


def evaluate(obligation, evidence, revisions, now, gate=Gate.PROTECTION):
    return evaluate_gate(gate, (obligation,), tuple(evidence), revisions, now=now)


def test_required_evidence_missing_is_not_pass(obligation, revisions, now):
    result = evaluate(obligation, [], revisions, now)
    assert not result.accepted
    assert result.decisions[0].result == R.UNKNOWN


def test_future_obligations_are_carried_even_when_already_passing(
    obligation, evidence, revisions, now
):
    result = evaluate(obligation, [evidence], revisions, now, Gate.BEHAVIOR)
    assert result.accepted and result.carry_forward == ("tls",)
    assert len(result.decisions) == 1


@pytest.mark.parametrize("field", ["source", "configuration", "policy", "environment"])
def test_changed_revision_invalidates_evidence(
    obligation, evidence, revisions, now, field
):
    result = evaluate(
        obligation, [evidence], replace(revisions, **{field: "f" * 64}), now
    )
    assert not result.accepted


def test_source_evidence_cannot_verify_target(obligation, evidence, revisions, now):
    target = replace(
        obligation, scope=replace(obligation.scope, environment_id="target")
    )
    assert not evaluate(target, [evidence], revisions, now).accepted


def test_expiry_boundary_and_future_observation_are_unknown(
    obligation, evidence, revisions, now
):
    assert not evaluate(
        obligation, [evidence], revisions, evidence.valid_until
    ).accepted
    future = replace(evidence, observed_at=now + timedelta(seconds=1))
    assert not evaluate(obligation, [future], revisions, now).accepted


def test_new_failure_cannot_be_masked_by_old_pass(obligation, evidence, revisions, now):
    failed = replace(evidence, evidence_id="evidence-2", observed_at=now, result=R.FAIL)
    result = evaluate(obligation, [evidence, failed], revisions, now)
    assert not result.accepted and result.decisions[0].result == R.FAIL


def test_ambiguous_timestamp_never_selects_arbitrary_success(
    obligation, evidence, revisions, now
):
    failed = replace(evidence, evidence_id="evidence-2", result=R.FAIL)
    assert not evaluate(obligation, [evidence, failed], revisions, now).accepted


def test_not_applicable_requires_explanation_and_approver(evidence):
    with pytest.raises(ContractError):
        replace(evidence, result=R.NOT_APPLICABLE)


def test_not_applicable_is_bound_and_expires(obligation, evidence, revisions, now):
    approved = replace(
        evidence,
        result=R.NOT_APPLICABLE,
        justification="No database is used",
        approved_by="verified-approver",
    )
    assert evaluate(obligation, [approved], revisions, now).accepted
    assert not evaluate(
        obligation, [approved], revisions, approved.valid_until
    ).accepted


def test_duplicate_obligation_and_evidence_ids_rejected(
    obligation, evidence, revisions, now
):
    with pytest.raises(ContractError, match="obligation"):
        evaluate_gate(Gate.PROTECTION, (obligation, obligation), (), revisions, now=now)
    with pytest.raises(ContractError, match="evidence"):
        evaluate(obligation, [evidence, evidence], revisions, now)


def test_unknown_and_wrong_verifier_cannot_pass(obligation, evidence, revisions, now):
    for item in [
        replace(evidence, result=R.UNKNOWN),
        replace(evidence, verifier_version="other"),
    ]:
        assert not evaluate(obligation, [item], revisions, now).accepted


def test_mutable_or_unbounded_evidence_cannot_enter_gate(obligation, revisions, now):
    for records in ([], (None,), (None,) * 4097):
        with pytest.raises(ContractError, match="immutable evidence"):
            evaluate_gate(Gate.PREFLIGHT, (obligation,), records, revisions, now=now)
