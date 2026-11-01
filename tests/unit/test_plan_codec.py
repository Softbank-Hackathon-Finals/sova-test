from dataclasses import replace
from datetime import timedelta

import pytest

from sova.adapters.plan_codec import (
    decode_plan,
    decode_approval,
    encode_approval,
    decode_inspection,
    encode_inspection,
)
from sova.domain.contracts import ContractError
from sova.domain.evidence import Gate, RevisionSet, VerificationObligation
from sova.domain.plans import (
    LifecyclePlan,
    PlanStep,
    PlanPurpose,
    PlanApproval,
    Inspection,
)


@pytest.fixture
def plan(scope, now):
    return LifecyclePlan(
        "plan",
        scope.tenant_id,
        scope.application_id,
        "author",
        PlanPurpose.CHANGE,
        RevisionSet("a" * 64, "b" * 64, "c" * 64, "d" * 64),
        now + timedelta(minutes=1),
        (PlanStep("step", scope, "adapter", "action", "{}", "1"),),
        (VerificationObligation("obligation", scope, Gate.PREFLIGHT, "v1"),),
    )


def test_plan_round_trip_preserves_approval_digest(plan):
    rebuilt = decode_plan(plan.document)
    assert rebuilt == plan and rebuilt.fingerprint == plan.fingerprint


def test_snapshot_and_approval_round_trip(plan, now):
    approval = PlanApproval(
        plan.fingerprint, "approver", plan.purpose, plan.valid_until
    )
    snapshot = Inspection(
        plan.steps[0].scope, plan.revisions, now, plan.valid_until, "{}", "e" * 64
    )
    assert decode_approval(encode_approval(approval)) == approval
    assert decode_inspection(encode_inspection(snapshot)) == snapshot


def test_unknown_storage_fields_and_noninteger_gates_rejected(plan):
    with pytest.raises(ContractError):
        decode_plan({**plan.document, "unsupported_field": True})
    document = plan.document
    document["obligations"][0]["due_gate"] = True
    with pytest.raises(ContractError):
        decode_plan(document)


def test_plan_reason_cannot_embed_mutable_data(plan):
    with pytest.raises(ContractError):
        replace(plan, reason=["mutable"])
