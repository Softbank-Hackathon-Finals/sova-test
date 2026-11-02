from dataclasses import replace
from datetime import timedelta
import pytest

from protection_support import protection_bundle, protection_profile
from governance_support import MemoryHolds
from sova.domain.contracts import ContractError
from sova.domain.evidence import VerificationResult
from sova.domain.governance import SecurityHold
from sova.domain.protection_parity import Availability, assess_protection
from sova.application.protection_parity import ProtectionParityGuard


def test_different_provider_implementations_compare_actual_objective(scope, now):
    policy, evidence, *_ = protection_bundle(scope, now)
    report = assess_protection(policy, evidence, now=now)
    row = report["requirements"][0]
    assert report["accepted"] and row["comparison"] == "maintained"
    assert row["source"]["implementation"] != row["target"]["implementation"]
    improved = (replace(evidence[0], result=VerificationResult.FAIL), evidence[1])
    assert (
        assess_protection(policy, improved, now=now)["requirements"][0]["comparison"]
        == "improved"
    )
    regressed = (evidence[0], replace(evidence[1], result=VerificationResult.FAIL))
    assert (
        assess_protection(policy, regressed, now=now)["requirements"][0]["comparison"]
        == "regressed"
    )
    assert not assess_protection(policy, regressed, now=now)["accepted"]


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "expired",
        "future",
        "unknown",
        "not-applicable",
        "wrong-scope",
        "wrong-revision",
        "wrong-verifier",
        "ambiguous",
        "new-failure",
        "baseline-unknown",
    ],
)
def test_unproven_protection_never_becomes_equivalence(case, scope, now):
    policy, evidence, *_ = protection_bundle(scope, now)
    a, b = evidence
    if case == "missing":
        evidence = (a,)
    if case == "expired":
        evidence = (
            a,
            replace(b, observed_at=now - timedelta(minutes=1), valid_until=now),
        )
    if case == "future":
        evidence = (a, replace(b, observed_at=now + timedelta(seconds=1)))
    if case == "unknown":
        evidence = (a, replace(b, result=VerificationResult.UNKNOWN))
    if case == "not-applicable":
        evidence = (
            a,
            replace(
                b,
                result=VerificationResult.NOT_APPLICABLE,
                approved_by="deployer",
                justification="skip",
            ),
        )
    if case == "wrong-scope":
        evidence = (a, replace(b, scope=replace(b.scope, application_id="other")))
    if case == "wrong-revision":
        evidence = (
            a,
            replace(b, revisions=replace(b.revisions, configuration="9" * 64)),
        )
    if case == "wrong-verifier":
        evidence = (a, replace(b, verifier_version="configuration-only-v1"))
    if case == "ambiguous":
        evidence += (replace(b, evidence_id="collision"),)
    if case == "new-failure":
        evidence += (
            replace(
                b,
                evidence_id="new-failed",
                observed_at=now + timedelta(seconds=1),
                result=VerificationResult.FAIL,
            ),
        )
        now += timedelta(seconds=1)
    if case == "baseline-unknown":
        evidence = (replace(a, result=VerificationResult.UNKNOWN), b)
    report = assess_protection(policy, evidence, now=now)
    assert not report["accepted"]


@pytest.mark.parametrize("field", ["provider_capability", "adapter_implementation"])
@pytest.mark.parametrize(
    "availability", [Availability.UNKNOWN, Availability.UNAVAILABLE]
)
def test_tool_or_provider_support_never_substitutes_for_qualification(
    field, availability, scope, now
):
    policy, _, *_ = protection_bundle(scope, now)
    req = policy.requirements[0]
    policy = replace(
        policy,
        requirements=(
            replace(req, target=replace(req.target, **{field: availability})),
        ),
    )
    report = assess_protection(policy, (), now=now)
    assert not report["accepted"]
    assert report["requirements"][0]["target"]["state"] == "unknown"


def make_guard(scope, now):
    policy, evidence, plan, *_ = protection_bundle(scope, now)
    revisions = {
        ep.scope: ep.revisions(policy.fingerprint)
        for req in policy.requirements
        for ep in (req.source, req.target)
    }
    holds = MemoryHolds(scope.tenant_id, now)
    guard = ProtectionParityGuard(
        policy_provider=lambda _: policy,
        evidence_provider=lambda _: evidence,
        authenticate_policy=lambda _: None,
        authenticate_evidence=lambda _: None,
        profile_provider=lambda _: protection_profile(),
        current_revisions=lambda s: revisions[s],
        holds=holds,
        clock=lambda: now,
    )
    return guard, policy, evidence, plan, revisions, holds


def test_gate_checks_drift_policy_revision_and_independent_hold(scope, now):
    guard, policy, evidence, plan, revisions, holds = make_guard(scope, now)
    assert guard(plan, now) > now
    s = policy.requirements[0].target.scope
    revisions[s] = replace(revisions[s], configuration="9" * 64)
    with pytest.raises(ContractError, match="revision changed"):
        guard(plan, now)
    revisions[s] = plan.revisions
    guard.policy_provider = lambda _: replace(policy, revision=2)
    with pytest.raises(ContractError, match="binding"):
        guard(plan, now)
    guard.policy_provider = lambda _: policy
    holds.open_hold(SecurityHold("incident", s, "detector", "violation", now))
    assert not guard.assess(plan, now)["accepted"]
    with pytest.raises(ContractError, match="blocks"):
        guard(plan, now)


def test_guard_reauthenticates_issuer_on_every_check_and_cannot_cover_unknown_resource(
    scope, now
):
    guard, _, _, plan, _, _ = make_guard(scope, now)
    assert guard(plan, now) > now

    def revoked(_):
        raise ContractError("issuer revoked")

    guard.authenticate_evidence = revoked
    with pytest.raises(ContractError, match="revoked"):
        guard(plan, now)
    guard.authenticate_evidence = lambda _: None
    changed = replace(
        plan,
        steps=(
            replace(
                plan.steps[0],
                scope=replace(plan.steps[0].scope, resource_id="uncovered"),
            ),
        ),
    )
    with pytest.raises(ContractError, match="outside"):
        guard(changed, now)


def test_contract_rejects_aliases_cross_tenant_empty_or_optional_only(scope, now):
    policy, *_ = protection_bundle(scope, now)
    req = policy.requirements[0]
    for target in [
        replace(req.target, scope=req.source.scope),
        replace(req.target, scope=replace(req.target.scope, tenant_id="other")),
        replace(
            req.target,
            scope=replace(req.target.scope, resource_id=req.source.scope.resource_id),
        ),
    ]:
        with pytest.raises(ContractError):
            replace(req, target=target)
    with pytest.raises(ContractError):
        replace(policy, requirements=())
    with pytest.raises(ContractError):
        replace(policy, requirements=(replace(req, required=False),))


@pytest.mark.parametrize("change", ["hold", "drift", "expiry"])
def test_assessment_recording_does_not_extend_or_freeze_execution_authority(
    change, scope, now
):
    guard, policy, _, plan, revisions, holds = make_guard(scope, now)
    target = policy.requirements[0].target.scope
    saved = []

    def record(*args):
        saved.append(args[-1].copy())
        if change == "hold":
            holds.open_hold(
                SecurityHold("late-incident", target, "detector", "violation", now)
            )
        elif change == "drift":
            revisions[target] = replace(revisions[target], configuration="9" * 64)
        else:
            guard.clock = lambda: now + timedelta(minutes=4)

    guard.record_assessment = record
    with pytest.raises(ContractError, match="before grant"):
        guard(plan, now)
    assert len(saved) == 1 and saved[0]["accepted"]
    # The stored report described the earlier observation; it is not a permit.
