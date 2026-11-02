from dataclasses import replace
from datetime import timedelta

import pytest
from governance_support import bundle, release_bundle, MemoryHolds
from sova.domain.contracts import ContractError
from sova.domain.evidence import VerificationResult, Gate
from sova.domain.governance import GovernancePolicy, SecurityControl, assess_governance
from sova.application.governance import GovernanceGuard, SecurityHoldService


def test_pass_bound_to_scope_revision_and_trusted_control(scope, now):
    policy, plan, _, evidence, _ = bundle(scope, now)
    report = assess_governance(policy, (evidence,), plan.revisions, now=now)
    assert report["accepted"]
    assert report["controls"][0]["state"] == "satisfied"
    assert report["policy_digest"] == policy.fingerprint


@pytest.mark.parametrize(
    "case",
    [
        "missing",
        "expired",
        "future",
        "failed",
        "unknown",
        "not-applicable",
        "wrong-scope",
        "wrong-revision",
        "wrong-verifier",
        "ambiguous",
    ],
)
def test_security_unknown_is_never_implicit_permission(case, scope, now):
    policy, plan, _, evidence, _ = bundle(scope, now)
    if case == "expired":
        evidence = replace(
            evidence, observed_at=now - timedelta(minutes=1), valid_until=now
        )
    if case == "future":
        evidence = replace(evidence, observed_at=now + timedelta(seconds=1))
    if case == "failed":
        evidence = replace(evidence, result=VerificationResult.FAIL)
    if case == "unknown":
        evidence = replace(evidence, result=VerificationResult.UNKNOWN)
    if case == "not-applicable":
        evidence = replace(
            evidence,
            result=VerificationResult.NOT_APPLICABLE,
            justification="skip",
            approved_by="ordinary-deployer",
        )
    if case == "wrong-scope":
        evidence = replace(evidence, scope=replace(scope, application_id="other"))
    if case == "wrong-revision":
        evidence = replace(
            evidence, revisions=replace(evidence.revisions, environment="f" * 64)
        )
    if case == "wrong-verifier":
        evidence = replace(evidence, verifier_version="different")
    records = () if case == "missing" else (evidence,)
    if case == "ambiguous":
        records += (replace(evidence, evidence_id="same-time"),)
    report = assess_governance(policy, records, plan.revisions, now=now)
    assert not report["accepted"]
    assert report["controls"][0]["state"] == (
        "violated" if case == "failed" else "unknown"
    )


def test_newer_failed_evidence_overrides_old_pass(scope, now):
    policy, plan, _, evidence, _ = bundle(scope, now)
    failed = replace(
        evidence,
        evidence_id="newer",
        observed_at=now + timedelta(seconds=1),
        result=VerificationResult.FAIL,
    )
    assert not assess_governance(
        policy, (evidence, failed), plan.revisions, now=failed.observed_at
    )["accepted"]


def test_policy_cannot_be_weakened_or_reused_with_old_revision(scope, now):
    policy, plan, _, evidence, _ = bundle(scope, now)
    with pytest.raises(ContractError):
        GovernancePolicy(
            policy.tenant_id, policy.application_id, 1, (), now, policy.valid_until
        )
    with pytest.raises(ContractError):
        SecurityControl(
            policy.controls[0].family,
            replace(policy.controls[0].obligation, required=False),
        )
    with pytest.raises(ContractError):
        SecurityControl(
            policy.controls[0].family,
            replace(policy.controls[0].obligation, due_gate=Gate.POSTFLIGHT),
        )
    with pytest.raises(ContractError):
        assess_governance(
            replace(policy, revision=2), (evidence,), plan.revisions, now=now
        )
    with pytest.raises(ContractError):
        assess_governance(policy, (evidence,), plan.revisions, now=policy.valid_until)


def guard_fixture(scope, now):
    policy, plan, approval, evidence, hold = bundle(scope, now)
    repo = MemoryHolds(scope.tenant_id, now)
    guard = GovernanceGuard(
        repo,
        policy_provider=lambda _: policy,
        evidence_provider=lambda _: (evidence,),
        authenticate_policy=lambda _: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    return guard, repo, policy, plan, approval, evidence, hold


def test_hold_is_app_wide_not_cleared_by_evidence_or_plan_approval(scope, now):
    guard, repo, _, plan, _, _, hold = guard_fixture(scope, now)
    assert guard.assess(plan, now)["accepted"]
    repo.open_hold(
        replace(hold, scope=replace(scope, environment_id="other-environment"))
    )
    report = guard.assess(plan, now)
    assert report["controls"][0]["state"] == "satisfied"
    assert not report["accepted"] and report["active_holds"] == [hold.hold_id]
    with pytest.raises(ContractError):
        guard(plan, now)


def test_missing_policy_or_uncontrolled_plan_resource_blocks(scope, now):
    guard, _, _, plan, _, _, _ = guard_fixture(scope, now)
    changed = replace(
        plan,
        steps=(replace(plan.steps[0], scope=replace(scope, resource_id="uncovered")),),
    )
    with pytest.raises(ContractError):
        guard(changed, now)
    changed = replace(plan, obligations=(replace(plan.obligations[0], required=False),))
    with pytest.raises(ContractError):
        guard(changed, now)

    def unavailable(_):
        raise RuntimeError("Policy service unavailable")

    guard.policy_provider = unavailable
    with pytest.raises(RuntimeError):
        guard(plan, now)


def release_service(repo, revisions, now, authorize=lambda *args: None):
    return SecurityHoldService(
        repo,
        authorize=authorize,
        authenticate_release=lambda _: None,
        authenticate_evidence=lambda _: None,
        current_revisions=lambda _: revisions,
        clock=lambda: now,
    )


def test_release_requires_separate_security_authorities(scope, now):
    _, plan, _, _, hold = bundle(scope, now)
    repo = MemoryHolds(scope.tenant_id, now)
    calls = []
    service = release_service(
        repo, plan.revisions, now, lambda *args: calls.append(args)
    )
    service.open(hold.raised_by, hold)
    request, evidence = release_bundle(hold, plan.revisions, now)
    released = service.release(
        request.requested_by, scope.application_id, request, evidence
    )
    assert not released.active and repo.active_holds(scope.application_id) == ()
    assert [c[2] for c in calls] == [
        "security:hold",
        "security:release-request",
        "security:release-approve",
    ]


@pytest.mark.parametrize(
    "case",
    [
        "self-approval",
        "raiser-approval",
        "wrong-scope",
        "wrong-revision",
        "wrong-evidence",
        "stale-evidence",
        "failed-evidence",
        "not-applicable",
        "expired-approval",
        "other-actor",
        "wrong-obligation",
        "pre-incident-evidence",
    ],
)
def test_invalid_hold_release_keeps_active(case, scope, now):
    _, plan, _, _, hold = bundle(scope, now)
    repo = MemoryHolds(scope.tenant_id, now)
    repo.open_hold(hold)
    service = release_service(repo, plan.revisions, now)
    request, evidence = release_bundle(hold, plan.revisions, now)
    with pytest.raises(ContractError):
        if case == "self-approval":
            request = replace(request, approved_by=request.requested_by)
        if case == "raiser-approval":
            request = replace(request, approved_by=hold.raised_by)
        if case == "wrong-scope":
            request = replace(request, scope=replace(scope, application_id="other"))
        if case == "wrong-revision":
            request = replace(
                request, revisions=replace(plan.revisions, environment="f" * 64)
            )
        if case == "wrong-evidence":
            evidence = replace(evidence, artifact_digest="0" * 64)
        if case == "stale-evidence":
            evidence = replace(evidence, observed_at=hold.raised_at, valid_until=now)
        if case == "failed-evidence":
            evidence = replace(evidence, result=VerificationResult.FAIL)
        if case == "not-applicable":
            evidence = replace(
                evidence,
                result=VerificationResult.NOT_APPLICABLE,
                justification="skip",
                approved_by="actor",
            )
        if case == "expired-approval":
            request = replace(request, approved_at=hold.raised_at, valid_until=now)
        if case == "wrong-obligation":
            evidence = replace(evidence, obligation_id="ordinary-deploy")
        if case == "pre-incident-evidence":
            evidence = replace(
                evidence, observed_at=hold.raised_at - timedelta(seconds=1)
            )
        service.release(
            "other" if case == "other-actor" else request.requested_by,
            scope.application_id,
            request,
            evidence,
        )
    assert repo.active_holds(scope.application_id)


def test_evidence_expiring_during_authority_lookup_is_rechecked(scope, now):
    guard, _, _, plan, _, evidence, _ = guard_fixture(scope, now)
    time = [now]

    def slow_lookup(_):
        time[0] = evidence.valid_until
        return (evidence,)

    guard.evidence_provider = slow_lookup
    guard.clock = lambda: time[0]
    assert not guard.assess(plan, now)["accepted"]


def test_hold_opened_during_evidence_lookup_is_visible(scope, now):
    guard, repo, _, plan, _, evidence, hold = guard_fixture(scope, now)

    def lookup(_):
        repo.open_hold(hold)
        return (evidence,)

    guard.evidence_provider = lookup
    assert not guard.assess(plan, now)["accepted"]


def test_revision_change_during_release_cannot_reuse_old_approval(scope, now):
    _, plan, _, _, hold = bundle(scope, now)
    repo = MemoryHolds(scope.tenant_id, now)
    repo.open_hold(hold)
    request, evidence = release_bundle(hold, plan.revisions, now)
    new_revisions = replace(plan.revisions, environment="0" * 64)
    evidence = replace(evidence, revisions=new_revisions)
    service = release_service(repo, plan.revisions, now)
    calls = []

    def changing(_):
        calls.append(None)
        return plan.revisions if len(calls) == 1 else new_revisions

    service.current_revisions = changing
    with pytest.raises(ContractError):
        service.release(request.requested_by, scope.application_id, request, evidence)
    assert repo.active_holds(scope.application_id)
