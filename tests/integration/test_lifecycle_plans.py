import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest

from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.plans import ApprovedPlanExecutor
from sova.domain.contracts import ContractError, EffectStatus
from sova.domain.evidence import (
    EvidenceRecord,
    Gate,
    RevisionSet,
    VerificationObligation,
    VerificationResult as R,
)
from sova.domain.plans import (
    Inspection,
    LifecyclePlan,
    PlanApproval,
    PlanPurpose as P,
    PlanStep,
)


@pytest.fixture
def bundle(scope, now):
    revisions = RevisionSet("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    obligation = VerificationObligation("owned-resource", scope, Gate.PREFLIGHT, "v1")
    step = PlanStep(
        "isolate",
        scope,
        "test-ingress",
        "set_ingress",
        '{"blocked":true}',
        "revision-1",
    )
    plan = LifecyclePlan(
        "plan-1",
        scope.tenant_id,
        scope.application_id,
        "author",
        P.CHANGE,
        revisions,
        now + timedelta(minutes=5),
        (step,),
        (obligation,),
    )
    approval = PlanApproval(plan.fingerprint, "approver", P.CHANGE, plan.valid_until)
    evidence = EvidenceRecord(
        "e1",
        obligation.obligation_id,
        scope,
        revisions,
        "v1",
        now - timedelta(seconds=1),
        now + timedelta(minutes=1),
        R.PASS,
        "artifact",
        "e" * 64,
    )
    return plan, approval, evidence, obligation


@pytest.fixture
def executor(tmp_path, bundle, now):
    connection = sqlite3.connect(tmp_path / "plans.sqlite")
    journal = SQLiteEffectJournal(connection)
    effects = EffectExecutor(journal, authorize=lambda *_: None, clock=lambda: now)
    instance = ApprovedPlanExecutor(
        effects,
        required_obligations=lambda _: (bundle[3],),
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    yield instance
    connection.close()


def run(executor, bundle, adapter, *, step="isolate"):
    plan, approval, evidence, _ = bundle
    return executor.execute_step(
        plan,
        approval,
        step,
        operation_id="operation-1",
        epoch=1,
        evidence=(evidence,),
        adapter=adapter,
    )


def test_approved_plan_materializes_the_exact_command(executor, bundle, adapter):
    result = run(executor, bundle, adapter)
    assert result.status == EffectStatus.APPLIED
    assert result.command.plan_digest == bundle[0].fingerprint
    assert len(adapter.calls) == 1


@pytest.mark.parametrize("change", ["parameters", "purpose", "revision", "reason"])
def test_plan_change_invalidates_existing_approval(executor, bundle, adapter, change):
    plan, approval, evidence, obligation = bundle
    if change == "parameters":
        plan = replace(
            plan, steps=(replace(plan.steps[0], parameters_json='{"blocked":false}'),)
        )
    elif change == "purpose":
        plan = replace(
            plan, purpose=P.RECOVERY, origin_plan_digest="f" * 64, reason="recover"
        )
    elif change == "revision":
        plan = replace(plan, revisions=replace(plan.revisions, source="f" * 64))
    else:
        plan = replace(plan, reason="changed rationale")
    with pytest.raises(ContractError, match="Approval"):
        run(executor, (plan, approval, evidence, obligation), adapter)
    assert adapter.calls == []


def test_self_approval_and_expiry_are_rejected(executor, bundle, adapter, now):
    plan, approval, evidence, obligation = bundle
    for invalid in [
        replace(approval, approved_by=plan.created_by),
        replace(approval, valid_until=now),
    ]:
        with pytest.raises(ContractError):
            run(executor, (plan, invalid, evidence, obligation), adapter)
    assert not adapter.calls


def test_unknown_failed_and_stale_evidence_cannot_execute(
    executor, bundle, adapter, now
):
    plan, approval, evidence, obligation = bundle
    for invalid in [
        replace(evidence, result=R.FAIL),
        replace(evidence, result=R.UNKNOWN),
        replace(evidence, valid_until=now),
    ]:
        with pytest.raises(ContractError, match="verification"):
            run(executor, (plan, approval, invalid, obligation), adapter)
    assert not adapter.calls


def test_plan_cannot_weaken_mandatory_policy_obligation(executor, bundle, adapter):
    plan, _, evidence, obligation = bundle
    weakened = replace(obligation, required=False, due_gate=Gate.POSTFLIGHT)
    plan = replace(plan, obligations=(weakened,))
    approval = PlanApproval(
        plan.fingerprint, "approver", plan.purpose, plan.valid_until
    )
    with pytest.raises(ContractError, match="weakened"):
        run(executor, (plan, approval, evidence, obligation), adapter)
    assert not adapter.calls


def test_empty_trusted_policy_is_not_implicit_permission(executor, bundle, adapter):
    executor.required_obligations = lambda _: ()
    with pytest.raises(ContractError, match="Policy"):
        run(executor, bundle, adapter)
    assert not adapter.calls


def test_dependency_must_be_confirmed_before_next_effect(executor, bundle, adapter):
    plan, _, evidence, obligation = bundle
    second = replace(
        plan.steps[0],
        step_id="restore",
        parameters_json='{"blocked":false}',
        depends_on=("isolate",),
    )
    plan = replace(plan, steps=(*plan.steps, second))
    approval = PlanApproval(plan.fingerprint, "approver", P.CHANGE, plan.valid_until)
    values = (plan, approval, evidence, obligation)
    with pytest.raises(RuntimeError):
        run(executor, values, adapter, step="restore")
    assert not adapter.calls
    run(executor, values, adapter)
    run(executor, values, adapter, step="restore")
    assert len(adapter.calls) == 2 and not adapter.blocked


def test_revocation_after_claim_is_rechecked_before_apply(executor, bundle, adapter):
    calls = 0

    def revoke(*_):
        nonlocal calls
        calls += 1
        if calls == 3:
            raise ContractError("approval revoked")

    executor.authenticate_approval = revoke
    with pytest.raises(ContractError, match="revoked"):
        run(executor, bundle, adapter)
    command = bundle[0].command("isolate", operation_id="operation-1", epoch=1)
    assert executor.effects.journal.get(command).status == EffectStatus.NOT_APPLIED
    assert not adapter.calls


def test_untrusted_evidence_issuer_is_rejected(executor, bundle, adapter):
    def untrusted(_):
        raise ContractError("untrusted evidence")

    executor.authenticate_evidence = untrusted
    with pytest.raises(ContractError, match="untrusted"):
        run(executor, bundle, adapter)
    assert not adapter.calls


@pytest.mark.parametrize("purpose", [P.RECOVERY, P.FINALIZATION])
def test_recovery_and_finalization_require_their_own_approval(
    executor, bundle, adapter, purpose
):
    original, old_approval, evidence, obligation = bundle
    plan = replace(
        original,
        plan_id="new-plan",
        purpose=purpose,
        origin_plan_digest=original.fingerprint,
        reason="reviewed recovery/cleanup",
    )
    with pytest.raises(ContractError):
        run(executor, (plan, old_approval, evidence, obligation), adapter)
    approval = PlanApproval(plan.fingerprint, "approver", purpose, plan.valid_until)
    assert (
        run(executor, (plan, approval, evidence, obligation), adapter).status
        == EffectStatus.APPLIED
    )


def test_invalid_dag_and_cross_tenant_steps_are_rejected(bundle):
    plan, _, _, _ = bundle
    with pytest.raises(ContractError):
        replace(plan, steps=(replace(plan.steps[0], depends_on=("isolate",)),))
    with pytest.raises(ContractError):
        replace(plan, steps=(plan.steps[0], plan.steps[0]))
    with pytest.raises(ContractError):
        replace(
            plan,
            steps=(
                replace(
                    plan.steps[0], scope=replace(plan.steps[0].scope, tenant_id="other")
                ),
            ),
        )


def test_recovery_without_origin_and_reason_is_rejected(bundle):
    with pytest.raises(ContractError):
        replace(bundle[0], purpose=P.RECOVERY)


def test_inspection_has_explicit_validity_and_detached_facts(bundle, now):
    plan, _, evidence, _ = bundle
    inspection = Inspection(
        plan.steps[0].scope,
        plan.revisions,
        now,
        plan.valid_until,
        '{"revision":1}',
        evidence.artifact_digest,
    )
    inspection.require_current(now)
    with pytest.raises(ContractError):
        inspection.require_current(plan.valid_until)
    with pytest.raises(ContractError):
        inspection.require_current(now - timedelta(seconds=1))


def test_evidence_expiring_during_authorization_cannot_dispatch(
    executor, bundle, adapter, now
):
    clock = [now]
    executor.clock = lambda: clock[0]
    checks = 0

    def slow_auth(*_):
        nonlocal checks
        checks += 1
        if checks == 3:
            clock[0] = bundle[2].valid_until

    executor.authenticate_approval = slow_auth
    with pytest.raises(ContractError, match="expired"):
        run(executor, bundle, adapter)
    command = bundle[0].command("isolate", operation_id="operation-1", epoch=1)
    assert not adapter.calls
    assert executor.effects.journal.get(command).status == EffectStatus.NOT_APPLIED
