from dataclasses import replace
from datetime import timedelta
import pytest
from security_support import security_snapshot
from governance_support import MemoryHolds
from sova.domain.contracts import ContractError
from sova.domain.governance import SecurityHold
from sova.domain.security_response import (
    StatelessResponseProfile,
    SecurityResponseBinding,
    ACTIONS,
)
from sova.domain.plans import PlanPurpose
from sova.domain.workflows import OperationState, OperationStatus, OperationProfile
from sova.application.security_response import SecurityResponseGuard


def response_bundle(scope, now):
    source = security_snapshot(scope, now)
    target = security_snapshot(replace(scope, environment_id="other-environment"), now)
    profile = StatelessResponseProfile(
        "registered-test",
        "a" * 64,
        "f" * 64,
        True,
        True,
        True,
        "operator",
        now + timedelta(minutes=5),
    )
    hold = SecurityHold(
        "incident", source.graph.resources[0].scope, "detector", "violation", now
    )
    binding = SecurityResponseBinding(
        source,
        target,
        "deployment:api",
        "deployment:api",
        (hold.hold_id,),
        profile,
        "c" * 64,
    )
    plan = binding.compile(
        plan_id="response",
        created_by="planner",
        now=now,
        valid_until=now + timedelta(minutes=2),
    )
    return binding, plan, hold


def test_response_is_exact_distinct_environment_and_restricted_actions(scope, now):
    binding, plan, _ = response_bundle(scope, now)
    assert plan.purpose == PlanPurpose.SECURITY_RESPONSE
    assert tuple(s.action for s in plan.steps) == ACTIONS
    assert plan.steps[0].scope == binding.source_resource.scope
    assert all(s.scope == binding.target_resource.scope for s in plan.steps[1:])
    assert plan.revisions.configuration == binding.fingerprint
    with pytest.raises(ContractError):
        replace(binding, target=binding.source)
    with pytest.raises(ContractError):
        replace(binding, hold_ids=())
    with pytest.raises(ContractError):
        replace(binding.profile, no_durable_state=False)


def test_expired_or_stateful_binding_cannot_compile(scope, now):
    binding, _, _ = response_bundle(scope, now)
    with pytest.raises(ContractError):
        binding.compile(
            plan_id="p",
            created_by="planner",
            now=now,
            valid_until=now + timedelta(hours=1),
        )
    with pytest.raises(ContractError):
        replace(binding, source_node="statefulset:database")


def test_guard_does_not_bypass_new_or_unrelated_holds(scope, now):
    binding, plan, hold = response_bundle(scope, now)
    repo = MemoryHolds(scope.tenant_id, now)
    repo.open_hold(hold)
    guard = SecurityResponseGuard(
        binding,
        repo,
        authorize_profile=lambda *_: None,
        verify_admission=lambda *_: None,
        clock=lambda: now,
    )
    assert guard(plan, now) == plan.valid_until
    repo.open_hold(replace(hold, hold_id="another-incident"))
    with pytest.raises(ContractError):
        guard(plan, now)


def test_ordinary_deployment_cannot_use_response_hold_exception(scope, now):
    binding, plan, hold = response_bundle(scope, now)
    repo = MemoryHolds(scope.tenant_id, now)
    repo.open_hold(hold)
    guard = SecurityResponseGuard(
        binding,
        repo,
        authorize_profile=lambda *_: None,
        verify_admission=lambda *_: None,
        clock=lambda: now,
    )
    with pytest.raises(ContractError):
        guard(replace(plan, purpose=PlanPurpose.CHANGE), now)
    with pytest.raises(ContractError):
        guard(
            replace(
                plan,
                steps=(
                    replace(plan.steps[0], action="delete_everything"),
                    *plan.steps[1:],
                ),
            ),
            now,
        )


def test_response_state_profile_does_not_open_migration_shortcut(scope, now):
    normal = OperationState(scope, "op", "a" * 64, OperationStatus.REGISTERED, 1, now)
    with pytest.raises(ContractError):
        normal.advance(OperationStatus.CONTAINING, expected_revision=1, now=now)
    state = replace(normal, profile=OperationProfile.SECURITY_RESPONSE)
    for target in (
        OperationStatus.CONTAINING,
        OperationStatus.PREPARING_REPLACEMENT,
        OperationStatus.VERIFYING_REPLACEMENT,
        OperationStatus.SWITCHING,
        OperationStatus.VERIFYING,
        OperationStatus.RESPONSE_VERIFIED,
    ):
        state = state.advance(target, expected_revision=state.revision, now=now)
    with pytest.raises(ContractError):
        state.advance(
            OperationStatus.CONTAINING, expected_revision=state.revision, now=now
        )


def test_different_environment_aliases_cannot_move_same_physical_resource(scope, now):
    binding, _, _ = response_bundle(scope, now)
    source = binding.source
    alias_scope = replace(
        source.graph.resources[0].scope, environment_id="alias-environment"
    )
    alias_graph = replace(
        source.graph, resources=(replace(source.graph.resources[0], scope=alias_scope),)
    )
    alias = replace(
        source,
        graph=alias_graph,
        findings=tuple(replace(f, scope=alias_scope) for f in source.findings),
    )
    with pytest.raises(ContractError, match="same physical workload"):
        replace(binding, target=alias)


def test_hold_created_during_admission_lookup_blocks_same_dispatch(scope, now):
    binding, plan, hold = response_bundle(scope, now)
    holds = MemoryHolds(scope.tenant_id, now)
    holds.open_hold(hold)

    def lookup(*_):
        holds.open_hold(
            replace(hold, hold_id="late", scope=binding.target_resource.scope)
        )

    guard = SecurityResponseGuard(
        binding,
        holds,
        authorize_profile=lambda *_: None,
        verify_admission=lookup,
        clock=lambda: now,
    )
    with pytest.raises(ContractError, match="holds changed"):
        guard(plan, now)
