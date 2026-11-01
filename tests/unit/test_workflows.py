from dataclasses import replace
from datetime import timedelta

import pytest

from sova.domain.contracts import ContractError
from sova.domain.workflows import (
    OperationState,
    OperationStatus as S,
    validate_step_transition,
)


@pytest.fixture
def state(scope, now):
    return OperationState(scope, "operation", "a" * 64, S.REGISTERED, 1, now)


def test_state_is_revisioned_without_mutating_prior_history(state, now):
    following = state.advance(S.ASSESSING, expected_revision=1, now=now)
    assert state.status == S.REGISTERED and state.revision == 1
    assert following.status == S.ASSESSING and following.revision == 2


@pytest.mark.parametrize("status", [S.FENCING, S.SWITCHING, S.VERIFYING, S.STABILIZING])
@pytest.mark.parametrize("target", [S.FAILED, S.CANCELLED, S.BLOCKED])
def test_post_fence_failure_requires_recovery_record(state, now, status, target):
    state = replace(state, status=status)
    with pytest.raises(ContractError, match="transition"):
        state.advance(target, expected_revision=state.revision, now=now)
    recovery = state.advance(S.RECOVERY_REQUIRED, expected_revision=1, now=now)
    assert recovery.status == S.RECOVERY_REQUIRED


def test_cannot_skip_rehearsal_and_approval(state, now):
    with pytest.raises(ContractError):
        state.advance(S.SWITCHING, expected_revision=1, now=now)


def test_stale_revision_and_time_do_not_change_state(state, now):
    with pytest.raises(ContractError, match="revision"):
        state.advance(S.ASSESSING, expected_revision=2, now=now)
    with pytest.raises(ContractError, match="backwards"):
        state.advance(S.ASSESSING, expected_revision=1, now=now - timedelta(seconds=1))


def test_security_hold_does_not_prevent_recording_recovery_requirement(state, now):
    held = replace(state, status=S.SWITCHING, security_hold=True)
    with pytest.raises(ContractError, match="hold"):
        held.advance(S.VERIFYING, expected_revision=1, now=now)
    recovery = held.advance(S.RECOVERY_REQUIRED, expected_revision=1, now=now)
    assert recovery.security_hold
    with pytest.raises(ContractError, match="hold"):
        recovery.advance(S.RECOVERING, expected_revision=2, now=now)


@pytest.mark.parametrize("state", ["succeeded", "failed", "blocked", "needs_attention"])
def test_finished_preview_step_cannot_be_replayed(state):
    with pytest.raises(ContractError):
        validate_step_transition(state, "running")


def test_successful_steps_cannot_be_rewritten_as_failed():
    with pytest.raises(ContractError):
        validate_step_transition("succeeded", "failed")
