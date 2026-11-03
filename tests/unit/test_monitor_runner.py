"""Scheduling only admits a current, authenticated registered baseline."""

from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
import pytest

from sova.domain.contracts import ContractError
from sova.monitoring.contracts import MonitorRegistration
from sova.monitoring.runner import ScheduledSecurityMonitor
from sova_security.domain.continuous_security import ContinuousSecurityReview


@pytest.fixture
def scheduled(scope, now):
    registration = MonitorRegistration(
        scope, "job", "monitor", "a" * 64, 60, now, now + timedelta(hours=1)
    )
    review = ContinuousSecurityReview(
        scope, "a" * 64, "b" * 64, "c" * 64, (), now, now + timedelta(minutes=1)
    )
    state = {
        "current": registration,
        "trusted": True,
        "allowed": True,
        "reviews": [],
        "outcomes": [],
        "fail": False,
        "after": lambda: None,
    }

    class Repo:
        def claim(self, *args, **kwargs):
            return "opaque-claim"

        def complete(self, claim, **result):
            state["outcomes"].append(result)

    class Monitor:
        def baseline_provider(self, _):
            return SimpleNamespace(fingerprint=registration.baseline_digest)

        def run_once(self, *args, **kwargs):
            if state["fail"]:
                raise RuntimeError("untrusted secret text must not be stored")
            state["after"]()
            return review

    runner = ScheduledSecurityMonitor(
        repository=Repo(),
        current_registration=lambda _: state["current"],
        authenticate_registration=lambda _: state["trusted"],
        authorize=lambda *_: state["allowed"],
        monitor_factory=lambda _: Monitor(),
        clock=lambda: now,
    )
    return runner, registration, state


def test_current_registered_review_is_completed_as_observation(scheduled):
    runner, r, state = scheduled
    assert runner.run_due(r, "worker").triggers == ()
    assert state["outcomes"][0]["outcome"] == "observed"


@pytest.mark.parametrize("case", ["revoked", "changed", "failed"])
def test_late_failure_is_recorded_as_failed_not_healthy(scheduled, case):
    runner, r, state = scheduled
    if case == "revoked":
        state["after"] = lambda: state.update(trusted=False)
    if case == "changed":
        state["after"] = lambda: state.update(
            current=replace(r, baseline_digest="d" * 64)
        )
    if case == "failed":
        state["fail"] = True
    with pytest.raises((ContractError, RuntimeError)):
        runner.run_due(r, "worker")
    assert state["outcomes"] == [{"outcome": "failed", "review_digest": None}]


def test_denial_before_claim_does_not_run_or_record(scheduled):
    runner, r, state = scheduled
    state["allowed"] = False
    with pytest.raises(ContractError):
        runner.run_due(r, "worker")
    assert state["outcomes"] == []
