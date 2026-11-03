"""Real PostgreSQL scheduling race, fencing, RLS and failure visibility."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from sova.adapters.postgres_monitoring import PostgresMonitorRepository
from sova.domain.contracts import ContractError, ResourceScope
from sova.monitoring.contracts import MonitorRegistration
from sova.ports.operations import LeaseLost
from sova.ports.plans import RepositoryConflict

pytestmark = pytest.mark.postgres


@pytest.fixture
def scheduled(postgres_bundle):
    lifecycle = postgres_bundle[0]
    now = datetime.now(UTC)
    r = MonitorRegistration(
        ResourceScope(lifecycle.tenant_id, "app", "test", "api"),
        "watch-api",
        "monitor-service",
        "a" * 64,
        60,
        now - timedelta(seconds=1),
        now + timedelta(hours=1),
    )
    repo = PostgresMonitorRepository(lifecycle)
    repo.register(r)
    return repo, r


def test_monitor_registration_is_immutable_and_tenant_scoped(scheduled):
    repo, r = scheduled
    repo.register(r)
    with pytest.raises(RepositoryConflict):
        repo.register(replace(r, baseline_digest="b" * 64))
    with pytest.raises(ContractError):
        repo.register(replace(r, scope=replace(r.scope, tenant_id="other")))


def test_concurrent_ticks_only_one_claim_and_completion_prevents_immediate_repeat(
    scheduled,
):
    repo, r = scheduled
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(pool.map(lambda owner: repo.claim(r, owner), ("one", "two")))
    assert sum(c is not None for c in claims) == 1
    claim = next(c for c in claims if c is not None)
    repo.complete(claim, outcome="observed", review_digest="b" * 64)
    assert repo.claim(r, "new") is None
    assert repo.alerts("app") == ()
    with pytest.raises(LeaseLost):
        repo.complete(claim, outcome="observed", review_digest="b" * 64)


def test_failed_tick_survives_repository_restart_as_single_redacted_alert(scheduled):
    repo, r = scheduled
    claim = repo.claim(r, "one")
    repo.complete(claim, outcome="failed", review_digest=None)
    restarted = PostgresMonitorRepository(repo.lifecycle)
    alerts = restarted.alerts("app")
    assert len(alerts) == 1 and alerts[0]["category"] == "monitor_failed"
    assert set(alerts[0]) == {
        "alert_id",
        "job_id",
        "run_id",
        "category",
        "created_at",
        "delivered_at",
    }
    assert alerts[0]["delivered_at"] is None


def test_expired_owner_cannot_complete_and_new_owner_records_abandonment(scheduled):
    repo, r = scheduled
    old = repo.claim(r, "old")
    with repo.lifecycle.transaction() as conn:
        conn.execute(
            "UPDATE sova_control.monitor_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=%s",
            (r.job_id,),
        )
    new = repo.claim(r, "new")
    assert new.run_id != old.run_id
    with pytest.raises(LeaseLost):
        repo.complete(old, outcome="observed", review_digest="b" * 64)
    repo.complete(new, outcome="attention", review_digest="c" * 64)
    assert {a["category"] for a in repo.alerts("app")} == {
        "monitor_abandoned",
        "security_attention",
    }


def test_disabled_job_cannot_finish_or_claim(scheduled):
    repo, r = scheduled
    claim = repo.claim(r, "one")
    repo.disable("app", r.job_id, expected_digest=r.fingerprint)
    assert repo.claim(r, "two") is None
    with pytest.raises(LeaseLost):
        repo.complete(claim, outcome="observed", review_digest="b" * 64)


def test_another_tenant_has_no_monitor_or_alert_access(scheduled):
    repo, r = scheduled
    claim = repo.claim(r, "one")
    repo.complete(claim, outcome="failed", review_digest=None)
    from sova.adapters.postgres_plans import PostgresLifecycleRepository

    other = PostgresMonitorRepository(
        PostgresLifecycleRepository(repo.lifecycle.connect, tenant_id="other-tenant")
    )
    assert other.alerts("app") == ()
    with other.lifecycle.transaction() as conn:
        for table in ("monitor_jobs", "monitor_runs", "monitor_alerts"):
            assert (
                conn.execute("SELECT count(*) FROM sova_control." + table).fetchone()[0]
                == 0
            )


def test_invalid_completion_cannot_claim_clean_result(scheduled):
    repo, r = scheduled
    claim = repo.claim(r, "one")
    with pytest.raises(ContractError):
        repo.complete(claim, outcome="observed", review_digest=None)
    with pytest.raises(ContractError):
        repo.complete(claim, outcome="failed", review_digest="a" * 64)
    repo.complete(claim, outcome="failed", review_digest=None)


def test_alert_relay_requires_matching_receipt_and_does_not_drop_lost_delivery(
    scheduled,
):
    from sova.monitoring.alerts import MonitorAlertRelay
    from sova.monitoring.contracts import AlertReceipt

    repo, r = scheduled
    repo.complete(repo.claim(r, "monitor"), outcome="failed", review_digest=None)
    sent = []

    class Sink:
        sink_id = "console"

        def deliver(self, event):
            sent.append(event)
            return AlertReceipt(event["alert_id"], self.sink_id, "local-ack")

    relay = MonitorAlertRelay(repository=repo, sink=Sink(), authorize=lambda *_: True)
    receipt = relay.deliver_one("dispatcher", "app", "relay-one")
    assert receipt.alert_id == sent[0]["alert_id"]
    assert "lease_token" not in sent[0] and "owner_id" not in sent[0]
    assert repo.alerts("app")[0]["delivered_at"] is not None
    assert relay.deliver_one("dispatcher", "app", "relay-two") is None


def test_alert_delivery_unknown_outcome_reuses_stable_id_after_lease_expires(scheduled):
    from sova.monitoring.alerts import MonitorAlertRelay

    repo, r = scheduled
    repo.complete(repo.claim(r, "monitor"), outcome="failed", review_digest=None)

    class Sink:
        sink_id = "console"

        def deliver(self, event):
            raise TimeoutError("synthetic response loss")

    relay = MonitorAlertRelay(repository=repo, sink=Sink(), authorize=lambda *_: True)
    with pytest.raises(TimeoutError):
        relay.deliver_one("dispatcher", "app", "old")
    assert repo.claim_alert("app", "new") is None
    alert = repo.alerts("app")[0]
    with repo.lifecycle.transaction() as conn:
        conn.execute(
            "UPDATE sova_control.monitor_alerts SET lease_until=clock_timestamp()-interval '1 second'"
        )
    claim = repo.claim_alert("app", "new")
    assert claim.alert_id == alert["alert_id"]
    assert repo.alerts("app")[0]["delivered_at"] is None


def test_parallel_alert_delivery_claims_are_exclusive_and_wrong_receipt_not_acknowledged(
    scheduled,
):
    from sova.monitoring.contracts import AlertReceipt

    repo, r = scheduled
    repo.complete(repo.claim(r, "monitor"), outcome="failed", review_digest=None)
    with ThreadPoolExecutor(max_workers=2) as pool:
        claims = list(
            pool.map(lambda owner: repo.claim_alert("app", owner), ("one", "two"))
        )
    claim = next(c for c in claims if c is not None)
    assert sum(c is not None for c in claims) == 1
    with pytest.raises(ContractError):
        repo.acknowledge_alert(claim, AlertReceipt("other-alert", "console", "ack"))
    repo.acknowledge_alert(claim, AlertReceipt(claim.alert_id, "console", "ack"))
    with pytest.raises(LeaseLost):
        repo.acknowledge_alert(claim, AlertReceipt(claim.alert_id, "console", "ack"))
