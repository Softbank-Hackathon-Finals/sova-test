from dataclasses import asdict, replace
from datetime import timedelta

import pytest

from sova.domain.contracts import ContractError
from sova.domain.telemetry import normalize_http_span, observation_window


@pytest.fixture
def sample(scope, now):
    def make(**changes):
        end = int((now - timedelta(seconds=1)).timestamp() * 10**9)
        raw = {
            "trace_id": "1" * 32,
            "span_id": "2" * 16,
            "start_ns": end - 100000000,
            "end_ns": end,
            "attributes": {
                "http.route": "/rooms/{room_id}/messages",
                "http.response.status_code": 200,
                "db.statement": "sensitive SQL",
                "authorization": "secret token",
                "gen_ai.input.messages": "private prompt",
                "sova.tenant.id": "attacker",
            },
        }
        raw.update(changes)
        return normalize_http_span(
            raw,
            scope=scope,
            deployment_digest="a" * 64,
            allowed_routes=("/rooms/{room_id}/messages",),
        )

    return make


def window(spans, scope, now, **changes):
    args = dict(
        scope=scope,
        deployment_digest="a" * 64,
        start=now - timedelta(minutes=1),
        end=now,
        observed_at=now,
        valid_until=now + timedelta(minutes=1),
        now=now,
    )
    args.update(changes)
    return observation_window(spans, **args)


def test_only_allowlisted_non_sensitive_fields_survive(sample, scope):
    result = asdict(sample())
    assert result["scope"]["tenant_id"] == scope.tenant_id
    assert all(
        text not in repr(result)
        for text in ("sensitive SQL", "secret token", "private prompt", "attacker")
    )


def test_duplicate_delivery_does_not_inflate_request_count(sample, scope, now):
    span = sample()
    result = window((span, span), scope, now)
    assert result["observed_requests"] == 1 and result["observed_p95_ms"] == 100
    assert not result["execution_authorized"]


def test_conflicting_duplicate_and_other_deployment_rejected(sample, scope, now):
    span = sample()
    with pytest.raises(ContractError, match="Conflicting"):
        window((span, replace(span, http_status=500)), scope, now)
    with pytest.raises(ContractError, match="Cross-scope"):
        window((replace(span, deployment_digest="b" * 64),), scope, now)


def test_reported_loss_empty_or_expired_window_cannot_qualify(sample, scope, now):
    assert not window((sample(),), scope, now, dropped_count=1)["sample_usable"]
    assert not window((), scope, now)["sample_usable"]
    with pytest.raises(ContractError):
        window((sample(),), scope, now, valid_until=now)


def test_scope_and_unregistered_raw_route_cannot_be_spoofed(sample, scope, now):
    span = sample()
    with pytest.raises(ContractError, match="Cross-scope"):
        window((replace(span, scope=replace(scope, tenant_id="other")),), scope, now)
    with pytest.raises(ContractError, match="route"):
        sample(
            attributes={
                "http.route": "/rooms/private-customer-id/messages",
                "http.response.status_code": 200,
            }
        )


@pytest.mark.parametrize(
    "change",
    [{"trace_id": "0" * 32}, {"span_id": "bad"}, {"end_ns": 1}, {"start_ns": True}],
)
def test_invalid_span_identity_or_time_rejected(sample, change):
    with pytest.raises(ContractError):
        sample(**change)


def test_missing_collector_loss_evidence_is_not_a_zero_loss_assertion(
    sample, scope, now
):
    missing = window((sample(),), scope, now)
    assert (
        missing["dropped_count"] is None and not missing["loss_observation_available"]
    )
    assert not missing["no_reported_loss"] and not missing["sample_usable"]
    known = window((sample(),), scope, now, dropped_count=0)
    assert known["loss_observation_available"] and known["sample_usable"]
