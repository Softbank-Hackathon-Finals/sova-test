from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import pytest

from sova.application.ai_gateway import AIGateway
from sova.domain.ai_residency import (
    AIEndpointFacts,
    AIResidencyPolicy,
    DataClass,
    DataPhase,
    LocationRule,
    assess_ai_route,
)
from sova.domain.contracts import ContractError


@pytest.fixture
def ai(scope, now):
    rules = tuple(LocationRule(phase, ("customer-jp",)) for phase in DataPhase)
    policy = AIResidencyPolicy(
        scope,
        "confidential-summary",
        1,
        DataClass.CONFIDENTIAL,
        ("summary",),
        ("local-model",),
        rules,
        now - timedelta(minutes=1),
        now + timedelta(minutes=5),
    )
    endpoint = AIEndpointFacts(
        scope,
        "local-model",
        "deployment-1",
        "customer-runtime",
        ("chat",),
        rules,
        now - timedelta(seconds=1),
        now + timedelta(minutes=3),
    )

    def assess(**changes):
        args = dict(
            scope=scope,
            data_class=DataClass.CONFIDENTIAL,
            purpose="summary",
            capability="chat",
            input_bytes=128,
            now=now,
        )
        args.update(changes)
        return assess_ai_route(policy, endpoint, **args)

    return policy, endpoint, assess


def gateway(ai, scope, now, **changes):
    policy, endpoint, _ = ai
    args = dict(
        policy_provider=Mock(return_value=policy),
        endpoint_provider=Mock(return_value=endpoint),
        classify=Mock(return_value=DataClass.CONFIDENTIAL),
        authorize=Mock(return_value=None),
        authenticate_policy=Mock(return_value=None),
        authenticate_endpoint=Mock(return_value=None),
        invoke=Mock(return_value="요약 결과"),
        clock=lambda: now,
    )
    args.update(changes)
    return AIGateway(**args)


def invoke(service, ai, scope, **changes):
    policy, endpoint, _ = ai
    args = dict(
        scope=scope,
        request_id="request-1",
        endpoint_id=endpoint.endpoint_id,
        expected_deployment=endpoint.deployment_revision,
        expected_policy_digest=policy.fingerprint,
        purpose="summary",
        capability="chat",
        payload="계좌번호가 포함된 합성 상담 내용",
    )
    args.update(changes)
    return service.complete("operator", **args)


def test_valid_local_endpoint_is_not_an_implicit_fallback(ai):
    assert ai[2]()["allowed"] and not ai[2]()["automatic_fallback"]


@pytest.mark.parametrize("phase", list(DataPhase))
def test_each_forbidden_location_is_denied_independently(ai, scope, now, phase):
    policy, endpoint, _ = ai
    endpoint = replace(
        endpoint,
        rules=tuple(
            LocationRule(r.phase, ("external-region",)) if r.phase == phase else r
            for r in endpoint.rules
        ),
    )
    result = assess_ai_route(
        policy,
        endpoint,
        scope=scope,
        data_class=DataClass.CONFIDENTIAL,
        purpose="summary",
        capability="chat",
        input_bytes=128,
        now=now,
    )
    assert not result["allowed"] and f"forbidden-{phase}-location" in result["reasons"]


@pytest.mark.parametrize(
    "change",
    [
        {"data_class": DataClass.PUBLIC},
        {"purpose": "unapproved"},
        {"capability": "tools"},
        {"input_bytes": 10**9},
    ],
)
def test_classification_purpose_features_and_limits_are_enforced(ai, change):
    assert not ai[2](**change)["allowed"]


def test_missing_data_phase_and_unknown_processing_location_rejected(ai):
    _, endpoint, _ = ai
    with pytest.raises(ContractError, match="Every data phase"):
        replace(endpoint, rules=endpoint.rules[:-1])
    with pytest.raises(ContractError, match="Processing"):
        replace(
            endpoint,
            rules=tuple(
                LocationRule(r.phase, ()) if r.phase == DataPhase.PROCESSING else r
                for r in endpoint.rules
            ),
        )


def test_gateway_uses_server_classification_and_omits_sensitive_receipts(
    ai, scope, now
):
    service = gateway(ai, scope, now)
    result = invoke(service, ai, scope)
    assert result["response"] == "요약 결과"
    assert "계좌번호" not in repr(result["receipt"])
    assert (
        "payload" not in result["receipt"] and "content_hash" not in result["receipt"]
    )
    assert service.invoke.call_count == 1 and service.authorize.call_count == 2


def test_denied_location_never_calls_model(ai, scope, now):
    policy, endpoint, _ = ai
    endpoint = replace(
        endpoint, rules=tuple(LocationRule(p, ("external",)) for p in DataPhase)
    )
    service = gateway(ai, scope, now, endpoint_provider=Mock(return_value=endpoint))
    with pytest.raises(ContractError, match="denied"):
        invoke(service, ai, scope)
    service.invoke.assert_not_called()


def test_policy_change_during_admission_blocks_dispatch(ai, scope, now):
    policy, _, _ = ai
    service = gateway(
        ai,
        scope,
        now,
        policy_provider=Mock(side_effect=[policy, replace(policy, revision=2)]),
    )
    with pytest.raises(ContractError, match="changed during"):
        invoke(service, ai, scope)
    service.invoke.assert_not_called()


def test_expiry_or_clock_rollback_during_authorization_blocks_dispatch(ai, scope, now):
    for final in (now + timedelta(hours=1), now - timedelta(seconds=1)):
        service = gateway(ai, scope, now, clock=Mock(side_effect=[now, final]))
        with pytest.raises(ContractError):
            invoke(service, ai, scope)
        service.invoke.assert_not_called()


def test_uncertain_model_response_never_retries_or_falls_back(ai, scope, now):
    service = gateway(
        ai, scope, now, invoke=Mock(side_effect=TimeoutError("uncertain"))
    )
    with pytest.raises(TimeoutError):
        invoke(service, ai, scope)
    assert service.invoke.call_count == 1


def test_unauthorized_actor_cannot_read_policy_or_classify(ai, scope, now):
    service = gateway(
        ai, scope, now, authorize=Mock(side_effect=ContractError("denied"))
    )
    with pytest.raises(ContractError):
        invoke(service, ai, scope)
    service.classify.assert_not_called()
    service.policy_provider.assert_not_called()
    service.invoke.assert_not_called()


def test_gateway_binds_requested_endpoint_id_even_when_registry_returns_an_allowed_other_id(
    ai, scope, now
):
    service = gateway(ai, scope, now)
    with pytest.raises(ContractError, match="changed"):
        invoke(service, ai, scope, endpoint_id="different-endpoint")
    service.invoke.assert_not_called()
