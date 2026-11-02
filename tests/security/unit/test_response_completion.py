"""Stored completion is a historical, scope-bound receipt, never a new permit."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest

from protection_support import protection_bundle
from sova.adapters.response_completion_codec import decode_response_completion
from sova.domain.contracts import ContractError, EffectObservation, EffectStatus
from sova.domain.response_completion import ResponseCompletion


@pytest.fixture
def completion_case(scope, now):
    # The storage codec is independent of the provider. The repository separately
    # requires the security-response profile and all four exact effect receipts.
    plan = protection_bundle(scope, now)[2]
    plan = replace(
        plan,
        steps=(replace(plan.steps[0], step_id="switch_route", action="switch_route"),),
    )
    command = plan.command("switch_route", operation_id="response", epoch=3)
    observed = EffectObservation(
        command.scope,
        command.fingerprint,
        EffectStatus.APPLIED,
        now,
        '{"route_revision":4,"request_id":"verified-request"}',
    )
    return plan, ResponseCompletion(
        command, observed, "worker", now + timedelta(seconds=10)
    )


def test_completion_round_trip_preserves_exact_observation_and_epoch(completion_case):
    plan, receipt = completion_case
    restored = decode_response_completion(receipt.document, plan)
    assert restored == receipt and restored.fingerprint == receipt.fingerprint
    assert restored.document["epoch"] == 3
    # It carries no execution token or mutable approval, and cannot itself
    # authorize a later provider call.
    assert "token" not in restored.document


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("epoch", True),
        ("plan_digest", "0" * 64),
        ("command_digest", "0" * 64),
        ("operation_id", "other-operation"),
    ],
)
def test_stored_binding_tampering_is_rejected(completion_case, field, value):
    plan, receipt = completion_case
    data = deepcopy(receipt.document)
    data[field] = value
    with pytest.raises(ContractError):
        decode_response_completion(data, plan)


def test_another_tenant_scope_cannot_reuse_completion(completion_case):
    plan, receipt = completion_case
    data = deepcopy(receipt.document)
    data["scope"]["tenant_id"] = "other-tenant"
    with pytest.raises(ContractError):
        decode_response_completion(data, plan)


@pytest.mark.parametrize("case", ["unknown", "nonfinal", "expired", "outlives-plan"])
def test_incomplete_or_unbounded_readback_cannot_form_receipt(completion_case, case):
    _, receipt = completion_case
    if case == "unknown":
        changes = {
            "observation": replace(receipt.observation, status=EffectStatus.UNKNOWN)
        }
    elif case == "nonfinal":
        changes = {"command": replace(receipt.command, step_id="earlier")}
    elif case == "expired":
        changes = {"verified_until": receipt.observation.observed_at}
    else:
        changes = {"verified_until": receipt.command.expires_at + timedelta(seconds=1)}
    with pytest.raises(ContractError):
        replace(receipt, **changes)


def test_extra_stored_fields_cannot_carry_credentials(completion_case):
    plan, receipt = completion_case
    data = {**receipt.document, "credential": "forbidden"}
    with pytest.raises(ContractError):
        decode_response_completion(data, plan)
