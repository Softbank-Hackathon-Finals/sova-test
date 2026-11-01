import json
from dataclasses import FrozenInstanceError, replace
from datetime import timedelta

import pytest

from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    EffectObservation,
    EffectStatus,
    ResourceScope,
    canonical_json,
    validate_permit,
)
from support import permit_for


def test_command_round_trip_has_stable_fingerprint(command):
    recovered = EffectCommand.from_document(json.loads(json.dumps(command.document)))
    assert recovered == command
    assert recovered.fingerprint == command.fingerprint


def test_command_is_immutable_and_payload_is_detached(command):
    original = command.fingerprint
    command.parameters["blocked"] = False
    assert command.parameters == {"blocked": True}
    assert command.fingerprint == original
    with pytest.raises(FrozenInstanceError):
        command.action = "run-shell"


def test_json_order_does_not_change_command_approval(command):
    one = replace(command, parameters_json='{"b":false,"a":true}')
    two = replace(command, parameters_json='{"a":true, "b":false}')
    assert one.fingerprint == two.fingerprint


@pytest.mark.parametrize(
    "payload",
    [
        {"x": float("nan")},
        {"x": float("inf")},
        {1: "non-string-key"},
        {"x": (1, 2)},
        {"x": {1}},
        {"x": "x" * 8193},
    ],
)
def test_noncanonical_or_oversized_commands_are_rejected(payload):
    with pytest.raises(ContractError):
        canonical_json(payload)


def test_recursive_and_deep_payloads_are_bounded():
    recursive = {}
    recursive["self"] = recursive
    with pytest.raises(ContractError, match="deep"):
        canonical_json(recursive)


@pytest.mark.parametrize("value", ["", " padded", "line\nbreak", "x" * 2049])
def test_invalid_resource_identity_rejected(value):
    with pytest.raises(ContractError):
        ResourceScope("tenant", "app", "env", value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("plan_digest", "not-a-digest"),
        ("fencing_epoch", True),
        ("fencing_epoch", 0),
        ("parameters_json", "[]"),
        ("parameters_json", '{"x":NaN}'),
    ],
)
def test_bad_command_contract_rejected(command, field, value):
    with pytest.raises(ContractError):
        replace(command, **{field: value})


def test_naive_timestamp_rejected(command):
    with pytest.raises(ContractError, match="aware"):
        replace(command, expires_at=command.expires_at.replace(tzinfo=None))


@pytest.mark.parametrize(
    "field,value",
    [
        ("scope", ResourceScope("other", "app-a", "environment-a", "owned-ingress")),
        ("operation_id", "other-operation"),
        ("plan_digest", "b" * 64),
        ("command_digest", "c" * 64),
        ("fencing_epoch", 2),
    ],
)
def test_permit_cannot_change_scope_plan_command_or_epoch(command, now, field, value):
    with pytest.raises(ContractError, match="match"):
        validate_permit(command, permit_for(command, **{field: value}), now)


def test_expiry_boundary_is_exclusive(command):
    with pytest.raises(ContractError, match="expired"):
        validate_permit(command, permit_for(command), command.expires_at)


def test_held_mutation_rejected_but_authorized_readback_allowed(command, now):
    permit = permit_for(command, security_hold=True)
    with pytest.raises(ContractError, match="hold"):
        validate_permit(command, permit, now)
    validate_permit(command, permit, now, mutation=False)


def test_expired_command_can_be_inspected_with_new_readonly_permit(command):
    now = command.expires_at + timedelta(seconds=1)
    permit = permit_for(command, expires_at=now + timedelta(minutes=1))
    validate_permit(command, permit, now, mutation=False)
    with pytest.raises(ContractError):
        validate_permit(command, permit, now)


def test_readback_cannot_claim_never_applied_from_current_state(command, now):
    with pytest.raises(ContractError, match="Readback"):
        EffectObservation(
            command.scope, command.fingerprint, EffectStatus.NOT_APPLIED, now, "{}"
        )


@pytest.mark.parametrize(
    "payload",
    [
        '{"blocked":true,"blocked":false}',
        '{"nested":{"key":1,"key":2}}',
        '{"x":"\\ud800"}',
    ],
)
def test_ambiguous_json_or_invalid_unicode_is_rejected(command, payload):
    with pytest.raises(ContractError):
        replace(command, parameters_json=payload)
