from dataclasses import replace
from unittest.mock import Mock

import pytest

from sova.adapters.preview import PreviewIngressAdapter, PreviewRouteAdapter
from sova.domain.contracts import ContractError, EffectStatus


def test_ingress_adapter_rejects_scope_action_and_extra_fields(command, scope):
    boundary = Mock()
    adapter = PreviewIngressAdapter(scope, boundary)
    command = replace(command, adapter_id=adapter.adapter_id)
    for changed in [
        replace(command, action="shell"),
        replace(command, parameters_json='{"blocked":true,"command":"sh"}'),
        replace(command, parameters_json='{"blocked":1}'),
        replace(command, scope=replace(scope, resource_id="other")),
    ]:
        with pytest.raises(ContractError):
            adapter.apply(changed)
    boundary.set_blocked.assert_not_called()


def test_ingress_readback_strips_unregistered_private_fields(command, scope, now):
    boundary = Mock()
    boundary.read.return_value = {
        "blocked": True,
        "binding_verified": True,
        "task_running": True,
        "private_data": "must-not-be-stored",
    }
    adapter = PreviewIngressAdapter(scope, boundary)
    command = replace(command, adapter_id=adapter.adapter_id)
    observed = adapter.readback(command, now)
    assert observed.status == EffectStatus.APPLIED
    assert "private_data" not in observed.evidence
    assert "must-not-be-stored" not in observed.evidence_json


@pytest.mark.parametrize(
    "payload",
    [
        '{"environment":[]}',
        '{"environment":"unregistered"}',
        '{"environment":"vm","script":"anything"}',
    ],
)
def test_route_rejects_unregistered_or_untyped_parameters(command, scope, payload):
    callback = Mock()
    adapter = PreviewRouteAdapter(scope, read=Mock(), apply=callback)
    command = replace(
        command,
        adapter_id=adapter.adapter_id,
        action="set_route",
        expected_revision="1",
        parameters_json=payload,
    )
    with pytest.raises(ContractError):
        adapter.apply(command)
    callback.assert_not_called()


def test_same_destination_is_not_proof_of_this_route_effect(command, scope, now):
    read = Mock(
        return_value={"environment": "vm", "revision": 2, "last_effect_digest": "other"}
    )
    adapter = PreviewRouteAdapter(scope, read=read, apply=Mock())
    command = replace(
        command,
        adapter_id=adapter.adapter_id,
        action="set_route",
        expected_revision="1",
        parameters_json='{"environment":"vm"}',
    )
    assert adapter.readback(command, now).status == EffectStatus.UNKNOWN
    read.return_value["last_effect_digest"] = command.fingerprint
    assert adapter.readback(command, now).status == EffectStatus.APPLIED
