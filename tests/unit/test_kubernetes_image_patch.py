from copy import deepcopy
from dataclasses import replace
from datetime import timedelta

import pytest
from kubernetes_patch_support import image_patch_bundle
from sova.adapters.kubernetes.image_patch import (
    MARKER,
    deployment_configuration,
    KubernetesImagePatchAdapter,
)
from sova.domain.contracts import ContractError, EffectStatus, canonical_json


def test_only_exact_approved_image_is_conditionally_patched(now):
    reg, command, adapter, state = image_patch_bundle(now)
    before = deepcopy(state["workload"])
    adapter.apply(command)
    assert len(state["calls"]) == 1
    assert state["workload"]["metadata"]["annotations"][MARKER] == command.fingerprint
    assert deployment_configuration(state["workload"]) == deployment_configuration(
        before
    )
    result = adapter.readback(command, now)
    assert result.status == EffectStatus.APPLIED
    assert result.evidence["runtime_verified"] is False
    assert state["calls"][0][-1]["value"] == reg.image


@pytest.mark.parametrize(
    "case", ["scope", "artifact", "action", "revision", "tag", "extra-parameter"]
)
def test_arbitrary_scope_artifact_action_or_parameters_cannot_reach_api(now, case):
    _, command, adapter, state = image_patch_bundle(now)
    if case == "scope":
        command = replace(command, scope=replace(command.scope, application_id="other"))
    if case == "action":
        command = replace(command, action="delete")
    if case == "revision":
        command = replace(command, expected_revision="9")
    if case in {"artifact", "tag", "extra-parameter"}:
        params = command.parameters
        if case == "artifact":
            params["artifact"]["image_digest"] = "0" * 64
        if case == "tag":
            params["image"] = "registry.example/owned/probe:latest"
        if case == "extra-parameter":
            params["command"] = "untrusted text"
        command = replace(command, parameters_json=canonical_json(params))
    with pytest.raises(ContractError):
        adapter.apply(command)
    assert state["calls"] == []


@pytest.mark.parametrize(
    "case",
    [
        "namespace",
        "deployment",
        "configuration",
        "resource-version",
        "predecessor",
        "expired-command",
        "expired-registration",
        "denied",
        "revoked",
    ],
)
def test_identity_drift_expiry_and_authority_failure_never_write(now, case):
    reg, command, adapter, state = image_patch_bundle(now)
    if case == "namespace":
        state["namespace_uid"] = "recreated"
    if case == "deployment":
        state["workload"]["metadata"]["uid"] = "recreated"
    if case == "configuration":
        state["workload"]["spec"]["template"]["spec"]["hostNetwork"] = True
    if case == "resource-version":
        state["workload"]["metadata"]["resourceVersion"] = "12"
    if case == "predecessor":
        state["workload"]["metadata"]["annotations"][MARKER] = "0" * 64
    if case == "expired-command":
        state["time"] = command.expires_at
    if case == "expired-registration":
        state["time"] = reg.valid_until
    if case == "denied":
        state["allowed"] = False
    if case == "revoked":
        state["authenticated"] = False
    with pytest.raises(ContractError):
        adapter.apply(command)
    assert not state["calls"]


@pytest.mark.parametrize("case", ["revoked", "denied", "registration", "expired"])
def test_authority_revoked_during_read_does_not_mutate(now, case):
    reg, command, adapter, state = image_patch_bundle(now)

    def late():
        if case == "revoked":
            state["authenticated"] = False
        if case == "denied":
            state["allowed"] = False
        if case == "registration":
            state["registration"] = replace(reg, resource_version="99")
        if case == "expired":
            state["time"] = command.expires_at

    state["late"] = late
    with pytest.raises(ContractError):
        adapter.apply(command)
    assert not state["calls"]


def test_lost_response_is_read_back_without_another_patch(now):
    _, command, adapter, state = image_patch_bundle(now)
    state["lost_response"] = True
    with pytest.raises(TimeoutError):
        adapter.apply(command)
    assert adapter.readback(command, now).status == EffectStatus.APPLIED
    assert len(state["calls"]) == 1
    # Current image alone without this command marker cannot prove this effect.
    state["workload"]["metadata"]["annotations"][MARKER] = "0" * 64
    assert adapter.readback(command, now).status == EffectStatus.UNKNOWN


@pytest.mark.parametrize(
    "repository",
    [
        "https://registry.example/probe",
        "registry.example/probe:latest",
        "registry.example/../probe",
        "user:password@registry.example/probe",
        "localhost:0/probe",
    ],
)
def test_registry_registration_has_no_url_credentials_tag_or_ambiguous_path(
    now, repository
):
    reg, *_ = image_patch_bundle(now)
    with pytest.raises(ContractError):
        replace(reg, repository=repository)


def test_new_approved_patch_can_replace_exact_registered_predecessor(now):
    reg, command, prior, state = image_patch_bundle(now)
    reg = replace(reg, base_command_digest="7" * 64)
    state["workload"]["metadata"]["annotations"][MARKER] = reg.base_command_digest
    state["registration"] = reg
    prior.transport.registration_digest = reg.fingerprint
    adapter = KubernetesImagePatchAdapter(
        reg,
        transport=prior.transport,
        current_registration=lambda: state["registration"],
        authenticate_registration=lambda _: True,
        authorize=lambda *_: True,
        clock=lambda: now,
    )
    adapter.apply(command)
    assert state["workload"]["metadata"]["annotations"][MARKER] == command.fingerprint
    assert len(state["calls"]) == 1


def test_explicit_read_window_does_not_renew_mutation_permission(now):
    reg, command, adapter, state = image_patch_bundle(now)
    reg = replace(reg, read_until=now + timedelta(minutes=9))
    state["registration"] = reg
    adapter.registration = reg
    adapter.transport.registration_digest = reg.fingerprint
    adapter.apply(command)
    state["time"] = reg.valid_until + timedelta(seconds=1)
    assert adapter.readback(command, state["time"]).status == EffectStatus.APPLIED
    with pytest.raises(ContractError):
        adapter.apply(command)
    assert len(state["calls"]) == 1
    state["authenticated"] = False
    with pytest.raises(ContractError):
        adapter.readback(command, state["time"])


def test_read_window_cannot_outlive_registered_api_access(now):
    reg, *_ = image_patch_bundle(now)
    with pytest.raises(ContractError):
        replace(reg, read_until=reg.reader.valid_until + timedelta(seconds=1))
