from dataclasses import replace
from datetime import timedelta
import tomllib

import pytest

from sova.adapters.sandbox.harbor import prepare_task
from sova.domain.contracts import ContractError
from sova.domain.sandbox import SandboxRequest


def request(scope, now):
    return SandboxRequest(
        scope,
        "trial-1",
        "a" * 64,
        "b" * 64,
        "registry.example/agent@sha256:" + "c" * 64,
        "registry.example/verifier@sha256:" + "d" * 64,
        120,
        now + timedelta(minutes=5),
    )


def test_baseline_blocks_setup_and_separate_verifier(scope, now):
    result = prepare_task(request(scope, now), now=now)
    config = tomllib.loads(result["task_toml"])
    assert result["executable"] is False
    assert config["environment"]["network_mode"] == "no-network"
    assert config["verifier"]["environment_mode"] == "separate"
    assert config["verifier"]["environment"]["network_mode"] == "no-network"
    assert "env" not in config["environment"]
    assert result["binding"]["source_digest"] == "a" * 64
    assert (
        prepare_task(replace(request(scope, now), tests_digest="e" * 64), now=now)[
            "binding_digest"
        ]
        != result["binding_digest"]
    )


@pytest.mark.parametrize(
    "change",
    [
        {"agent_image": "alpine:latest"},
        {"timeout_seconds": True},
        {"timeout_seconds": 1801},
        {"source_digest": "bad"},
    ],
)
def test_unpinned_or_invalid_requests_blocked(change, scope, now):
    with pytest.raises(ContractError):
        replace(request(scope, now), **change)


def test_expiry_not_executable(scope, now):
    with pytest.raises(ContractError):
        prepare_task(request(scope, now), now=now + timedelta(minutes=5))
