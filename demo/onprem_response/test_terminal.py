"""Real loopback HTTP fixture and local boundary tests, not cluster evidence."""

import json
import os
import socket
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import httpx
import pytest

from onprem_response.controls import read, seal
from onprem_response.terminal import ProxyRoutes, TerminalTrial
from onprem_response.manifests import PROBE_CODE
from onprem_response.terminal_fixture import (
    APP_CODE,
    PROBE_EXTENSION,
    terminal_manifests,
)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_actual_actor_request_is_denied_and_independently_audited(tmp_path):
    code = tmp_path / "fixture.py"
    code.write_text(APP_CODE)
    ports = [free_port(), free_port()]
    processes = []
    try:
        for component, port, uid in [
            ("neighbor", ports[0], "neighbor-pod"),
            ("api", ports[1], "actor-pod"),
        ]:
            env = dict(
                os.environ,
                APPLICATION="owned-test",
                ENVIRONMENT="blue",
                COMPONENT=component,
                POD_UID=uid,
                LISTEN_HOST="127.0.0.1",
                LISTEN_PORT=str(port),
                NEIGHBOR_HOST="127.0.0.1",
                NEIGHBOR_PORT=str(ports[0]),
            )
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-I", "-B", str(code)],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
            until = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() > until:
                        raise RuntimeError("fixture_start_failed")
                    time.sleep(0.05)
        with httpx.Client(trust_env=False, timeout=3) as client:
            nonce = "a" * 32
            actor = f"http://127.0.0.1:{ports[1]}"
            neighbor = f"http://127.0.0.1:{ports[0]}"
            assert client.get(actor + "/health").status_code == 200
            assert client.get(neighbor + "/health").status_code == 200
            r = client.post(actor + "/attempt", json={"nonce": nonce})
            assert r.status_code == 200 and r.json()["authorization_denied"] is True
            assert (
                r.json()["upstream_status"] == 403
                and r.json()["actor_pod_uid"] == "actor-pod"
            )
            audit = client.get(neighbor + "/audit", params={"nonce": nonce}).json()[
                "audit"
            ]
            assert (
                audit["actor_ip"] == "127.0.0.1"
                and audit["actor_pod_uid"] == "actor-pod"
                and audit["status"] == 403
            )
            assert (
                client.post(actor + "/attempt", json={"nonce": nonce}).status_code
                == 409
            )
            assert (
                client.post(
                    actor + "/attempt",
                    json={"nonce": "b" * 32, "target": "https://unregistered.invalid"},
                ).status_code
                == 400
            )
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=3)


def test_manifest_is_bounded_and_keeps_probe_ingress_closed():
    docs = terminal_manifests("abcdef12", "docker.io/library/python@sha256:" + "a" * 64)
    assert all(not d.get("spec", {}).get("hostNetwork") for d in docs)
    policy = next(d for d in docs if d["kind"] == "NetworkPolicy")
    assert policy["spec"]["ingress"] == []
    for d in docs:
        if d["kind"] == "ConfigMap":
            compile(d["data"]["main.py"], "fixture", "exec")
    assert not any(
        d["kind"] in {"Secret", "ClusterRole", "ClusterRoleBinding"} for d in docs
    )


def test_actual_http_proxy_forwards_attempt_and_audit(tmp_path):
    ports = [free_port(), free_port(), free_port()]
    end = "ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()"
    probe = PROBE_CODE.replace(end, PROBE_EXTENSION + "\n" + end)
    probe = probe.replace(
        "HTTPConnection(TARGETS['blue'],8080,",
        f"HTTPConnection(TARGETS['blue'],{ports[1]},",
    )
    probe = probe.replace(
        "HTTPConnection(TARGETS['neighbor'],8080,",
        f"HTTPConnection(TARGETS['neighbor'],{ports[0]},",
    )
    probe = probe.replace(
        end, f"ThreadingHTTPServer(('127.0.0.1',{ports[2]}),Handler).serve_forever()"
    )
    processes = []
    try:
        for component, port, code in [
            ("neighbor", ports[0], APP_CODE),
            ("api", ports[1], APP_CODE),
            ("probe", ports[2], probe),
        ]:
            path = tmp_path / (component + ".py")
            path.write_text(code)
            env = dict(
                os.environ,
                APPLICATION="owned-test",
                ENVIRONMENT="blue",
                COMPONENT=component,
                POD_UID=component + "-pod",
                LISTEN_HOST="127.0.0.1",
                LISTEN_PORT=str(port),
                NEIGHBOR_HOST="127.0.0.1",
                NEIGHBOR_PORT=str(ports[0]),
                SOURCE_ENV="owned-blue",
                TARGET_ENV="owned-green",
                TARGETS=json.dumps(
                    {k: "127.0.0.1" for k in ["blue", "green", "neighbor"]}
                ),
            )
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-I", "-B", str(path)],
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            )
            until = time.monotonic() + 5
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() > until:
                        raise RuntimeError("fixture_start_failed")
                    time.sleep(0.05)
        nonce = "c" * 32
        with httpx.Client(trust_env=False, timeout=5) as client:
            r = client.post(
                f"http://127.0.0.1:{ports[2]}/attempt", json={"nonce": nonce}
            )
            assert r.status_code == 200, r.text
            assert r.json()["upstream_status"] == 403
            audit = client.get(
                f"http://127.0.0.1:{ports[2]}/audit?nonce={nonce}"
            ).json()["audit"]
            assert audit["nonce"] == nonce and audit["actor_pod_uid"] == "api-pod"
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=3)


@pytest.mark.parametrize(
    "path",
    [
        "https://outside.invalid",
        "/attempt?target=elsewhere",
        "/api/v1/secrets",
        "/probe?target=foreign",
    ],
)
def test_proxy_cannot_choose_a_destination(path):
    routes = ProxyRoutes(SimpleNamespace(), "source", "target")
    with pytest.raises(ValueError):
        routes.call(path)


def test_proxy_post_paths_remain_literal_and_get_probe_has_a_nonce():
    calls = []
    api = SimpleNamespace(
        namespaces={"probe": "owned-probe"},
        request=lambda *args: calls.append(args) or {"ok": False},
    )
    routes = ProxyRoutes(api, "source", "target")
    routes.call("/attempt", {"nonce": "a" * 32})
    routes.call("/route", {"request": "fixed"})
    assert calls[0][0] == "POST" and calls[0][1].endswith("/proxy/attempt")
    assert calls[1][1].endswith("/proxy/route") and "?" not in calls[1][1]
    routes.call("/probe?target=blue")
    assert "target=blue&request_id=" in calls[2][1]


def test_no_effect_can_execute_before_exact_post_observation_approval():
    trial = object.__new__(TerminalTrial)
    trial.approved = False
    with pytest.raises(ValueError, match="approval"):
        trial.authorize(None, None, datetime.now(UTC), True)


def test_attempt_control_is_not_accepted_by_legacy_response_reader(tmp_path):
    now = datetime.now(UTC)
    binding = {"plan_id": "owned", "plan_digest": "a" * 64}
    key = b"x" * 32
    envelope = seal(
        key,
        action="attempt",
        request_id="b" * 32,
        binding=binding,
        revision="c" * 40,
        expires_at=(now + timedelta(seconds=20)).isoformat(),
    )
    p = tmp_path / "attempt.json"
    p.write_text(json.dumps(envelope))
    p.chmod(0o600)
    with pytest.raises(ValueError):
        read(
            p,
            key=key,
            binding=binding,
            revision="c" * 40,
            at=now,
            deadline=now + timedelta(minutes=1),
        )
    assert (
        read(
            p,
            key=key,
            binding=binding,
            revision="c" * 40,
            at=now,
            deadline=now + timedelta(minutes=1),
            actions={"attempt"},
        )["action"]
        == "attempt"
    )


@pytest.mark.parametrize(
    "field", ["actor_uid", "actor_ip", "nonce", "status", "application"]
)
def test_unattributed_denials_cannot_create_a_response_plan(tmp_path, field):
    trial = object.__new__(TerminalTrial)
    trial.root = tmp_path
    trial.attack_attempted = False
    trial.attack = None
    trial.app = "test-app"
    trial.ns = {"blue": "owned-blue"}
    trial.source = {"spec": {"selector": {"matchLabels": {"app": "test"}}}}
    nonce = "a" * 32
    response = {
        "nonce": nonce,
        "application": trial.app,
        "authorization_denied": True,
        "upstream_status": 403,
        "actor_pod_uid": "actual-pod",
    }
    audit = {
        "nonce": nonce,
        "application": trial.app,
        "status": 403,
        "actor_pod_uid": "actual-pod",
        "actor_ip": "192.0.2.10",
    }
    if field == "actor_uid":
        response["actor_pod_uid"] = "other-pod"
    if field == "actor_ip":
        audit["actor_ip"] = "192.0.2.11"
    if field == "nonce":
        audit["nonce"] = "b" * 32
    if field == "status":
        response["upstream_status"] = 401
    if field == "application":
        audit["application"] = "other-app"
    pod = {
        "metadata": {"uid": "actual-pod", "labels": {"app": "test"}},
        "status": {"podIP": "192.0.2.10"},
    }
    trial.api = SimpleNamespace(
        check_owned=lambda: None, request=lambda *args: {"items": [pod]}
    )

    def call(path, *args):
        if path == "/attempt":
            return response
        if path.startswith("/audit"):
            return {"audit": audit}
        return {"ok": True}

    trial.routes = SimpleNamespace(call=call)
    bound = []
    trial.bind_response = lambda *args: bound.append(args)
    with pytest.raises(ValueError, match="actor Pod"):
        trial.observe_attempt(nonce)
    assert bound == [] and trial.attack is None


def test_approval_for_initial_display_binding_cannot_authorize_response_plan(tmp_path):
    trial = object.__new__(TerminalTrial)
    trial.hmac_key = b"x" * 32
    trial.plan_binding = {"plan_id": "initial", "plan_digest": "a" * 64}
    trial.plan = SimpleNamespace(plan_id="response", fingerprint="b" * 64)
    trial.source_revision = "c" * 40
    trial.deadline = datetime.now(UTC) + timedelta(minutes=1)
    wrong = seal(
        trial.hmac_key,
        action="respond",
        request_id="d" * 32,
        binding=trial.plan_binding,
        revision=trial.source_revision,
        expires_at=trial.deadline.isoformat(),
    )
    p = tmp_path / "respond.private.json"
    p.write_text(json.dumps(wrong))
    p.chmod(0o600)
    with pytest.raises(ValueError):
        trial.command(tmp_path, "respond")


@pytest.mark.parametrize("published", [False, True])
def test_completion_waits_for_final_readback_publication(
    tmp_path, monkeypatch, published
):
    from onprem_response.supervisor import Supervisor
    from onprem_response.terminal_supervisor import TerminalSupervisor

    steps = [
        "apply_isolation",
        "activate_replacement",
        "verify_replacement",
        "switch_route",
    ]
    monkeypatch.setattr(
        Supervisor,
        "status",
        lambda _: {
            "phase": "complete",
            "steps": steps,
            "response_verified": True,
            "remaining_seconds": 200,
            "can_stop": True,
        },
    )
    state = tmp_path / "state"
    state.mkdir()
    path = state / "terminal-status.private.json"
    path.write_text(
        json.dumps(
            {
                "phase": "watch" if published else "verify_replacement",
                "observation_revision": 10,
                "steps": steps if published else steps[:-1],
                "attack_observed": True,
                "approved": True,
            }
        )
    )
    path.chmod(0o600)
    (tmp_path / "respond.private.json").touch()
    manager = object.__new__(TerminalSupervisor)
    monkeypatch.setattr(TerminalSupervisor, "session", property(lambda _: tmp_path))
    value = manager.status()
    assert value["response_verified"] is published
    assert value["phase"] == ("complete" if published else "responding")
    assert value["can_stop"] is published
    assert value["observation_revision"] == 10
