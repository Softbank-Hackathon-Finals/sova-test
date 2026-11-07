"""Finite-plan and real loopback protocol regressions; not cluster evidence."""

from datetime import timedelta
import json
import os
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

import httpx
import pytest

from onprem_response.expanded_fixture import expanded_manifests
from onprem_response.incident import IncidentAdapter, IncidentTrial
from onprem_response.incident_supervisor import IncidentSupervisor
from onprem_response.terminal_supervisor import TerminalSupervisor
from onprem_response.terminal import TerminalTrial
from onprem_response.trial import now
from sova.domain.contracts import ContractError, EffectStatus

IMAGE = "docker.io/library/python@sha256:" + "a" * 64


def skeleton(tmp_path, components=("api", "worker")):
    trial = object.__new__(IncidentTrial)
    trial.root, trial.components = tmp_path, components
    trial.ns = {s: "owned-" + s for s in ("blue", "green", "probe")}
    trial.artifacts = {
        (s, c): {"uid": s + c, "template": "b" * 64, "code": "c" * 64}
        for s in ("blue", "green")
        for c in components
    }
    trial.api = SimpleNamespace(uids={v: "uid-" + k for k, v in trial.ns.items()})
    trial.image, trial.app, trial.run_id = IMAGE, "owned-app", "aabbccdd"
    trial.old_pods, trial.streams = (
        {c: "old-" + c for c in components},
        {c: "d" * 32 for c in components},
    )
    trial.commands, trial.receipts = {}, {}
    trial.deadline = now() + timedelta(minutes=5)
    trial.route = lambda c: {"environment_id": trial.ns["blue"], "revision": 1}
    trial.publish = lambda *a, **k: None
    return trial


def test_plan_pins_selected_set_and_excludes_database(tmp_path):
    t = skeleton(tmp_path)
    t.prepare_plan("respond")
    p = t.pending_plan
    assert len(p.steps) == 8
    assert [s.action for s in p.steps] == [
        "isolate",
        "isolate",
        "fence",
        "fence",
        "activate",
        "activate",
        "inject_failure",
        "verify",
    ]
    assert all(
        json.loads(s.parameters_json)["selected"] == ["api", "worker"] for s in p.steps
    )
    assert all(
        "neighbor" not in s.scope.resource_id and "database" not in s.scope.resource_id
        for s in p.steps
    )
    original = p.fingerprint
    t.components = ("api",)
    t.prepare_plan("respond")
    assert t.pending_plan.fingerprint != original
    for group in [("database",), ("api", "database"), (), ("api", "api"), ["api"]]:
        with pytest.raises((ContractError, TypeError)):
            IncidentTrial(tmp_path, IMAGE, {}, components=group)


def test_recovery_is_new_plan_and_cannot_reuse_approval(tmp_path):
    t = skeleton(tmp_path)
    t.prepare_plan("respond")
    original = t.pending_plan
    t.prepare_plan("recheck")
    retry = t.pending_plan
    assert retry.fingerprint != original.fingerprint
    assert retry.origin_plan_digest == original.fingerprint
    assert retry.steps[0].action == "clear_failure"
    assert [s.action for s in retry.steps].count("verify") == 2
    t.prepare_plan("return")
    returned = t.pending_plan
    assert returned.fingerprint not in {retry.fingerprint, original.fingerprint}
    assert [s.action for s in returned.steps] == [
        "restore",
        "restore",
        "release_policy",
        "release_policy",
        "return",
        "return",
    ]
    assert all(
        s.action not in {"clear_incident", "delete_database"} for s in returned.steps
    )


def test_direct_final_step_and_expired_plan_rejected(tmp_path):
    t = skeleton(tmp_path)
    t.prepare_plan("respond")
    t.active_plan = t.pending_plan
    last = t.active_plan.steps[-1]
    c = t.active_plan.command(last.step_id, operation_id=t.active_plan.plan_id, epoch=1)
    with pytest.raises(ContractError, match="Previous effect"):
        t.authorize(c, None, now(), True)
    t.receipts = {
        t.active_plan.command(
            s.step_id, operation_id=t.active_plan.plan_id, epoch=1
        ).fingerprint: EffectStatus.APPLIED
        for s in t.active_plan.steps
    }
    with pytest.raises(ContractError, match="Exact current"):
        t.authorize(c, None, t.deadline, True)
    t.active_plan = None
    with pytest.raises(ContractError, match="Exact current"):
        t.authorize(c, None, now(), True)


def test_unregistered_adapter_command_fails_before_any_request(tmp_path):
    t = skeleton(tmp_path)
    t.prepare_plan("respond")
    c = t.pending_plan.command(
        t.pending_plan.steps[0].step_id, operation_id="other-operation", epoch=1
    )
    with pytest.raises(ContractError, match="Unregistered"):
        IncidentAdapter(t).apply(c)


def test_manifest_privilege_and_fixture_syntax():
    rows = expanded_manifests("aabbccdd", IMAGE)
    deployments = [r for r in rows if r["kind"] == "Deployment"]
    assert len(deployments) == 6
    assert {r["metadata"]["name"] for r in deployments} == {
        "api",
        "worker",
        "neighbor",
        "probe",
    }
    for r in rows:
        if r["kind"] == "ConfigMap":
            compile(r["data"]["main.py"], "fixture", "exec")
        if r["kind"] == "Deployment":
            pod = r["spec"]["template"]["spec"]
            assert pod["automountServiceAccountToken"] is False
            assert not pod.get("hostNetwork")
            assert all(
                c["securityContext"]["capabilities"]["drop"] == ["ALL"]
                and c["securityContext"]["readOnlyRootFilesystem"]
                for c in pod["containers"]
            )


def port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_real_existing_stream_identity_close_and_green_fault(tmp_path):
    rows = expanded_manifests("aabbccdd", IMAGE)
    app_code = next(
        r["data"]["main.py"]
        for r in rows
        if r["kind"] == "ConfigMap" and r["metadata"]["name"] == "api-code"
    )
    probe_code = next(
        r["data"]["main.py"]
        for r in rows
        if r["kind"] == "ConfigMap" and r["metadata"]["name"] == "probe-code"
    )
    app_port, probe_port = port(), port()
    probe_code = probe_code.replace(",8080,timeout=", f",{app_port},timeout=").replace(
        "ThreadingHTTPServer(('0.0.0.0',8080),Handler)",
        f"ThreadingHTTPServer(('127.0.0.1',{probe_port}),Handler)",
    )
    processes = []
    try:
        for name, code, env in [
            (
                "app",
                app_code,
                dict(
                    APPLICATION="owned-test",
                    COMPONENT="api",
                    ENVIRONMENT="green",
                    POD_UID="actual-uid",
                    LISTEN_HOST="127.0.0.1",
                    LISTEN_PORT=str(app_port),
                ),
            ),
            (
                "probe",
                probe_code,
                dict(
                    APPLICATION="owned-test",
                    SOURCE_ENV="source",
                    TARGET_ENV="target",
                    TARGETS=json.dumps(
                        {
                            "blue": "127.0.0.1",
                            "green": "127.0.0.1",
                            "neighbor": "127.0.0.1",
                            "blue-worker": "127.0.0.1",
                            "green-worker": "127.0.0.1",
                        }
                    ),
                ),
            ),
        ]:
            path = tmp_path / (name + ".py")
            path.write_text(code)
            processes.append(
                subprocess.Popen(
                    [sys.executable, "-I", "-B", str(path)],
                    env=dict(os.environ, **env),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            )
        with httpx.Client(trust_env=False, timeout=5) as client:
            url = f"http://127.0.0.1:{probe_port}"
            for _ in range(60):
                try:
                    if client.get(url + "/health").status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(0.05)
            nonce = "b" * 32
            assert (
                client.post(
                    url + "/streams/open", json={"component": "api", "nonce": nonce}
                ).status_code
                == 200
            )
            for _ in range(30):
                stream = client.get(url + "/streams").json()["streams"]["api"]
                if stream["alive"]:
                    break
                time.sleep(0.05)
            assert stream["pod_uid"] == "actual-uid" and stream["lines"] > 0
            assert (
                client.post(
                    url + "/streams/close", json={"component": "api", "nonce": "c" * 32}
                ).status_code
                == 409
            )
            assert (
                client.post(
                    url + "/streams/close", json={"component": "api", "nonce": nonce}
                ).json()["closed"]
                is True
            )
            stream = client.get(url + "/streams").json()["streams"]["api"]
            assert stream["client_socket_closed"] is True
            app = f"http://127.0.0.1:{app_port}"
            assert (
                client.post(
                    app + "/fault", json={"failed": True, "command": "anything"}
                ).status_code
                == 400
            )
            assert client.post(app + "/fault", json={"failed": True}).status_code == 200
            assert client.get(app + "/health").status_code == 503
            assert (
                client.post(app + "/fault", json={"failed": False}).status_code == 200
            )
            assert (
                client.get(app + "/health?nonce=" + nonce).json()["probe_nonce"]
                == nonce
            )
    finally:
        for proc in processes:
            proc.terminate()
        for proc in processes:
            proc.wait(timeout=5)
            proc.stderr.close()


def test_original_terminal_admission_reused():
    assert IncidentTrial.observe_attempt is TerminalTrial.observe_attempt


def test_registration_does_not_publish_ready_before_stream_baseline(
    tmp_path, monkeypatch
):
    session = tmp_path / "session-00000000000000000000000000000000"
    (session / "state").mkdir(parents=True)
    manager = object.__new__(IncidentSupervisor)
    manager.root, manager.session_id = tmp_path, "0" * 32
    monkeypatch.setattr(
        TerminalSupervisor,
        "status",
        lambda _: {"phase": "ready", "can_attempt": True, "can_respond": True},
    )
    result = manager.status()
    assert result["phase"] == "preparing"
    assert result["can_attempt"] is False and result["can_respond"] is False
