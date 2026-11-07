from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from onprem_response.supervisor import Supervisor, write_json


def setup(tmp_path, monkeypatch):
    launched = []

    def popen(command, **kwargs):
        launched.append((command, kwargs))
        return SimpleNamespace(pid=99999, poll=lambda: None)

    monkeypatch.setattr("onprem_response.supervisor.subprocess.Popen", popen)
    settings = SimpleNamespace(
        validate=lambda: None,
        python=tmp_path / "python",
        wrapper=tmp_path / "wrapper",
        producer_root=tmp_path / "producer",
        security_root=tmp_path / "security",
        profile=tmp_path / "profile",
        image="fixed@sha256:" + "a" * 64,
        producer_revision="b" * 40,
    )
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    return Supervisor(root, settings), launched


def action(manager, kind, key="a" * 32):
    state = manager.status()
    return {
        "action": kind,
        "request_id": key,
        "session_id": state["session_id"],
        "plan_digest": state["plan_digest"],
        "approved": True,
    }


def ready(manager):
    root = manager.session / "state"
    root.mkdir(mode=0o700)
    write_json(
        root / "trial.private.json",
        {"deadline": (datetime.now(UTC) + timedelta(minutes=7)).isoformat()},
    )
    write_json(
        root / "registration.private.json",
        {"plan_id": "unit-plan", "plan_digest": "d" * 64},
    )
    (root / "feed-key.private").write_bytes(b"k" * 32)
    (root / "feed-key.private").chmod(0o600)
    return root


def test_duplicate_prepare_does_not_create_second_worker(tmp_path, monkeypatch):
    manager, launched = setup(tmp_path, monkeypatch)
    body = action(manager, "prepare")
    manager.act(body)
    assert manager.act(body)["duplicate"]
    assert len(launched) == 1
    cmd, kwargs = launched[0]
    assert kwargs["stdin"] == -3
    assert "--operator-control" in cmd and "--state" in cmd
    assert "KUBECONFIG" not in kwargs["env"]
    assert not any(k.startswith("AWS_") for k in kwargs["env"])
    with pytest.raises(ValueError):
        manager.act(action(manager, "prepare", key="b" * 32))
    manager.lockfile.close()


def test_response_requires_approval_and_current_plan(tmp_path, monkeypatch):
    manager, _ = setup(tmp_path, monkeypatch)
    manager.act(action(manager, "prepare"))
    ready(manager)
    body = action(manager, "respond", key="c" * 32)
    body["approved"] = False
    with pytest.raises(ValueError):
        manager.act(body)
    body["approved"] = True
    body["plan_digest"] = "e" * 64
    with pytest.raises(ValueError):
        manager.act(body)
    body = action(manager, "respond", key="c" * 32)
    manager.act(body)
    assert (manager.session / "respond.private.json").exists()
    assert manager.status()["phase"] == "responding"
    with pytest.raises(ValueError):
        manager.act(action(manager, "stop", key="d" * 32))
    manager.lockfile.close()


def test_unconfirmed_cleanup_prevents_reprepare(tmp_path, monkeypatch):
    manager, launched = setup(tmp_path, monkeypatch)
    manager.act(action(manager, "prepare"))
    root = ready(manager)
    write_json(
        root / "result.private.json",
        {"cleanup": {"unit-namespace": "cleanup_unconfirmed"}},
    )
    assert manager.status()["phase"] == "attention"
    with pytest.raises(ValueError):
        manager.act(action(manager, "prepare", key="e" * 32))
    assert len(launched) == 1
    manager.lockfile.close()
