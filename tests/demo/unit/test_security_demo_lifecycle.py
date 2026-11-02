"""The demo's cleanup must not acquire authority from a reused name."""

from security_demo import LABEL, Demo, owned_container, write_private
import json
import os
import pytest


def test_cleanup_requires_exact_container_and_session_label():
    record = {"container_id": "id", "name": "sova-demo", "run_id": "run"}
    inspection = {
        "Id": "id",
        "Name": "/sova-demo",
        "Config": {"Labels": {LABEL: "run"}},
    }
    assert owned_container(record, inspection)
    assert not owned_container({**record, "container_id": "other"}, inspection)
    assert not owned_container({**record, "run_id": "other"}, inspection)
    assert not owned_container(record, {**inspection, "Config": {"Labels": {}}})


def test_private_registration_cannot_follow_a_symlink(tmp_path):
    target = tmp_path / "existing"
    target.write_text("unchanged")
    link = tmp_path / "registration"
    link.symlink_to(target)
    with pytest.raises(OSError):
        write_private(link, {"private": True})
    assert target.read_text() == "unchanged"
    output = tmp_path / "new"
    write_private(output, {"private": True})
    assert os.stat(output).st_mode & 0o777 == 0o600


def test_cleanup_continues_after_a_resource_failure_and_preserves_records(tmp_path):
    demo = Demo(tmp_path, {})
    attempts = []

    def failed_probe():
        attempts.append("probe")
        raise RuntimeError("probe unreachable")

    demo.stop_probe = failed_probe
    demo.stop_cluster = lambda: attempts.append("cluster")
    demo.stop_database = lambda: attempts.append("database")
    demo.cleanup()
    assert attempts == ["probe", "cluster", "database"]
    proof = json.loads((tmp_path / "cleanup.json").read_text())
    assert proof["records_preserved"] is True
    assert proof["errors"] == ["owned_probe_stop_unverified"]


def test_login_renewal_cannot_restart_an_undrained_action(tmp_path):
    from types import SimpleNamespace

    demo = Demo(tmp_path, {})
    demo.console = SimpleNamespace(terminate=lambda: None, wait=lambda timeout: None)
    write_private(
        tmp_path / "console-shutdown.json",
        {"drain": {"collector_stopped": True, "action_drained": False}},
    )
    demo.launch_console = lambda: pytest.fail("must not restart undrained actions")
    with pytest.raises(RuntimeError, match="did not drain"):
        demo.renew_login()


def test_cleanup_waits_for_docker_auto_remove_readback(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import security_demo

    demo = Demo(tmp_path, {})
    demo.cluster = {"container_id": "id", "name": "sova-demo", "run_id": "run"}
    inspection = {
        "Id": "id",
        "Name": "/sova-demo",
        "Config": {"Labels": {LABEL: "run"}},
    }
    monkeypatch.setattr(
        security_demo.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout=json.dumps([inspection])),
    )
    readbacks = iter(["id\n", ""])

    def command(args, **kwargs):
        return next(readbacks) if "ps" in args else "id"

    monkeypatch.setattr(security_demo, "checked", command)
    monkeypatch.setattr(security_demo.time, "sleep", lambda _: None)
    demo.stop_cluster()
    with pytest.raises(StopIteration):
        next(readbacks)
