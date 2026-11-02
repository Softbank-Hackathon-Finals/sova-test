from datetime import UTC, datetime, timedelta
import threading
from types import SimpleNamespace
import pytest
import security_console
from sova.domain.contracts import ContractError


def test_shutdown_rejects_new_actions_and_drains_existing_work(tmp_path):
    console = object.__new__(security_console.SecurityConsole)
    console.root = tmp_path
    console.lock = threading.RLock()
    console.stop = threading.Event()
    console.deadline = datetime.now(UTC) + timedelta(minutes=5)
    console.busy = False
    console.action_thread = None
    console.prepared = None
    console.operation = None
    entered = threading.Event()
    release = threading.Event()

    def work():
        entered.set()
        release.wait(3)

    console.inject = work
    console.thread = threading.Thread(target=console.stop.wait, daemon=True)
    console.thread.start()
    console.start_action("inject")
    assert entered.wait(1)
    result = []
    closer = threading.Thread(target=lambda: result.append(console.close()))
    closer.start()
    assert console.stop.wait(1)
    with pytest.raises(ContractError, match="shutting down"):
        console.start_action("inject")
    release.set()
    closer.join(timeout=3)
    assert result == [{"collector_stopped": True, "action_drained": True}]
    assert not console.busy


def test_existing_bootstrap_file_is_never_removed_when_startup_is_refused(
    tmp_path, monkeypatch
):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    access = root / "operator-access.json"
    access.write_text("existing-owner-file")
    access.chmod(0o600)
    closed = []
    console = SimpleNamespace(
        session={},
        root=root,
        deadline=datetime.now(UTC) + timedelta(minutes=5),
        close=lambda: closed.append(True),
    )
    monkeypatch.setattr(security_console, "SecurityConsole", lambda _: console)
    monkeypatch.setattr(security_console.signal, "signal", lambda *_: None)
    with pytest.raises(FileExistsError):
        security_console.main(["--session-root", str(root), "--port", "8795"])
    assert closed == [True] and access.read_text() == "existing-owner-file"
