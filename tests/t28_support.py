"""Synthetic operator only; actual pinned T28 driver and durable SQLite journal."""

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import sqlite3
import time
from types import SimpleNamespace
import urllib.request

from sova.adapters.platform_t28 import DurableT28Port, OperatorBinding, PLATFORM_COMMIT, load_driver
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.domain.contracts import EffectCommand, EffectObservation, EffectStatus, ResourceScope, canonical_json
from support import permit_for


def runtime(root, work, phase="normal", *, deny=False):
    driver = load_driver(root)
    driver.STEPS = (driver.Step("s4-fault-inject", "S4", "operator", "T28", "synthetic test effect", ("synthetic-effect",)),)
    work = Path(work)
    now = datetime(2026, 11, 7, tzinfo=UTC)
    command = EffectCommand(ResourceScope("test-tenant", "test-app", "test-env", "test-resource"),
        "test-operation", "s4-fault-inject", "synthetic-t28", "t28_operator", "test-operation:fault",
        "a" * 64, "revision-1", 1, now + timedelta(minutes=5), canonical_json({
            "argv": ["synthetic-effect"], "platform_commit": PLATFORM_COMMIT, "plan_id": "test-plan", "profile": "mock",
            "application_id": "test-application", "diff_digest": "b" * 64, "image_digest": "sha256:" + "c" * 64}))
    effect = work / "effect.txt"

    class Adapter:
        adapter_id = "synthetic-t28"

        def validate(self, command):
            assert command.parameters["argv"] == ["synthetic-effect"]

        def apply(self, command):
            if phase == "remote-http":
                port = int((work / "remote-port").read_text())
                request = urllib.request.Request(f"http://127.0.0.1:{port}/effect",
                    data=command.fingerprint.encode(), method="POST")
                with urllib.request.urlopen(request, timeout=15) as response:
                    assert response.status == 200
                return
            if phase == "pause-before-effect":
                (work / "claimed").write_text("claimed")
                deadline = time.monotonic() + 10
                while not (work / "release").exists():
                    assert time.monotonic() < deadline
                    time.sleep(0.02)
            if phase == "before-effect":
                os._exit(41)
            with effect.open("a") as stream:
                stream.write("once\n")
                stream.flush()
                os.fsync(stream.fileno())
            if phase == "after-effect":
                os._exit(42)

        def readback(self, command, now):
            applied = effect.exists() and effect.read_text() == "once\n"
            return EffectObservation(command.scope, command.fingerprint,
                EffectStatus.APPLIED if applied else EffectStatus.NOT_APPLIED, now,
                canonical_json({"synthetic_effect_observed": applied}))

    def authorize(_command, _permit, _now, mutation):
        if deny:
            raise PermissionError("Synthetic current authority revoked")
        if phase == "remote-http" and not mutation and not (work / "remote-terminal").exists():
            raise PermissionError("Caller death is not remote operation quiescence")

    db = sqlite3.connect(work / "journal.sqlite")
    db.execute("PRAGMA synchronous=FULL")
    engine = EffectExecutor(SQLiteEffectJournal(db), authorize=authorize, clock=lambda: now)
    binding = OperatorBinding(command, permit_for(command), Adapter())

    class Port(DurableT28Port):
        def __call__(self, *args, **kwargs):
            result = super().__call__(*args, **kwargs)
            if phase == "after-receipt":
                os._exit(43)
            return result

    port = Port(root, "test-plan", "test-application", (binding,), engine)
    args = SimpleNamespace(record=str(work / "run.jsonl"), plan_id="test-plan", profile="mock",
        application_id="test-application", kubeconfig=None, fault_record="unused", receipts=None,
        wait=0, interval=1, step_timeout=30, plan_state_command=None)
    return driver, args, port, binding, db


def delayed_remote(work):
    """A separate local process keeps an accepted request alive after caller death."""
    work = Path(work)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            assert self.path == "/effect" and self.headers.get("Content-Length") == "64"
            digest = self.rfile.read(64).decode("ascii")
            assert len(digest) == 64 and all(c in "0123456789abcdef" for c in digest)
            with (work / "remote-requests").open("a") as stream:
                stream.write(json.dumps({"command": digest}) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            deadline = time.monotonic() + 15
            while not (work / "remote-release").exists():
                assert time.monotonic() < deadline
                time.sleep(0.02)
            with (work / "effect.txt").open("a") as stream:
                stream.write("once\n")
                stream.flush()
                os.fsync(stream.fileno())
            (work / "remote-terminal").write_text(digest)
            try:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"done")
            except (BrokenPipeError, ConnectionResetError):
                pass

    with HTTPServer(("127.0.0.1", 0), Handler) as server:
        (work / "remote-port").write_text(str(server.server_port))
        server.serve_forever(poll_interval=0.05)
