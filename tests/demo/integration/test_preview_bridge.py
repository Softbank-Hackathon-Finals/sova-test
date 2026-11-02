"""Real SQLite and HTTP API; AWS/TLS effects are explicit fault-injected fakes.

No registered cloud resource, private key, or live preview database is loaded.
"""

import http.cookiejar
import json
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
from unittest.mock import Mock

import pytest

from server import Console, handler
from sova.domain.contracts import ContractError


class ControlledIngress:
    def __init__(self):
        self.blocked = False
        self.calls = []
        self.lose_next_response = False

    def read(self):
        return {"blocked": self.blocked, "binding_verified": True, "task_running": True}

    def set_blocked(self, value):
        self.blocked = value
        self.calls.append(value)
        if self.lose_next_response:
            self.lose_next_response = False
            raise TimeoutError("effect applied but response lost")
        return self.read()


def test_checked_route_rejects_changed_approval_before_effect(console):
    subject, boundary = console, console.network
    with pytest.raises(ValueError, match="변경"):
        subject.switch("vm", expected_revision="b" * 64, expected_route_revision=1)
    with pytest.raises(ValueError, match="변경"):
        subject.switch("vm", expected_revision="a" * 64, expected_route_revision=999)
    assert subject.operation is None
    assert boundary.calls == []


@pytest.fixture
def console(tmp_path):
    boundary = ControlledIngress()
    config = {
        "name": "test-http-app",
        "run_id": "test-http-run",
        "account": "test-only",
        "security_group": "test-ingress",
        "revision": "a" * 64,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
    }
    console = Console(
        config,
        {"aws": 1, "vm": 2},
        network=boundary,
        database=tmp_path / "console.sqlite",
        start_collector=False,
        tls_context=ssl.create_default_context(),
    )

    def remote(side, *, request_id=None, message=None):
        if side == "aws" and boundary.blocked:
            raise TimeoutError("injected blocked connection")
        return {
            "environment": side,
            "instance": "test-" + side,
            "revision": "a" * 64,
            "request_id": request_id,
            "message": message,
        }, 1.0

    console.remote = Mock(side_effect=remote)
    console.controlled_denial = Mock(return_value={"type": "controlled_security_test"})
    yield console
    assert console.operation is None, "A test left a workflow running"
    console.db.close()


@pytest.fixture
def http_api(console):
    server = ThreadingHTTPServer(
        ("127.0.0.1", 0), handler(console, "http://unused", "test-token")
    )
    origin = f"http://127.0.0.1:{server.server_port}"
    server.RequestHandlerClass = handler(console, origin, "test-token")
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    client.open(origin + "/", timeout=2).read()

    def request(path, body=None, *, request_origin=None, raw_body=None):
        request = urllib.request.Request(
            origin + path,
            data=raw_body
            if raw_body is not None
            else None
            if body is None
            else json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Origin": request_origin or origin,
            },
        )
        with client.open(request, timeout=2) as response:
            return response.status, json.load(response)

    try:
        yield request
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_checked_http_switch_validates_binding_and_reports_real_steps(
    http_api, console
):
    with pytest.raises(urllib.error.HTTPError) as rejected:
        http_api(
            "/api/switch-checked",
            {
                "environment": "vm",
                "revision": "a" * 64,
                "route_revision": 999,
            },
        )
    assert rejected.value.code == 400
    assert console.operation is None
    status, operation = http_api(
        "/api/switch-checked",
        {
            "environment": "vm",
            "revision": "a" * 64,
            "route_revision": 1,
        },
    )
    assert status == 202
    complete(console, operation["id"])
    state = console.snapshot()
    assert state["route"] == "vm"
    assert state["workflows"][0]["status"] == "succeeded"
    assert all(step["status"] == "succeeded" for step in state["workflows"][0]["steps"])


def complete(console, operation_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        state = console.snapshot()
        if not state["operation"] and state["last_operation"]["id"] == operation_id:
            return state["last_operation"]
        time.sleep(0.005)
    raise AssertionError("Workflow did not complete within the test deadline")


def test_existing_http_route_contract_uses_durable_effects(http_api, console):
    status, operation = http_api("/api/switch", {"environment": "vm"})
    assert status == 202
    finished = complete(console, operation["id"])
    assert finished["status"] == "succeeded"
    route_step = next(s for s in finished["steps"] if s["id"] == "route")
    assert route_step["evidence"]["effect_marker_verified"]
    assert route_step["evidence"]["effect_status"] == "confirmed_applied"
    status, receipt = http_api("/api/action", {"message": "test", "automatic": False})
    assert status == 200 and receipt["environment"] == "vm"
    assert (
        console.read_route()["last_effect_digest"]
        == route_step["evidence"]["effect_digest"]
    )
    with pytest.raises(urllib.error.HTTPError) as denied:
        http_api(
            "/api/switch",
            {"environment": "aws"},
            request_origin="https://other.invalid",
        )
    assert denied.value.code == 403


def test_controlled_isolation_and_restore_preserve_public_api(http_api, console):
    status, operation = http_api(
        "/api/security-test", {"action": "drill", "confirm": True}
    )
    assert status == 202
    assert complete(console, operation["id"])["status"] == "succeeded"
    assert console.route == "vm" and console.network.calls == [True]
    _, operation = http_api(
        "/api/security-test", {"action": "restore", "confirm": True}
    )
    assert complete(console, operation["id"])["status"] == "succeeded"
    assert console.route == "vm" and console.network.calls == [True, False]
    assert console.security["state"] == "normal"
    assert console.db.execute(
        "SELECT count(*) FROM sova_effects_v1 WHERE status='confirmed_applied'"
    ).fetchone() == (3,)


def test_unknown_ingress_is_reconciled_only_on_explicit_restore(http_api, console):
    console.network.lose_next_response = True
    _, operation = http_api("/api/security-test", {"action": "drill", "confirm": True})
    failed = complete(console, operation["id"])
    assert failed["status"] == "needs_attention"
    assert console.network.calls == [True]
    assert console.db.execute("SELECT status FROM sova_effects_v1").fetchone() == (
        "unknown",
    )
    _, restoration = http_api(
        "/api/security-test", {"action": "restore", "confirm": True}
    )
    restored = complete(console, restoration["id"])
    assert restored["status"] == "succeeded" and console.network.calls == [True, False]
    assert (
        restored["steps"][0]["evidence"]["prior_effect_readbacks"][0]["status"]
        == "confirmed_applied"
    )
    old = console.db.execute(
        "SELECT status FROM workflows WHERE id=?", (operation["id"],)
    ).fetchone()
    assert old == (
        "needs_attention",
    )  # The historical workflow failure is not rewritten.


def test_step_replay_and_out_of_order_calls_never_execute(console):
    operation = console.begin_workflow(
        "route_switch", "vm", [("first", "first"), ("second", "second")]
    )
    callback = Mock(return_value={"verified": True})
    try:
        with pytest.raises(ContractError):
            console.step(operation, "second", callback)
        console.step(operation, "first", callback)
        with pytest.raises(ContractError):
            console.step(operation, "first", callback)
        assert callback.call_count == 1
    finally:
        console.finish_workflow(operation, False)


def test_empty_evidence_and_unfinished_steps_cannot_be_green(console):
    operation = console.begin_workflow("route_switch", "vm", [("first", "first")])
    with pytest.raises(ContractError, match="evidence"):
        console.step(operation, "first", lambda: {})
    console.finish_workflow(operation, True)
    assert console.last_operation["status"] == "needs_attention"


def test_old_database_route_schema_migrates_without_losing_history(tmp_path):
    path = tmp_path / "legacy.sqlite"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE route(id INTEGER PRIMARY KEY,environment TEXT,revision INTEGER)"
        )
        db.execute("INSERT INTO route VALUES(1,'vm',17)")
    config = {
        "name": "legacy",
        "run_id": "legacy",
        "account": "test",
        "security_group": "test",
        "revision": "a" * 64,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=1)).isoformat(),
    }
    console = Console(
        config,
        {},
        network=ControlledIngress(),
        database=path,
        start_collector=False,
        tls_context=ssl.create_default_context(),
    )
    try:
        assert console.read_route() == {
            "environment": "vm",
            "revision": 17,
            "last_effect_digest": None,
        }
        assert console.effect_journal.unresolved(console.route_adapter.scope) == ()
    finally:
        console.db.close()


@pytest.mark.parametrize(
    "path,body",
    [
        ("/api/switch", {"environment": []}),
        ("/api/switch", {"environment": {"name": "vm"}}),
        ("/api/security-test", {"action": [], "confirm": True}),
        ("/api/security-test", {"action": "drill", "confirm": 1}),
        ("/api/action", {"message": "test", "automatic": "false"}),
    ],
)
def test_malformed_commands_return_400_without_effects(http_api, console, path, body):
    with pytest.raises(urllib.error.HTTPError) as rejected:
        http_api(path, body)
    assert rejected.value.code == 400
    assert not console.network.calls and console.operation is None
    assert console.db.execute("SELECT count(*) FROM sova_effects_v1").fetchone() == (0,)


def test_route_command_cannot_change_the_workflow_target(console):
    operation = console.begin_workflow("route_switch", "vm", [("route", "route")])
    try:
        with pytest.raises(ContractError, match="workflow target"):
            console.step(operation, "route", lambda: console.route_to("aws"))
        assert console.route == "aws" and console.read_route()["revision"] == 1
        assert console.db.execute(
            "SELECT count(*) FROM sova_effects_v1"
        ).fetchone() == (0,)
    finally:
        console.finish_workflow(operation, False)


def test_duplicate_steps_cannot_be_registered(console):
    with pytest.raises(ContractError, match="unique"):
        console.begin_workflow(
            "route_switch", "vm", [("same", "first"), ("same", "second")]
        )
    assert console.operation is None


def test_stale_in_memory_workflow_cannot_issue_effects(console):
    operation = console.begin_workflow("route_switch", "vm", [("route", "route")])
    console.db.execute(
        "UPDATE workflows SET status='needs_attention' WHERE id=?", (operation["id"],)
    )
    console.db.commit()
    try:
        with pytest.raises(ContractError, match="no longer active"):
            console.step(operation, "route", lambda: console.route_to("vm"))
        assert console.read_route()["environment"] == "aws"
        assert console.db.execute(
            "SELECT count(*) FROM sova_effects_v1"
        ).fetchone() == (0,)
    finally:
        console.finish_workflow(operation, False)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"environment":"aws","environment":"vm"}',
        b'{"environment":NaN}',
        b'{"environment":"\xff"}',
        b"[]",
    ],
)
def test_ambiguous_json_and_invalid_utf8_fail_closed(http_api, console, raw):
    with pytest.raises(urllib.error.HTTPError) as rejected:
        http_api("/api/switch", raw_body=raw)
    assert rejected.value.code == 400 and console.operation is None
    assert console.db.execute("SELECT count(*) FROM sova_effects_v1").fetchone() == (0,)
