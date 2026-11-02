"""Loopback HTTP only. AWS/VM operations are explicit test doubles."""

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import threading
import time
from types import SimpleNamespace

import pytest
from migration_bridge import MigrationBridge
from operator_auth import OperatorAuth
from security_console import handler
from sova.domain.contracts import ContractError


@pytest.fixture
def upstream():
    calls = []
    state = {
        "now": time.time(),
        "route": "aws",
        "route_revision": 1,
        "revision": "a" * 64,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
        "scope": "실제 AWS·VM 요청 / explicit test double",
        "workloads": {"aws": {"database": False}, "vm": {"database": False}},
        "observations": {},
        "events": [],
        "workflows": [],
    }

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            calls.append(("GET", self.path, dict(self.headers)))
            self.send_response(200)
            if self.path == "/":
                self.send_header(
                    "Set-Cookie", "sova_preview=" + "u" * 43 + "; HttpOnly"
                )
            self.end_headers()
            self.wfile.write(
                b"preview" if self.path == "/" else json.dumps(state).encode()
            )

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            calls.append(("POST", self.path, dict(self.headers), body))
            if state.get("lose_ack"):
                self.close_connection = True
                return
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b'{"id":"test-operation","status":"running"}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield MigrationBridge(server.server_port), calls, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def action(**change):
    return {
        "action": "switch",
        "environment": "vm",
        "revision": "a" * 64,
        "route_revision": 1,
        **change,
    }


def test_separate_cookie_fixed_target_and_checked_binding(upstream):
    bridge, calls, _ = upstream
    assert bridge.state()["status"] == "connected"
    assert bridge.action(action())["status"] == "accepted-not-complete"
    post = calls[-1]
    assert post[1] == "/api/switch-checked"
    assert post[2]["Cookie"] == "sova_preview=" + "u" * 43
    assert post[2]["Origin"] == bridge.origin
    assert "X-Sova-CSRF" not in post[2]
    assert post[3] == {"environment": "vm", "revision": "a" * 64, "route_revision": 1}
    assert "sova_security" not in str(calls)


def test_owner_bootstrap_secret_is_sent_only_to_bootstrap(upstream):
    bridge, calls, _ = upstream
    secret = "private-bridge-" + "s" * 32
    bridge._bootstrap_token_provider = lambda: secret
    assert bridge.state()["status"] == "connected"
    bridge.action(action())
    assert calls[0][2]["X-Sova-Bridge"] == secret
    assert all("X-Sova-Bridge" not in c[2] for c in calls[1:])


def test_invalid_bootstrap_secret_never_reaches_backend(upstream):
    bridge, calls, _ = upstream
    bridge._bootstrap_token_provider = lambda: "injected\r\nHeader: bad"
    assert bridge.state()["status"] == "unavailable"
    assert calls == []


@pytest.mark.parametrize(
    "change",
    [
        {"route_revision": 2},
        {"revision": "b" * 64},
        {"action": []},
        {"environment": []},
        {"action": "shell"},
        {"url": "http://attacker.invalid"},
        {"route_revision": True},
    ],
)
def test_invalid_or_changed_approval_never_mutates(upstream, change):
    bridge, calls, _ = upstream
    with pytest.raises(ContractError):
        bridge.action(action(**change))
    assert not any(c[0] == "POST" for c in calls)


@pytest.mark.parametrize(
    "change",
    [
        {"expires_at": "2020-01-01T00:00:00+00:00"},
        {"expires_at": "2099-01-01"},
        {"now": 1},
        {"scope": "other service"},
        {"revision": "not-a-digest"},
    ],
)
def test_expired_stale_or_wrong_service_cannot_switch(upstream, change):
    bridge, calls, state = upstream
    state.update(change)
    result = bridge.state()
    assert result["status"] == "unavailable" and result["state"] is None
    with pytest.raises(ContractError):
        bridge.action(action())
    assert not any(c[0] == "POST" for c in calls)


def test_applied_but_lost_ack_is_never_retried(upstream):
    bridge, calls, state = upstream
    state["lose_ack"] = True
    with pytest.raises(ContractError, match="no automatic retry"):
        bridge.action(action())
    assert sum(c[0] == "POST" for c in calls) == 1


def test_probe_serializes_korean_message_as_utf8(upstream):
    bridge, calls, _ = upstream
    bridge.action(action(action="probe", environment="aws"))
    assert calls[-1][1] == "/api/action"
    assert calls[-1][3] == {"message": "Sova 통합 콘솔 업무 요청", "automatic": False}


def test_six_area_readiness_only_maps_fresh_owned_fixture_health(upstream):
    bridge, _, state = upstream
    state["registered_at"] = (datetime.now(UTC) - timedelta(minutes=1)).isoformat()
    source, target = "sova-probe-abcdef012345-aws", "sova-probe-abcdef012345-vm"
    state["workloads"]["aws"]["instance"] = source
    state["workloads"]["vm"]["instance"] = target
    state["observations"]["vm"] = {
        "available": True,
        "observed_at": time.time() - 1,
        "instance": target,
    }
    result = bridge.readiness()
    assert result["status"] == "connected"
    report = result["report"]
    rows = [r for a in report["areas"] for r in a["requirements"]]
    assert len(rows) == 24
    assert [r["id"] for r in rows if r["result"] == "pass"] == ["migration:target-http"]
    assert not report["all_areas_verified"] and not report["execution_authorized"]
    assert datetime.fromisoformat(result["expires_at"]) < datetime.now(UTC) + timedelta(
        seconds=8
    )
    state["observations"]["vm"]["observed_at"] = time.time() - 30
    result = bridge.readiness()
    assert all(
        r["result"] == "unknown"
        for a in result["report"]["areas"]
        for r in a["requirements"]
    )


def test_readiness_does_not_invent_program_without_its_own_registration(upstream):
    bridge, _, _ = upstream
    result = bridge.readiness()
    assert result["status"] == "unavailable" and result["report"] is None
    assert len(result["catalog"]) == 6


def test_console_migration_requires_cookie_and_origin_proof():
    calls = []
    bridge = SimpleNamespace(
        state=lambda: calls.append("read") or {"status": "unavailable"},
        action=lambda body: calls.append(body) or {"status": "accepted-not-complete"},
    )
    console = SimpleNamespace(deadline=datetime.now(UTC) + timedelta(minutes=2))
    auth = OperatorAuth(deadline=console.deadline, clock=lambda: datetime.now(UTC))
    token, session = auth.exchange(auth.issue_bootstrap())
    server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    origin = f"http://127.0.0.1:{server.server_port}"
    server.RequestHandlerClass = handler(console, origin, auth, migration_bridge=bridge)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, body=None, headers=None):
        conn = http.client.HTTPConnection(*server.server_address, timeout=3)
        conn.request("GET" if body is None else "POST", path, body, headers or {})
        response = conn.getresponse()
        status = response.status
        response.read()
        conn.close()
        return status

    headers = {
        "Cookie": "sova_security=" + token,
        "X-Sova-CSRF": session.csrf,
        "Origin": origin,
        "Content-Type": "application/json",
    }
    try:
        assert request("/api/migration/state") == 404
        assert (
            request("/api/migration/state", headers={"Cookie": headers["Cookie"]})
            == 403
        )
        assert (
            request(
                "/api/migration/action",
                "{}",
                {**headers, "Origin": "http://attacker.invalid"},
            )
            == 403
        )
        assert calls == []
        assert request("/api/migration/state", headers=headers) == 200
        assert request("/api/migration/action", "{}", headers) == 202
        assert calls == ["read", {}]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
