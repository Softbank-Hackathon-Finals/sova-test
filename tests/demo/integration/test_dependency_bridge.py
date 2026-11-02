"""Actual loopback HTTP; fixed test processes, never a generic proxy."""

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
import threading
from types import SimpleNamespace

import pytest

from console_web import ConsoleWebBundle
from dependency_bridge import DependencyBridge
from operator_auth import OperatorAuth
from security_console import handler
from sova.domain.contracts import ContractError


@pytest.fixture
def upstream():
    requests = []
    response_state = {
        "nodes": [{"id": "api"}],
        "revision": 1,
        "scope": "registered local demo; test",
    }

    class Lab(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            requests.append(("GET", self.path, dict(self.headers)))
            self.send_response(200)
            if self.path == "/":
                self.send_header("Set-Cookie", "sova_graph=" + "x" * 43 + "; HttpOnly")
            self.end_headers()
            self.wfile.write(
                b"lab" if self.path == "/" else json.dumps(response_state).encode()
            )

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(("POST", self.path, dict(self.headers), body))
            if body.get("action") == "restore":
                self.close_connection = True
                return  # Applied request, lost acknowledgement: must not retry.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(response_state).encode())

    server = ThreadingHTTPServer(("127.0.0.1", 0), Lab)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield DependencyBridge(server.server_port), requests, response_state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_bridge_uses_only_its_upstream_cookie_and_fixed_paths(upstream):
    bridge, calls, _ = upstream
    assert bridge.state()["revision"] == 1
    bridge.action({"action": "fault", "nodes": ["api"]})
    assert [c[1] for c in calls] == ["/", "/api/state", "/api/action"]
    assert calls[-1][2]["Cookie"] == "sova_graph=" + "x" * 43
    assert calls[-1][2]["Origin"] == bridge.origin
    assert "X-Sova-CSRF" not in calls[-1][2]
    assert "sova_security" not in str(calls)


def test_lost_mutation_acknowledgement_is_never_retried(upstream):
    bridge, calls, _ = upstream
    with pytest.raises(ContractError, match="no automatic retry"):
        bridge.action({"action": "restore", "nodes": ["api"]})
    assert sum(c[0] == "POST" for c in calls) == 1


@pytest.mark.parametrize(
    "body",
    [
        {"action": [], "nodes": []},
        {"action": "shell", "nodes": []},
        {"action": "probe", "nodes": [], "url": "http://attacker.invalid"},
        {"action": "isolate", "nodes": ["api", "api"]},
        {"action": "fault", "nodes": [{}]},
    ],
)
def test_invalid_or_unbounded_action_never_reaches_upstream(upstream, body):
    bridge, calls, _ = upstream
    with pytest.raises(ContractError):
        bridge.action(body)
    assert not calls


def test_unknown_upstream_identity_is_not_a_registered_lab(upstream):
    bridge, _, state = upstream
    state["scope"] = "other service"
    with pytest.raises(ContractError, match="Registered dependency"):
        bridge.state()


def test_console_bridge_requires_operator_cookie_origin_and_proof(tmp_path):
    (tmp_path / "assets").mkdir()
    (tmp_path / "index.html").write_text('<div id="react-test"></div>')
    (tmp_path / "assets/app.js").write_text("export {}")
    bundle = ConsoleWebBundle(tmp_path)
    calls = []
    bridge = SimpleNamespace(
        state=lambda: calls.append("read") or {"scope": "test"},
        action=lambda body: calls.append(body) or {"scope": "test"},
    )
    console = SimpleNamespace(deadline=datetime.now(UTC) + timedelta(minutes=2))
    auth = OperatorAuth(deadline=console.deadline, clock=lambda: datetime.now(UTC))
    token, session = auth.exchange(auth.issue_bootstrap())
    server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    server.daemon_threads = True
    origin = "http://127.0.0.1:" + str(server.server_port)
    server.RequestHandlerClass = handler(
        console, origin, auth, ui_bundle=bundle, dependency_bridge=bridge
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def call(path, body=None, headers=None):
        c = http.client.HTTPConnection(*server.server_address, timeout=3)
        c.request("GET" if body is None else "POST", path, body, headers or {})
        r = c.getresponse()
        result = (r.status, r.read(), r.getheader("Content-Security-Policy"))
        c.close()
        return result

    headers = {
        "Cookie": "sova_security=" + token,
        "X-Sova-CSRF": session.csrf,
        "Origin": origin,
        "Content-Type": "application/json",
    }
    try:
        assert b"react-test" not in call("/")[1]
        assert call("/api/dependency/state")[0] == 404
        assert (
            call("/api/dependency/state", headers={"Cookie": headers["Cookie"]})[0]
            == 403
        )
        assert not calls
        status, body, csp = call("/", headers=headers)
        assert status == 200 and b"react-test" in body
        assert b"react-test" in call("/?view=workloads", headers=headers)[1]
        assert (
            "script-src 'self';" in csp
            and "script-src 'self' 'unsafe-inline'" not in csp
        )
        assert "style-src 'self' 'unsafe-inline'" in csp
        assert call("/api/dependency/state", headers=headers)[0] == 200
        assert (
            call(
                "/api/dependency/action",
                '{"action":"probe","nodes":[]}',
                {**headers, "Origin": "https://attacker.invalid"},
            )[0]
            == 403
        )
        assert calls == ["read"]
        assert (
            call("/api/dependency/action", '{"action":"probe","nodes":[]}', headers)[0]
            == 200
        )
        assert len(calls) == 2
        assert call("/console/assets/../../.env", headers=headers)[0] == 404
        assert b"security.js" in call("/legacy", headers=headers)[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
