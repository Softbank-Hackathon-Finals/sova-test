"""Local HTTP boundary tests; no Kubernetes or production identity implied."""

from datetime import UTC, datetime, timedelta
import http.client
from http.server import ThreadingHTTPServer
import json
import threading
from types import SimpleNamespace
import pytest
from security_console import handler
from operator_auth import OperatorAuth


@pytest.fixture
def console_http():
    console = SimpleNamespace(
        deadline=datetime.now(UTC) + timedelta(minutes=1),
        csrf="test-csrf",
        actions=[],
        snapshot=lambda after: {"after": after, "scope": "test-double"},
    )
    console.start_action = lambda action, digest=None: console.actions.append(
        (action, digest)
    )
    server = ThreadingHTTPServer(("127.0.0.1", 0), http.client.HTTPConnection)
    origin = "http://127.0.0.1:" + str(server.server_port)
    auth = OperatorAuth(deadline=console.deadline, clock=lambda: datetime.now(UTC))
    console.bootstrap = auth.issue_bootstrap()
    console.session_token, session = auth.exchange(console.bootstrap)
    console.csrf = session.csrf
    console.auth = auth
    server.RequestHandlerClass = handler(console, origin, auth)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server, origin, console
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(setup, path, *, method="GET", body=None, headers=None):
    server, _, _ = setup
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        data = response.read()
        return response.status, data
    finally:
        connection.close()


def test_operator_session_host_origin_and_csrf_are_required(console_http):
    _, origin, console = console_http
    assert request(console_http, "/")[0] == 200
    assert request(console_http, "/api/state")[0] == 404
    assert request(console_http, "/", headers={"Host": "attacker.invalid"})[0] == 403
    headers = {
        "Content-Type": "application/json",
        "Cookie": "sova_security=" + console.session_token,
        "Origin": origin,
        "X-Sova-CSRF": console.csrf,
    }
    for missing in ("Cookie", "Origin", "X-Sova-CSRF"):
        changed = dict(headers)
        changed.pop(missing)
        assert (
            request(
                console_http,
                "/api/action",
                method="POST",
                body='{"action":"prepare"}',
                headers=changed,
            )[0]
            == 403
        )
    changed = {**headers, "Origin": "https://attacker.invalid"}
    assert (
        request(
            console_http,
            "/api/action",
            method="POST",
            body='{"action":"prepare"}',
            headers=changed,
        )[0]
        == 403
    )
    assert console.actions == []
    assert (
        request(
            console_http,
            "/api/action",
            method="POST",
            body='{"action":"prepare"}',
            headers=headers,
        )[0]
        == 202
    )
    assert console.actions == [("prepare", None)]


@pytest.mark.parametrize(
    "body",
    [
        '{"action":"prepare","action":"approve"}',
        '{"action":"prepare","command":"rm -rf"}',
        '{"action":"prepare","token":"secret"}',
        '{"action":NaN}',
        "{}",
        "[" * 20 + "0" + "]" * 20,
        "x" * 2049,
    ],
)
def test_ambiguous_or_unregistered_action_fields_are_rejected(console_http, body):
    _, origin, console = console_http
    headers = {
        "Content-Type": "application/json",
        "Cookie": "sova_security=" + console.session_token,
        "Origin": origin,
        "X-Sova-CSRF": console.csrf,
    }
    assert (
        request(console_http, "/api/action", method="POST", body=body, headers=headers)[
            0
        ]
        == 409
    )
    assert console.actions == []


def test_api_state_cursor_and_private_paths(console_http):
    _, _, console = console_http
    headers = {
        "Cookie": "sova_security=" + console.session_token,
        "X-Sova-CSRF": console.csrf,
    }
    status, body = request(console_http, "/api/state?after=10", headers=headers)
    assert status == 200 and json.loads(body)["after"] == 10
    assert json.loads(body)["interfaces"] == {"dependency": False, "migration": False}
    assert request(console_http, "/api/state?after=-1", headers=headers)[0] == 409
    assert (
        request(console_http, "/.local-notes/admin-kubeconfig.json", headers=headers)[0]
        == 404
    )


def test_page_visit_never_grants_operator_cookie_and_bootstrap_replay_denied(
    console_http,
):
    server, origin, console = console_http
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        connection.request("GET", "/")
        response = connection.getresponse()
        assert response.status == 200
        assert response.getheader("Set-Cookie") is None
        assert response.getheader("Referrer-Policy") == "no-referrer"
        assert "login.js" in response.read().decode()
    finally:
        connection.close()
    assert request(console_http, "/workload")[0] == 404
    assert request(console_http, "/security.js")[0] == 404
    assert request(console_http, "/?bootstrap=" + console.bootstrap)[0] == 404
    assert (
        request(
            console_http,
            "/api/session",
            method="POST",
            body=json.dumps({"bootstrap": console.bootstrap}),
            headers={"Content-Type": "application/json", "Origin": origin},
        )[0]
        == 409
    )
    # No HTTP bootstrap secret is ever reflected in the error.
    assert (
        console.bootstrap.encode()
        not in request(
            console_http,
            "/api/session",
            method="POST",
            body=json.dumps({"bootstrap": console.bootstrap}),
            headers={"Content-Type": "application/json", "Origin": origin},
        )[1]
    )


def test_logout_revokes_server_side_session_and_csrf_is_per_session(console_http):
    _, origin, console = console_http
    headers = {
        "Cookie": "sova_security=" + console.session_token,
        "X-Sova-CSRF": console.csrf,
    }
    status, raw = request(console_http, "/api/state", headers=headers)
    assert status == 200 and json.loads(raw)["csrf"] == console.csrf
    headers.update(
        {
            "Content-Type": "application/json",
            "Origin": origin,
            "X-Sova-CSRF": console.csrf,
        }
    )
    assert (
        request(console_http, "/api/logout", method="POST", body="{}", headers=headers)[
            0
        ]
        == 200
    )
    assert request(console_http, "/api/state", headers=headers)[0] == 404
    assert (
        request(
            console_http,
            "/api/action",
            method="POST",
            body='{"action":"prepare"}',
            headers=headers,
        )[0]
        == 403
    )
    assert console.actions == []


def test_cookie_alone_shared_with_another_loopback_port_cannot_read_state(console_http):
    _, origin, console = console_http
    stolen_cookie = {
        "Cookie": "sova_security=" + console.session_token,
        "Origin": origin,
    }
    assert request(console_http, "/api/state", headers=stolen_cookie)[0] == 403
    assert request(console_http, "/api/workload", headers=stolen_cookie)[0] == 403
    for invalid in ["another-origin-proof", "é" * 43]:
        assert (
            request(
                console_http,
                "/api/state",
                headers={**stolen_cookie, "X-Sova-CSRF": invalid},
            )[0]
            == 403
        )
    assert (
        request(
            console_http,
            "/api/state",
            headers={**stolen_cookie, "X-Sova-CSRF": console.csrf},
        )[0]
        == 200
    )


def test_valid_bootstrap_exchanges_without_reflecting_cookie_token(console_http):
    server, origin, console = console_http
    auth = OperatorAuth(deadline=console.deadline, clock=lambda: datetime.now(UTC))
    grant = auth.issue_bootstrap()
    server.RequestHandlerClass = handler(console, origin, auth)
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    try:
        connection.request(
            "POST",
            "/api/session",
            json.dumps({"bootstrap": grant}),
            {"Origin": origin, "Content-Type": "application/json"},
        )
        response = connection.getresponse()
        assert response.status == 200
        cookie = response.getheader("Set-Cookie")
        body = json.loads(response.read())
        assert (
            "HttpOnly" in cookie
            and "SameSite=Strict" in cookie
            and "Max-Age=" in cookie
        )
        token = cookie.split(";")[0]
        assert token.split("=", 1)[1] not in json.dumps(body)
        assert grant not in json.dumps(body)
    finally:
        connection.close()
    assert request(console_http, "/api/state", headers={"Cookie": token})[0] == 403
    assert (
        request(
            console_http,
            "/api/state",
            headers={"Cookie": token, "X-Sova-CSRF": body["origin_proof"]},
        )[0]
        == 200
    )


def test_short_body_cannot_execute_even_with_valid_operator_proof(console_http):
    import socket

    server, origin, console = console_http
    body = b'{"action":"prepare"}'
    headers = (
        "POST /api/action HTTP/1.0\r\nHost: "
        + origin.split("//")[1]
        + "\r\nOrigin: "
        + origin
        + "\r\nCookie: sova_security="
        + console.session_token
        + "\r\nX-Sova-CSRF: "
        + console.csrf
        + "\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body) + 10)
        + "\r\n\r\n"
    ).encode()
    with socket.create_connection(server.server_address, timeout=3) as client:
        client.sendall(headers + body)
        client.shutdown(socket.SHUT_WR)
        response = client.makefile("rb").read()
    assert b"409" in response.splitlines()[0]
    assert console.actions == []


def test_duplicate_or_blank_cursor_is_not_silently_normalized(console_http):
    _, _, console = console_http
    headers = {
        "Cookie": "sova_security=" + console.session_token,
        "X-Sova-CSRF": console.csrf,
    }
    for query in ["after=&after=1", "after=1&after=2", "after=1&unexpected=2", "after"]:
        assert request(console_http, "/api/state?" + query, headers=headers)[0] == 409


def test_recent_history_is_explicit_and_cannot_mix_with_an_old_cursor(console_http):
    _, _, console = console_http
    console.snapshot = lambda after=0, recent=False: {"after": after, "recent": recent}
    headers = {
        "Cookie": "sova_security=" + console.session_token,
        "X-Sova-CSRF": console.csrf,
    }
    status, raw = request(console_http, "/api/state?recent=1", headers=headers)
    assert status == 200 and json.loads(raw)["recent"] is True
    for query in ("recent=0", "recent=", "recent=1&recent=1", "recent=1&after=2"):
        assert request(console_http, "/api/state?" + query, headers=headers)[0] == 409
