"""Real loopback sockets: slow clients are bounded and operator access recovers."""

from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler
import http.client
import socket
import threading
import time
from types import SimpleNamespace
from bounded_http import BoundedLoopbackServer
from operator_auth import OperatorAuth
from security_console import handler


def test_slow_header_connections_cannot_exhaust_unbounded_threads():
    entered = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def handle(self):
            entered.set()
            super().handle()

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = BoundedLoopbackServer(
        ("127.0.0.1", 0), Handler, max_connections=1, read_timeout=0.25
    )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    blocked = None
    try:
        blocked = socket.create_connection(server.server_address, timeout=2)
        assert entered.wait(1)
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        connection.request("GET", "/")
        response = connection.getresponse()
        assert response.status == 503
        response.read()
        connection.close()
        # The slow connection expires without intervention; a new slot works.
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            connection = http.client.HTTPConnection(*server.server_address, timeout=2)
            connection.request("GET", "/")
            response = connection.getresponse()
            status = response.status
            response.read()
            connection.close()
            if status == 200:
                break
            time.sleep(0.05)
        assert status == 200
    finally:
        if blocked:
            blocked.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_oversized_headers_are_rejected_without_console_state_or_authentication():
    deadline = datetime.now(UTC) + timedelta(minutes=1)
    console = SimpleNamespace(deadline=deadline)
    auth = OperatorAuth(deadline=deadline, clock=lambda: datetime.now(UTC))
    server = BoundedLoopbackServer(("127.0.0.1", 0), http.client.HTTPConnection)
    origin = "http://127.0.0.1:" + str(server.server_port)
    server.RequestHandlerClass = handler(console, origin, auth)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        connection.request("GET", "/", headers={"X-Padding": "x" * 9000})
        response = connection.getresponse()
        assert response.status == 431
        response.read()
        connection.close()
        connection = http.client.HTTPConnection(*server.server_address, timeout=2)
        connection.request("GET", "/")
        response = connection.getresponse()
        assert response.status == 200
        assert response.getheader("Set-Cookie") is None
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def test_port_collision_cleans_only_new_bootstrap_and_closes_collector(
    tmp_path, monkeypatch
):
    import security_console

    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    closed = []
    console = SimpleNamespace(
        session={},
        root=root,
        deadline=datetime.now(UTC) + timedelta(minutes=5),
        close=lambda: closed.append(True),
    )
    monkeypatch.setattr(security_console, "SecurityConsole", lambda _: console)
    monkeypatch.setattr(security_console.signal, "signal", lambda *_: None)
    import pytest

    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        with pytest.raises(OSError):
            security_console.main(
                ["--session-root", str(root), "--port", str(occupied.getsockname()[1])]
            )
    assert closed == [True]
    assert not (root / "operator-access.json").exists()
