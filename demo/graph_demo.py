"""Registered local dependency graphs with real processes, HTTP and SQLite.

This is a demo adapter, not discovery, Kubernetes, a firewall or attack detection.
Only owned child processes can be stopped. Profiles never specify code or URLs.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
# Keep source-checkout execution available while sharing the independent model.
if str(ROOT.parent / "src") not in sys.path:
    sys.path.insert(0, str(ROOT.parent / "src"))
from sova.application.graph_catalog import runtime_graph

MAX_BODY = 16384


def load_profiles(path=None):
    path = Path(path) if path else ROOT / "graph_profiles.json"
    if path.stat().st_size > 128 * 1024:
        raise ValueError("profile_too_large")
    data = json.loads(path.read_text())
    if (
        set(data) != {"version", "applications"}
        or data["version"] != 1
        or not isinstance(data["applications"], list)
        or not 1 <= len(data["applications"]) <= 8
    ):
        raise ValueError("invalid_profile_registry")
    profiles = {}

    def identifier(value):
        return isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9-]{0,39}", value)

    def short(value, limit=200):
        return isinstance(value, str) and 0 < len(value) <= limit

    for app in data["applications"]:
        if (
            not isinstance(app, dict)
            or set(app)
            != {
                "id",
                "name",
                "description",
                "entry",
                "fault_default",
                "isolation_default",
                "nodes",
            }
            or not identifier(app["id"])
            or app["id"] in profiles
            or not short(app["name"], 60)
            or not short(app["description"])
            or not isinstance(app["nodes"], list)
            or not 1 <= len(app["nodes"]) <= 16
        ):
            raise ValueError("invalid_application")
        nodes = {}
        for node in app["nodes"]:
            if (
                not isinstance(node, dict)
                or set(node) != {"id", "name", "kind", "description", "dependencies"}
                or not identifier(node["id"])
                or node["id"] in nodes
                or not short(node["name"], 40)
                or not short(node["description"])
                or node["kind"] not in {"service", "storage"}
                or not isinstance(node["dependencies"], list)
                or len(node["dependencies"]) > 8
            ):
                raise ValueError("invalid_node")
            nodes[node["id"]] = node
        for node in nodes.values():
            seen = set()
            for dependency in node["dependencies"]:
                if (
                    not isinstance(dependency, dict)
                    or set(dependency) != {"target", "required"}
                    or dependency["target"] not in nodes
                    or dependency["target"] in seen
                    or type(dependency["required"]) is not bool
                ):
                    raise ValueError("invalid_dependency")
                seen.add(dependency["target"])
            if node["kind"] == "storage" and node["dependencies"]:
                raise ValueError("storage_must_be_leaf")
        if (
            not isinstance(app["entry"], str)
            or app["entry"] not in nodes
            or not isinstance(app["fault_default"], str)
            or app["fault_default"] not in nodes
            or not isinstance(app["isolation_default"], list)
            or any(
                not isinstance(n, str) or n not in nodes
                for n in app["isolation_default"]
            )
            or len(set(app["isolation_default"])) != len(app["isolation_default"])
        ):
            raise ValueError("invalid_application_defaults")
        visiting = set()
        visited = set()

        def visit(node):
            if node in visiting:
                raise ValueError("dependency_cycle")
            if node in visited:
                return
            visiting.add(node)
            for dependency in nodes[node]["dependencies"]:
                visit(dependency["target"])
            visiting.remove(node)
            visited.add(node)

        visit(app["entry"])
        if visited != set(nodes):
            raise ValueError("unreachable_node")
        profiles[app["id"]] = app
    return profiles


def exchange(port, token, path="/health", body=None, timeout=0.6):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    headers = {"X-Component-Token": token, "Connection": "close"}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    try:
        connection.request("GET" if body is None else "POST", path, payload, headers)
        response = connection.getresponse()
        raw = response.read(128 * 1024 + 1)
        if len(raw) > 128 * 1024:
            raise ValueError("oversized_response")
        result = json.loads(raw)
        if not isinstance(result, dict):
            raise ValueError("invalid_response")
        return result
    finally:
        connection.close()


class Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def component_main():
    config = json.loads(sys.stdin.buffer.readline(MAX_BODY))
    node = config["node"]
    fault = threading.Event()
    database = config.get("database")
    if database:
        with sqlite3.connect(database) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS receipts(request_id TEXT PRIMARY KEY,at REAL NOT NULL,message_hash TEXT NOT NULL)"
            )

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def authorized(self):
            return hmac.compare_digest(
                self.headers.get("X-Component-Token", ""), config["token"]
            )

        def do_GET(self):
            if self.path != "/health" or not self.authorized():
                return self.reply(404, {"error": "not_found"})
            rows = None
            if database:
                with sqlite3.connect(database) as db:
                    rows = db.execute("SELECT count(*) FROM receipts").fetchone()[0]
            self.reply(
                200,
                {
                    "node": node,
                    "pid": os.getpid(),
                    "fault": fault.is_set(),
                    "rows": rows,
                },
            )

        def do_POST(self):
            if not self.authorized():
                return self.reply(404, {"error": "not_found"})
            try:
                self.connection.settimeout(2)
                size = int(self.headers.get("Content-Length", "0"))
                if self.headers.get("Transfer-Encoding") or not 0 < size <= MAX_BODY:
                    raise ValueError("body")
                body = json.loads(self.rfile.read(size))
                if not isinstance(body, dict):
                    raise ValueError("body")
                if (
                    self.path == "/fault"
                    and set(body) == {"enabled"}
                    and type(body["enabled"]) is bool
                ):
                    fault.set() if body["enabled"] else fault.clear()
                    return self.reply(200, {"node": node, "fault": fault.is_set()})
                if (
                    self.path != "/invoke"
                    or set(body) != {"request_id", "message"}
                    or not isinstance(body["request_id"], str)
                    or len(body["request_id"]) != 32
                    or not isinstance(body["message"], str)
                    or len(body["message"]) > 80
                ):
                    raise ValueError("request")
            except (ValueError, TypeError, OSError):
                return self.reply(400, {"error": "invalid_request"})
            started = time.perf_counter()
            result = {
                "ok": True,
                "degraded": False,
                "spans": [],
                "edges": [],
                "stores": [],
                "failures": [],
                "request_id": body["request_id"],
            }
            if fault.is_set():
                result.update(ok=False, degraded=True)
                result["failures"].append({"node": node, "error": "injected_http_503"})
            elif database:
                with sqlite3.connect(database) as db:
                    db.execute(
                        "INSERT OR IGNORE INTO receipts VALUES(?,?,?)",
                        (
                            body["request_id"],
                            time.time(),
                            hashlib.sha256(body["message"].encode()).hexdigest(),
                        ),
                    )
                result["stores"].append(node)
            else:
                for dependency in config["dependencies"]:
                    try:
                        child = exchange(
                            dependency["port"],
                            dependency["token"],
                            "/invoke",
                            body,
                            timeout=3,
                        )
                        if child.get("request_id") != body["request_id"]:
                            raise ValueError("response_identity")
                    except (OSError, ValueError, http.client.HTTPException):
                        child = {
                            "ok": False,
                            "degraded": True,
                            "spans": [],
                            "edges": [],
                            "stores": [],
                            "failures": [
                                {
                                    "node": dependency["target"],
                                    "error": "connection_unavailable",
                                }
                            ],
                        }
                    result["edges"].append(
                        {
                            "source": node,
                            "target": dependency["target"],
                            "required": dependency["required"],
                            "ok": bool(child["ok"]),
                            "degraded": bool(child["degraded"]),
                        }
                    )
                    for field in ["spans", "edges", "stores", "failures"]:
                        result[field].extend(child[field])
                    result["degraded"] |= bool(child["degraded"]) or not child["ok"]
                    if not child["ok"] and dependency["required"]:
                        result["ok"] = False
                        break
            result["spans"].insert(
                0,
                {
                    "node": node,
                    "pid": os.getpid(),
                    "ok": result["ok"],
                    "degraded": result["degraded"],
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2),
                },
            )
            result["stored"] = bool(result["stores"])
            self.reply(200 if result["ok"] else 503 if fault.is_set() else 502, result)

    server = Server(("127.0.0.1", config["port"]), Handler)
    server.timeout = 0.3
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    try:
        while not stopped.is_set() and time.time() < config["deadline"]:
            server.handle_request()
    finally:
        server.server_close()


class Runtime:
    def __init__(
        self, directory: Path, profiles=None, application_id=None, deadline=None
    ):
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self.profiles = profiles if profiles is not None else load_profiles()
        self.lock = threading.RLock()
        self.processes = {}
        self.tokens = {}
        self.ports = {}
        self.isolated = set()
        self.last = None
        self.traces = []
        self.events = []
        self.observations = {}
        self.requests = 0
        self.successes = 0
        self.revision = 0
        self.stop = threading.Event()
        self.thread = None
        self.deadline = deadline or time.time() + 7200
        try:
            self.select_application(application_id or next(iter(self.profiles)))
        except BaseException:
            self.close()
            raise

    def emit(self, kind, nodes, message):
        seq = self.events[-1]["seq"] + 1 if self.events else 1
        self.events.append(
            {
                "seq": seq,
                "at": time.time(),
                "kind": kind,
                "nodes": nodes,
                "message": message,
                "application_id": self.profile["id"],
            }
        )
        self.events = self.events[-100:]

    def select_application(self, application_id):
        with self.lock:
            if (
                not isinstance(application_id, str)
                or application_id not in self.profiles
            ):
                raise ValueError("unregistered_application")
            for node in list(self.processes):
                self.stop_node(node)
            self.profile = self.profiles[application_id]
            self.nodes = {n["id"]: n for n in self.profile["nodes"]}
            self.ids = list(self.nodes)
            self.edges = [
                {"source": n["id"], **d}
                for n in self.nodes.values()
                for d in n["dependencies"]
            ]
            self.processes = {}
            self.tokens = {n: secrets.token_hex(24) for n in self.ids}
            self.ports = {}
            self.isolated = set()
            self.observations = {}
            self.last = None
            self.traces = []
            self.requests = 0
            self.successes = 0
            reservations = [
                Server(("127.0.0.1", 0), BaseHTTPRequestHandler) for _ in self.ids
            ]
            self.ports = {n: s.server_port for n, s in zip(self.ids, reservations)}
            for server in reservations:
                server.server_close()
            started = set()

            def start_dependencies(node):
                if node in started:
                    return
                for d in self.nodes[node]["dependencies"]:
                    start_dependencies(d["target"])
                self.start_node(node)
                started.add(node)

            start_dependencies(self.profile["entry"])
            self.revision += 1
            self.system_graph = runtime_graph(
                self.profile, self.revision, self.deadline
            )
            self.emit(
                "application_registered",
                self.ids,
                self.profile["name"]
                + " 등록 구조로 실행 · "
                + str(len(self.ids))
                + "개 독립 프로세스",
            )
            self.sample()
            return self.snapshot()

    def start_node(self, node):
        if node in self.processes and self.processes[node].poll() is None:
            return
        spec = self.nodes[node]
        config = {
            "node": node,
            "port": self.ports[node],
            "token": self.tokens[node],
            "deadline": self.deadline,
            "dependencies": [
                {
                    **d,
                    "port": self.ports[d["target"]],
                    "token": self.tokens[d["target"]],
                }
                for d in spec["dependencies"]
            ],
        }
        if spec["kind"] == "storage":
            location = self.directory / self.profile["id"]
            location.mkdir(exist_ok=True)
            config["database"] = str(location / (node + ".sqlite3"))
        process = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--component"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={
                "PATH": os.defpath,
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUNBUFFERED": "1",
            },
        )
        self.processes[node] = process
        process.stdin.write(json.dumps(config).encode() + b"\n")
        process.stdin.close()
        for _ in range(40):
            if process.poll() is not None:
                raise RuntimeError("component_start_failed:" + node)
            try:
                observed = exchange(self.ports[node], self.tokens[node])
                if observed.get("node") == node and observed.get("pid") == process.pid:
                    return
            except (OSError, ValueError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        raise RuntimeError("component_readiness_timeout:" + node)

    def stop_node(self, node):
        process = self.processes.get(node)
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if process is not None and process.poll() is None:
            raise RuntimeError("component_stop_unconfirmed:" + node)

    def sample(self):
        with self.lock:
            request_id = secrets.token_hex(16)
            started = time.perf_counter()
            entry = self.profile["entry"]
            try:
                result = exchange(
                    self.ports[entry],
                    self.tokens[entry],
                    "/invoke",
                    {
                        "request_id": request_id,
                        "message": "Sova registered dependency probe",
                    },
                    timeout=4,
                )
                if result.get("request_id") != request_id:
                    raise ValueError("request_mismatch")
            except (OSError, ValueError, http.client.HTTPException):
                result = {
                    "ok": False,
                    "degraded": True,
                    "failures": [{"node": entry, "error": "entry_unavailable"}],
                    "spans": [],
                    "edges": [],
                    "stores": [],
                    "stored": False,
                }
            result.update(
                request_id=request_id,
                at=time.time(),
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            self.requests += 1
            self.successes += bool(result["ok"])
            self.last = result
            self.traces.append(result)
            self.traces = self.traces[-40:]
            for node in self.ids:
                at = time.time()
                try:
                    observed = exchange(self.ports[node], self.tokens[node])
                    if (
                        observed.get("node") != node
                        or observed.get("pid") != self.processes[node].pid
                    ):
                        raise ValueError("identity_mismatch")
                    observed.update(available=True, at=at)
                except (OSError, ValueError, http.client.HTTPException):
                    observed = {
                        "available": False,
                        "at": at,
                        "pid": None,
                        "fault": False,
                        "rows": None,
                    }
                self.observations[node] = observed
            return result

    def snapshot(self):
        with self.lock:
            now = time.time()
            nodes = []
            last = self.last or {}
            spans = {s["node"]: s for s in last.get("spans", [])}
            for node, spec in self.nodes.items():
                observation = self.observations.get(node, {})
                stale = now - observation.get("at", 0) > 6
                span = spans.get(node)
                state = (
                    "unknown"
                    if stale
                    else "isolated"
                    if node in self.isolated
                    else "failed"
                    if not observation.get("available") or observation.get("fault")
                    else "impacted"
                    if span and (not span["ok"] or span["degraded"])
                    else "healthy"
                )
                nodes.append(
                    {
                        **spec,
                        "state": state,
                        "observation": observation,
                        "stale": stale,
                        "called": span is not None,
                        "selected_effect": "owned_process_stopped"
                        if node in self.isolated
                        else None,
                    }
                )
            return {
                "now": now,
                "revision": self.revision,
                "system_graph": {
                    "digest": self.system_graph.fingerprint,
                    "origin": self.system_graph.origin,
                    "review_units": [
                        list(g) for g in self.system_graph.movement_groups()
                    ],
                },
                "application": {
                    k: self.profile[k]
                    for k in [
                        "id",
                        "name",
                        "description",
                        "entry",
                        "fault_default",
                        "isolation_default",
                    ]
                },
                "applications": [
                    {"id": p["id"], "name": p["name"], "node_count": len(p["nodes"])}
                    for p in self.profiles.values()
                ],
                "nodes": nodes,
                "edges": self.edges,
                "last_request": self.last,
                "traces": list(reversed(self.traces)),
                "events": list(reversed(self.events)),
                "requests": self.requests,
                "successes": self.successes,
                "isolated": sorted(self.isolated),
                "scope": "registered local demo; real processes/HTTP/SQLite; manual fault; process-stop isolation; not auto-discovery, Kubernetes, firewall or migration",
            }

    def action(self, action, nodes):
        with self.lock:
            if action not in {"isolate", "restore", "fault", "clear_fault", "probe"}:
                raise ValueError("unsupported_action")
            if (
                not isinstance(nodes, list)
                or any(not isinstance(n, str) or n not in self.nodes for n in nodes)
                or len(set(nodes)) != len(nodes)
            ):
                raise ValueError("invalid_nodes")
            if action in {"isolate", "restore"}:
                if not nodes:
                    raise ValueError("select_nodes")
                for node in nodes:
                    if action == "isolate":
                        self.stop_node(node)
                        self.isolated.add(node)
                    else:
                        self.start_node(node)
                        self.isolated.discard(node)
                self.emit(
                    action,
                    nodes,
                    "소유 프로세스 종료 확인"
                    if action == "isolate"
                    else "프로세스 재기동·신원 확인",
                )
            elif action in {"fault", "clear_fault"}:
                if len(nodes) != 1 or nodes[0] in self.isolated:
                    raise ValueError("select_running_node")
                node = nodes[0]
                observed = exchange(
                    self.ports[node],
                    self.tokens[node],
                    "/fault",
                    {"enabled": action == "fault"},
                )
                if observed.get("fault") is not (action == "fault"):
                    raise RuntimeError("fault_readback_failed")
                self.emit(
                    action,
                    nodes,
                    self.nodes[node]["name"]
                    + (
                        " 수동 HTTP 503 주입"
                        if action == "fault"
                        else " 장애 주입 해제"
                    ),
                )
            elif nodes:
                raise ValueError("probe_nodes_must_be_empty")
            self.revision += 1
            self.sample()
            return self.snapshot()

    def start_collection(self):
        def collect():
            while not self.stop.wait(2):
                try:
                    self.sample()
                except Exception:
                    with self.lock:
                        self.emit("collector_error", [], "관측 실패 · 신선도 확인 필요")

        self.thread = threading.Thread(target=collect, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread is not None:
            self.thread.join(timeout=8)
        for node in list(self.processes):
            self.stop_node(node)


def handler(runtime, origin, token, deadline):
    expected_host = urlsplit(origin).netloc
    web = ROOT / "graph_web"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def trusted(self):
            return self.headers.get("Host") == expected_host

        def authenticated(self):
            try:
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                return "sova_graph" in cookie and hmac.compare_digest(
                    cookie["sova_graph"].value, token
                )
            except Exception:
                return False

        def reply(self, status, body, kind="application/json", cookie=False):
            raw = (
                body
                if isinstance(body, bytes)
                else json.dumps(body, ensure_ascii=False).encode()
            )
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            if cookie:
                self.send_header(
                    "Set-Cookie",
                    "sova_graph=" + token + "; HttpOnly; SameSite=Strict; Path=/",
                )
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if not self.trusted():
                return self.reply(403, {"error": "host_denied"})
            assets = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/graph.js": ("graph.js", "text/javascript"),
                "/graph.css": ("graph.css", "text/css"),
            }
            if self.path in assets:
                name, kind = assets[self.path]
                return self.reply(
                    200, (web / name).read_bytes(), kind, cookie=self.path == "/"
                )
            if self.path == "/api/state" and self.authenticated():
                result = runtime.snapshot()
                result["expires_at"] = deadline.isoformat()
                return self.reply(200, result)
            return self.reply(404, {"error": "not_found"})

        def do_POST(self):
            if (
                not self.trusted()
                or not self.authenticated()
                or self.headers.get("Origin") != origin
            ):
                return self.reply(403, {"error": "origin_or_session_denied"})
            if datetime.now(timezone.utc) >= deadline:
                return self.reply(409, {"error": "demo_expired"})
            try:
                self.connection.settimeout(2)
                size = int(self.headers.get("Content-Length", "0"))
                if (
                    self.path not in {"/api/action", "/api/application"}
                    or self.headers.get("Content-Type") != "application/json"
                    or self.headers.get("Transfer-Encoding")
                    or not 0 < size <= MAX_BODY
                ):
                    raise ValueError("invalid_request")
                body = json.loads(self.rfile.read(size))
                if self.path == "/api/application":
                    if not isinstance(body, dict) or set(body) != {"application_id"}:
                        raise ValueError("invalid_application")
                    result = runtime.select_application(body["application_id"])
                    result["expires_at"] = deadline.isoformat()
                    return self.reply(200, result)
                if (
                    not isinstance(body, dict)
                    or set(body) != {"action", "nodes"}
                    or not isinstance(body["action"], str)
                ):
                    raise ValueError("invalid_action")
                result = runtime.action(body["action"], body["nodes"])
                result["expires_at"] = deadline.isoformat()
                return self.reply(200, result)
            except (ValueError, TypeError):
                return self.reply(400, {"error": "invalid_action"})
            except (OSError, RuntimeError, http.client.HTTPException):
                runtime.sample()
                return self.reply(409, {"error": "action_unconfirmed_check_state"})

    return Handler


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", action="store_true")
    parser.add_argument("--port", type=int, default=8791)
    parser.add_argument("--until", required=False)
    parser.add_argument(
        "--state-root", type=Path, help="Owner-private per-run metadata directory"
    )
    args = parser.parse_args()
    if args.component:
        return component_main()
    deadline = (
        datetime.fromisoformat(args.until)
        if args.until
        else datetime.fromtimestamp(time.time() + 1800, timezone.utc)
    )
    if (
        deadline.tzinfo is None
        or not 0 < (deadline - datetime.now(timezone.utc)).total_seconds() <= 43200
    ):
        parser.error("Use a timezone-aware deadline within the next twelve hours")
    notes = args.state_root or ROOT.parent / ".local-notes/graph-demo-20261031"
    notes.mkdir(parents=True, mode=0o700, exist_ok=True)
    if args.state_root and (
        notes.is_symlink()
        or notes.stat().st_uid != os.geteuid()
        or notes.stat().st_mode & 0o077
    ):
        parser.error("owner-private state directory required")
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    with tempfile.TemporaryDirectory(
        prefix="sova-graph-", dir=notes if args.state_root else None
    ) as directory:
        runtime = Runtime(Path(directory), deadline=deadline.timestamp())
        try:
            origin = f"http://127.0.0.1:{args.port}"
            server = Server(
                ("127.0.0.1", args.port),
                handler(runtime, origin, secrets.token_urlsafe(32), deadline),
            )
            server.timeout = 0.5
            runtime.start_collection()
            (notes / "server.json").write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "url": origin,
                        "expires_at": deadline.isoformat(),
                        "child_pids": {n: p.pid for n, p in runtime.processes.items()},
                    },
                    indent=2,
                )
            )
            print("Sova dependency demo: " + origin, flush=True)
            try:
                while not stopped.is_set() and datetime.now(timezone.utc) < deadline:
                    server.handle_request()
            finally:
                server.server_close()
                (notes / "last-state.json").write_text(
                    json.dumps(runtime.snapshot(), ensure_ascii=False, indent=2)
                )
        finally:
            runtime.close()
            (notes / "shutdown.json").write_text(
                json.dumps(
                    {
                        "stopped_at": datetime.now(timezone.utc).isoformat(),
                        "children_exited": all(
                            p.poll() is not None for p in runtime.processes.values()
                        ),
                    }
                )
            )


if __name__ == "__main__":
    main()
