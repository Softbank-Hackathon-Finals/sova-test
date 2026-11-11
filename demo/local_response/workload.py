"""Actual bounded workload: PostgreSQL messages, durable queue, worker and HTTP.

Synthetic local application. No AWS emulation, arbitrary URLs, shell execution,
production credentials, or real vulnerability/exploit. Faults are explicit tests.
"""

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

import psycopg

ROLE = os.environ.get("ROLE", "api")
ENV = os.environ.get("ENVIRONMENT", "local-source")
RELEASE = os.environ.get("RELEASE", "v1")
UID = os.environ.get("POD_UID", "unregistered")
STATE = {"fault": False, "write_open": False, "route": "source"}
LOCK = threading.RLock()
AUDIT = []


def secret(name):
    return Path("/credentials", name).read_text().strip()


def connection(*, password=None):
    return psycopg.connect(
        host=os.environ.get("DB_HOST", "db"),
        dbname="workload",
        user="app",
        password=password or secret("password"),
        connect_timeout=2,
        options="-c statement_timeout=2000 -c lock_timeout=1000",
    )


def http(host, path="/health", *, method="GET", body=None, token=None):
    # Host is from the fixed deployment contract, never from an HTTP request.
    headers = {"Content-Type": "application/json", "X-Request-ID": os.urandom(16).hex()}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(
        "http://" + host + ":8080" + path,
        data=None if body is None else json.dumps(body).encode(),
        headers=headers,
        method=method,
    )
    try:
        with urlopen(request, timeout=2) as response:
            return {"status": response.status, "body": json.loads(response.read(32768))}
    except HTTPError as error:
        return {"status": error.code, "body": json.loads(error.read(32768))}
    except (OSError, URLError, ValueError):
        return {"status": None, "error": "connection_unavailable"}


def base():
    return {
        "role": ROLE,
        "environment": ENV,
        "release": RELEASE,
        "pod_uid": UID,
        "observed_at": time.time(),
    }


def fingerprint():
    with connection() as db:
        messages = db.execute(
            'SELECT id, body FROM messages ORDER BY id COLLATE "C"'
        ).fetchall()
        jobs = db.execute(
            'SELECT id, body, completed FROM jobs ORDER BY id COLLATE "C"'
        ).fetchall()
    raw = json.dumps(
        [messages, jobs], ensure_ascii=False, separators=(",", ":")
    ).encode()
    return {
        "messages": len(messages),
        "jobs": len(jobs),
        "completed": sum(row[2] for row in jobs),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


def worker():
    while True:
        try:
            if not STATE["fault"]:
                with connection() as db:
                    row = db.execute(
                        "SELECT id FROM jobs WHERE NOT completed ORDER BY id FOR UPDATE SKIP LOCKED LIMIT 1"
                    ).fetchone()
                    if row:
                        db.execute(
                            "UPDATE jobs SET completed=true, worker_uid=%s WHERE id=%s",
                            (UID, row[0]),
                        )
        except (psycopg.Error, OSError):
            pass
        time.sleep(0.4)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def reply(self, code, body):
        raw = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass
        self.close_connection = True

    def body(self):
        self.connection.settimeout(3)
        length = self.headers.get("Content-Length", "")
        if (
            self.headers.get("Transfer-Encoding")
            or not length.isdecimal()
            or not 0 < int(length) <= 8192
        ):
            raise ValueError()
        value = json.loads(self.rfile.read(int(length)))
        if type(value) is not dict:
            raise ValueError()
        return value

    def admin(self):
        return hmac.compare_digest(
            self.headers.get("Authorization", ""), "Bearer " + secret("admin")
        )

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/stream":
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                for sequence in range(120):
                    self.wfile.write(
                        (json.dumps({**base(), "sequence": sequence}) + "\n").encode()
                    )
                    self.wfile.flush()
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            self.close_connection = True
            return
        if path in {"/health", "/ready"}:
            value = base()
            value["request_id"] = self.headers.get("X-Request-ID")
            value["fault"] = STATE["fault"]
            value["write_open"] = STATE["write_open"]
            if ROLE in {"api", "worker"}:
                value["db_host"] = os.environ.get("DB_HOST", "db")
            if ROLE == "edge":
                value["route"] = STATE["route"]
            return self.reply(503 if STATE["fault"] else 200, value)
        if path == "/security-check":
            return self.reply(
                200,
                {
                    **base(),
                    "legacy_feature_enabled": RELEASE == "v1",
                    "controlled_regression": True,
                },
            )
        if path == "/protected":
            nonce = self.headers.get("X-Request-ID", "")
            if not re.fullmatch("[a-f0-9]{32}", nonce):
                return self.reply(400, {"error": "nonce_required"})
            with LOCK:
                AUDIT.append(
                    {
                        "nonce": nonce,
                        "status": 403,
                        "peer": self.client_address[0],
                        "target_uid": UID,
                        "at": time.time(),
                    }
                )
                del AUDIT[:-100]
            return self.reply(403, {"denied": True, "nonce": nonce, "pod_uid": UID})
        if path == "/audit" and self.admin():
            return self.reply(200, {"events": list(AUDIT)})
        if ROLE == "edge" and path in {"/", "/messages", "/fingerprint"}:
            result = http(
                os.environ["SOURCE_API"]
                if STATE["route"] == "source"
                else os.environ["TARGET_API"],
                "/messages" if path == "/" else path,
            )
            return self.reply(
                result.get("status") or 503,
                result.get("body", {"error": result.get("error")}),
            )
        if ROLE in {"api", "worker"} and path in {"/messages", "/fingerprint"}:
            if RELEASE == "bad":
                return self.reply(500, {"error": "controlled_release_regression"})
            try:
                if path == "/fingerprint":
                    return self.reply(
                        200,
                        {**base(), **fingerprint(), "write_open": STATE["write_open"]},
                    )
                with connection() as db:
                    rows = db.execute(
                        "SELECT id, body FROM messages ORDER BY id LIMIT 100"
                    ).fetchall()
                return self.reply(
                    200,
                    {
                        **base(),
                        "messages": [{"id": row[0], "body": row[1]} for row in rows],
                    },
                )
            except (psycopg.Error, OSError):
                return self.reply(503, {"error": "database_unavailable"})
        return self.reply(404, {"error": "not_found"})

    def do_POST(self):
        try:
            body = self.body()
        except (ValueError, OSError):
            return self.reply(400, {"error": "invalid_request"})
        path = urlsplit(self.path).path
        if path.startswith("/admin/"):
            if not self.admin():
                return self.reply(403, {"error": "admin_required"})
            if (
                path == "/admin/fault"
                and set(body) == {"enabled"}
                and type(body["enabled"]) is bool
            ):
                STATE["fault"] = body["enabled"]
            elif (
                path == "/admin/write"
                and set(body) == {"enabled"}
                and type(body["enabled"]) is bool
            ):
                with LOCK:
                    STATE["write_open"] = body["enabled"]
            elif (
                path == "/admin/route"
                and ROLE == "edge"
                and body.get("route") in {"source", "target"}
                and set(body) == {"route"}
            ):
                STATE["route"] = body["route"]
            elif (
                path == "/admin/check"
                and set(body) == {"target"}
                and body["target"] in {"external", "auth", "db"}
            ):
                if body["target"] == "db":
                    try:
                        with connection() as db:
                            db.execute("SELECT 1").fetchone()
                        return self.reply(200, {"connected": True})
                    except (psycopg.Error, OSError):
                        return self.reply(200, {"connected": False})
                return self.reply(
                    200, http(os.environ[body["target"].upper() + "_HOST"])
                )
            elif (
                path == "/admin/attempt"
                and set(body) == {"nonce"}
                and re.fullmatch("[a-f0-9]{32}", str(body["nonce"]))
            ):
                request = Request(
                    "http://" + os.environ["AUTH_HOST"] + ":8080/protected",
                    headers={"X-Request-ID": body["nonce"]},
                )
                try:
                    with urlopen(request, timeout=2) as response:
                        return self.reply(200, {"upstream_status": response.status})
                except HTTPError as error:
                    return self.reply(
                        200,
                        {
                            "upstream_status": error.code,
                            "receipt": json.loads(error.read(8192)),
                        },
                    )
                except (OSError, URLError):
                    return self.reply(503, {"error": "attempt_unavailable"})
            else:
                return self.reply(400, {"error": "unsupported_action"})
            return self.reply(200, {**base(), **STATE})
        if ROLE == "edge" and path in {"/messages", "/jobs"}:
            result = http(
                os.environ["SOURCE_API"]
                if STATE["route"] == "source"
                else os.environ["TARGET_API"],
                path,
                method="POST",
                body=body,
            )
            return self.reply(
                result.get("status") or 503,
                result.get("body", {"error": "upstream_unavailable"}),
            )
        if ROLE == "api" and path in {"/messages", "/jobs"}:
            if (
                set(body) != {"id", "body"}
                or not re.fullmatch("[a-f0-9]{32}", str(body.get("id")))
                or type(body.get("body")) is not str
                or not 0 < len(body["body"]) <= 200
            ):
                return self.reply(400, {"error": "bounded_message_required"})
            with LOCK:
                if not STATE["write_open"] or STATE["fault"]:
                    return self.reply(503, {"error": "writes_held"})
                try:
                    with connection() as db:
                        table = "messages" if path == "/messages" else "jobs"
                        # table is one of two constants, not user input.
                        previous = db.execute(
                            f"SELECT body FROM {table} WHERE id=%s", (body["id"],)
                        ).fetchone()
                        if previous and previous[0] != body["body"]:
                            return self.reply(409, {"error": "idempotency_conflict"})
                        db.execute(
                            f"INSERT INTO {table}(id,body) VALUES(%s,%s) ON CONFLICT(id) DO NOTHING",
                            (body["id"], body["body"]),
                        )
                    return self.reply(
                        200, {**base(), "id": body["id"], "accepted": True}
                    )
                except (psycopg.Error, OSError):
                    return self.reply(503, {"error": "database_unavailable"})
        return self.reply(404, {"error": "not_found"})


def main():
    if ROLE == "worker":
        threading.Thread(target=worker, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()


if __name__ == "__main__":
    main()
