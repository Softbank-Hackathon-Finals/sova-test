"""Loopback console for the fixed local RKE2 workload response runner."""

import argparse
from datetime import UTC, datetime, timedelta
import fcntl
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
from urllib.parse import urlsplit

from operator_auth import OperatorAuth
from response_scenarios.__main__ import assets, PREFIX
from .provision import private_json
from .runtime import Runtime

CSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"


def local_assets():
    result = assets()
    path = Path(__file__).parents[1] / "response_scenarios" / "runtime_client.mjs"
    result[PREFIX + "runtime_client.mjs"] = (
        path.read_bytes(),
        "text/javascript; charset=utf-8",
    )
    result["/app/"] = (
        (Path(__file__).parent / "app.html").read_bytes(),
        "text/html; charset=utf-8",
    )
    result["/local-app.mjs"] = (
        (Path(__file__).parent / "app.mjs").read_bytes(),
        "text/javascript; charset=utf-8",
    )
    for key in ("/", "/console", "/console/", PREFIX, PREFIX + "index.html"):
        raw, mime = result[key]
        raw = raw.replace(b"connect-src 'none'", b"connect-src 'self'")
        raw = raw.replace(
            b'<body class="response-preview">',
            b'<body class="response-preview" data-runtime="local-rke2">',
        )
        result[key] = (raw, mime)
    return result


def handler(runtime, auth, origin, public_assets):
    authority = urlsplit(origin).netloc

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def valid_site(self, write=False):
            return (
                self.headers.get_all("Host", []) == [authority]
                and self.headers.get("Sec-Fetch-Site") not in {"cross-site"}
                and (not write or self.headers.get("Origin") == origin)
            )

        def reply(
            self, status, value, mime="application/json; charset=utf-8", headers=None
        ):
            raw = (
                json.dumps(value, ensure_ascii=False).encode()
                if isinstance(value, (dict, list))
                else value
            )
            self.send_response(status)
            for key, val in {
                "Content-Type": mime,
                "Content-Length": str(len(raw)),
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Content-Security-Policy": CSP,
                "Referrer-Policy": "no-referrer",
                "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
                **(headers or {}),
            }.items():
                self.send_header(key, val)
            self.end_headers()
            try:
                self.wfile.write(raw)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def session(self):
            try:
                values = self.headers.get_all("Cookie", [])
                if len(values) != 1 or values[0].count("sova_local=") != 1:
                    return None
                jar = SimpleCookie(values[0])
                return auth.authenticate(jar["sova_local"].value)
            except (ValueError, KeyError):
                return None

        def do_GET(self):
            if not self.valid_site():
                return self.reply(403, {"error": "origin_required"})
            if self.path.startswith("/api/"):
                session = self.session()
                if not session:
                    return self.reply(
                        403, {"error": "개인 운영자 접속 주소로 열어 주세요."}
                    )
                if self.path == "/api/session":
                    return self.reply(
                        200,
                        {
                            "csrf": session.csrf,
                            "expires_at": session.expires_at.isoformat(),
                        },
                    )
                if self.path == "/api/state":
                    return self.reply(200, runtime.status())
                if self.path == "/api/app":
                    try:
                        return self.reply(
                            200, runtime.kube.request("control", "edge", "/messages")
                        )
                    except Exception:
                        return self.reply(
                            503, {"error": "local_application_unavailable"}
                        )
                return self.reply(404, {"error": "not_found"})
            item = public_assets.get(self.path)
            if item:
                return self.reply(200, item[0], item[1])
            return self.reply(404, {"error": "not_found"})

        def do_POST(self):
            if not self.valid_site(write=True):
                return self.reply(403, {"error": "origin_required"})
            if self.headers.get(
                "Content-Type"
            ) != "application/json" or self.headers.get("Transfer-Encoding"):
                return self.reply(400, {"error": "json_required"})
            self.connection.settimeout(3)
            try:
                lengths = self.headers.get_all("Content-Length", [])
                if (
                    len(lengths) != 1
                    or not lengths[0].isdecimal()
                    or not 0 < int(lengths[0]) <= 2048
                ):
                    raise ValueError()
                body = json.loads(self.rfile.read(int(lengths[0])))
                if type(body) is not dict:
                    raise ValueError()
            except (ValueError, OSError):
                return self.reply(400, {"error": "bounded_json_required"})
            if self.path == "/api/session":
                try:
                    if set(body) != {"token"}:
                        raise ValueError()
                    token, session = auth.exchange(body["token"])
                except Exception:
                    return self.reply(
                        403, {"error": "개인 접속 주소가 만료됐거나 이미 사용됐습니다."}
                    )
                return self.reply(
                    200,
                    {"csrf": session.csrf},
                    headers={
                        "Set-Cookie": "sova_local="
                        + token
                        + "; HttpOnly; SameSite=Strict; Path=/"
                    },
                )
            session = self.session()
            if not session or self.headers.get("X-Sova-CSRF") != session.csrf:
                return self.reply(403, {"error": "session_and_csrf_required"})
            try:
                if self.path == "/api/command":
                    return self.reply(202, runtime.submit(body))
                if self.path == "/api/scenario" and set(body) == {"scenario"}:
                    return self.reply(200, runtime.select(body["scenario"]))
                if self.path == "/api/message" and set(body) == {"id", "body"}:
                    import re

                    if (
                        runtime.busy
                        or not re.fullmatch("[a-f0-9]{32}", str(body["id"]))
                        or type(body["body"]) is not str
                        or not 0 < len(body["body"]) <= 200
                    ):
                        raise ValueError(
                            "실행 중에는 기다려 주세요. 메시지는 200자 이내입니다."
                        )
                    response = runtime.kube.request(
                        "control", "edge", "/messages", body=body
                    )
                    return self.reply(
                        200 if response.get("status") == 200 else 503,
                        response
                        if response.get("status") == 200
                        else {
                            "error": "업무 쓰기가 보류됐거나 실제 저장을 확인하지 못했습니다."
                        },
                    )
            except (ValueError, RuntimeError) as error:
                return self.reply(409, {"error": str(error)[:200]})
            return self.reply(404, {"error": "not_found"})

        def do_PUT(self):
            return self.reply(405, {"error": "method_not_allowed"})

        do_PATCH = do_PUT
        do_DELETE = do_PUT

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--port", type=int, default=18142)
    parser.add_argument("--hours", type=float, default=8)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not 0 < args.hours <= 12:
        parser.error("bounded loopback port and runtime required")
    os.umask(0o077)
    root = args.state.resolve()
    lockfile = open(root / "runner.lock", "a")
    fcntl.flock(lockfile, fcntl.LOCK_EX | fcntl.LOCK_NB)
    runtime = Runtime(root)
    origin = "http://127.0.0.1:" + str(args.port)
    deadline = datetime.now(UTC) + timedelta(hours=args.hours)
    auth = OperatorAuth(
        deadline=deadline, clock=lambda: datetime.now(UTC), session_until=deadline
    )
    token = auth.issue_bootstrap()
    private_json(
        root / "operator-access.json",
        {
            "url": origin + "/console/#" + token,
            "expires_at": auth.bootstrap_until.isoformat(),
            "session_until": deadline.isoformat(),
        },
    )
    stop = threading.Event()

    def observer():
        while not stop.is_set() and datetime.now(UTC) < deadline:
            if not runtime.busy:
                try:
                    runtime.observe()
                except Exception:
                    runtime.observation = {
                        "current": False,
                        "error": "observation_unavailable",
                        "observed_at": datetime.now(UTC).isoformat(),
                    }
            stop.wait(5)

    threading.Thread(target=observer, daemon=True).start()
    with ThreadingHTTPServer(
        ("127.0.0.1", args.port), handler(runtime, auth, origin, local_assets())
    ) as server:
        server.daemon_threads = True
        print(
            "Sova local RKE2 console: "
            + origin
            + "/console/ (owner access file required)",
            flush=True,
        )
        try:
            server.serve_forever()
        finally:
            stop.set()
            # Never delete workloads or change gates when the console closes.
            lockfile.close()


if __name__ == "__main__":
    main()
