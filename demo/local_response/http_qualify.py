"""Drive the running loopback console over HTTP exactly as the browser does.

`qualify` calls the Runtime in-process. This runner instead goes through the
served console: bootstrap exchange, session cookie, CSRF header, the same
`/api/scenario`, `/api/command` and `/api/state` calls `runtime_client.mjs`
makes. It proves the console-to-cluster path, and with `--until` it repeats the
nine scenarios as a bounded soak. It stops on the first unconfirmed step and
never retries a held effect.

It consumes the one-time bootstrap link, so restart the server afterwards to
issue a fresh link for a person.
"""

import argparse
from datetime import UTC, datetime
import http.client
import json
from pathlib import Path
import secrets
import time
from urllib.parse import urlsplit

from .contracts import SCENARIOS, SIGNALS, now
from .provision import private_json

ORDER = [
    "isolate",
    "segment",
    "egress",
    "credentials",
    "patch",
    "restart",
    "scale",
    "migrate",
    "rollback",
]


class Console:
    def __init__(self, origin):
        parts = urlsplit(origin)
        if parts.scheme != "http" or parts.hostname != "127.0.0.1":
            raise ValueError("loopback_origin_required")
        self.origin = origin
        self.host = parts.netloc
        self.port = parts.port
        self.cookie = None
        self.csrf = None

    def call(self, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        headers = {"Host": self.host, "Sec-Fetch-Site": "same-origin"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        payload = None
        if body is not None:
            payload = json.dumps(body).encode()
            headers.update(
                {
                    "Origin": self.origin,
                    "Content-Type": "application/json",
                    "Content-Length": str(len(payload)),
                }
            )
            if self.csrf:
                headers["X-Sova-CSRF"] = self.csrf
        try:
            connection.request(
                "GET" if body is None else "POST", path, body=payload, headers=headers
            )
            response = connection.getresponse()
            raw = response.read(2_000_000)
            return response.status, response.getheader("Set-Cookie"), raw
        finally:
            connection.close()

    def json(self, path, body=None, *, expect=(200,)):
        status, _cookie, raw = self.call(path, body)
        value = json.loads(raw)
        if status not in expect:
            raise RuntimeError(f"http_{status}: {path}: {value.get('error', '')}"[:200])
        return value

    def login(self, token):
        status, cookie, raw = self.call("/api/session", {"token": token})
        if status != 200 or not cookie or not cookie.startswith("sova_local="):
            raise RuntimeError("console_session_not_established")
        self.cookie = cookie.split(";", 1)[0]
        self.csrf = json.loads(raw)["csrf"]

    def state(self):
        value = self.json("/api/state")
        if (
            value.get("kind") != "sova.local-response.v1"
            or value.get("actual_execution") is not True
            or value.get("session", {}).get("source") != "local-rke2"
        ):
            raise RuntimeError("unexpected_runtime_contract")
        return value

    def command(self, value, *, timeout=300):
        before = self.state()
        if before["busy"]:
            raise RuntimeError("runtime_busy_before_command")
        revision = before["session"]["revision"]
        self.json(
            "/api/command",
            {
                "request_id": secrets.token_hex(16),
                "revision": revision,
                "command": value,
            },
            expect=(202,),
        )
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            time.sleep(1)
            current = self.state()
            if not current["busy"] and current["session"]["revision"] > revision:
                session = current["session"]
                held = (
                    session["phase"] == "held"
                    or (session.get("recovery") or {}).get("phase") == "recovery_held"
                )
                if held:
                    last = (session.get("history") or [{}])[-1]
                    raise RuntimeError(
                        "held: " + value + ": " + str(last.get("message", ""))[-120:]
                    )
                return current
        raise RuntimeError("local_command_not_confirmed: " + value)


def steps(scenario):
    signal, targets = SIGNALS[scenario]
    values = [
        f"inject {signal} --target {targets}",
        "response plan",
        "response submit",
        "response approve",
        "response verify",
        "response finalize",
    ]
    if scenario in {"isolate", "segment"}:
        values += ["recovery start", "recovery verify", "recovery finalize"]
    if scenario == "migrate":
        values.append("exit drill")
    return values


def run(root, origin, scenarios, until, max_cycles):
    access = json.loads((root / "operator-access.json").read_text())
    if not access["url"].startswith(origin + "/"):
        raise RuntimeError("operator_access_origin_mismatch")
    token = urlsplit(access["url"]).fragment
    console = Console(origin)
    status, _cookie, page = console.call("/console/")
    if status != 200 or b'data-runtime="local-rke2"' not in page:
        raise RuntimeError("console_page_not_in_local_runtime_mode")
    console.login(token)
    report = {
        "kind": "sova.local-response.http-qualification.v1",
        "started_at": now(),
        "origin": origin,
        "path": "browser-equivalent HTTP: /api/session, /api/scenario, /api/command, /api/state",
        "scope": None,  # copied from the served runtime below
        "until": until.isoformat() if until else None,
        "cycles": [],
    }
    served = console.state()
    report["scope"] = served["scope"]
    report["topology"] = served.get("topology", {}).get("name", "local")
    filename = root / ("http-qualification-" + secrets.token_hex(4) + ".json")
    print("EVIDENCE " + str(filename), flush=True)
    cycle = 0
    try:
        while cycle < max_cycles and (until is None or datetime.now(UTC) < until):
            cycle += 1
            record = {"cycle": cycle, "started_at": now(), "results": []}
            report["cycles"].append(record)
            for scenario in scenarios:
                if until is not None and datetime.now(UTC) >= until:
                    break
                console.command("response reset")
                console.json("/api/scenario", {"scenario": scenario})
                started = time.monotonic()
                result = {"scenario": scenario, "started_at": now(), "passed": False}
                record["results"].append(result)
                private_json(filename, report)
                for value in steps(scenario):
                    final = console.command(value)
                app = console.call("/api/app")[0]
                session = final["session"]
                result.update(
                    passed=session["outcome"] == "pass"
                    and all(item["passed"] for item in session["checks"])
                    and (
                        scenario not in {"isolate", "segment"}
                        or (session.get("recovery") or {}).get("phase") == "recovered"
                    ),
                    checks=[[c["name"], c["passed"]] for c in session["checks"]],
                    app_http_after=app,
                    seconds=round(time.monotonic() - started, 1),
                    completed_at=now(),
                )
                private_json(filename, report)
                print(
                    f"{'PASS' if result['passed'] else 'FAIL'} cycle={cycle} {scenario} {result['seconds']}s",
                    flush=True,
                )
                if not result["passed"]:
                    raise RuntimeError("scenario_not_passed: " + scenario)
            record["completed_at"] = now()
        console.command("response reset")
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["error"] = str(error)[:300]
        try:
            report["failure_state"] = console.state()
        except Exception:
            report["failure_state"] = None
        raise
    finally:
        report["completed_at"] = now()
        private_json(filename, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--port", type=int, default=18142)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), action="append")
    parser.add_argument("--until", help="ISO-8601 time to stop starting scenarios")
    parser.add_argument("--cycles", type=int, default=1)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535 or not 1 <= args.cycles <= 100:
        parser.error("bounded loopback port and cycle count required")
    until = datetime.fromisoformat(args.until) if args.until else None
    if until is not None and until.tzinfo is None:
        parser.error("--until needs a timezone offset")
    run(
        args.state.resolve(),
        "http://127.0.0.1:" + str(args.port),
        args.scenario or ORDER,
        until,
        args.cycles if until is None else 100,
    )


if __name__ == "__main__":
    main()
