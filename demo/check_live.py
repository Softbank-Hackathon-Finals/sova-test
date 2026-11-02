"""Real preview requests and route switch, no mocked AWS/VM responses."""

import http.cookiejar
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "http://127.0.0.1:8790"


def main():
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    client.open(ORIGIN + "/", timeout=10).read()

    def get():
        return json.load(client.open(ORIGIN + "/api/state", timeout=10))

    def post(path, body, origin=ORIGIN):
        req = urllib.request.Request(
            ORIGIN + path,
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "Origin": origin},
        )
        with client.open(req, timeout=10) as r:
            return r.status, json.load(r)

    result = {
        "mocked": False,
        "requests": [],
        "switches": [],
        "db_migration": False,
        "security_auto_response": False,
    }
    initial = get()
    assert all(
        initial["observations"][s]["available"]
        and not initial["observations"][s]["stale"]
        for s in ("aws", "vm")
    )
    first = initial["route"]
    for side in [first, "vm" if first == "aws" else "aws", first]:
        before = get()
        if before["route"] != side:
            start = time.perf_counter()
            status, operation = post("/api/switch", {"environment": side})
            assert status == 202
            deadline = time.monotonic() + 20
            while time.monotonic() < deadline:
                current = get()
                last = current["last_operation"]
                if last and last["id"] == operation["id"] and not current["operation"]:
                    assert last["status"] == "succeeded" and current["route"] == side
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("Route operation incomplete")
            result["switches"].append(
                {
                    "to": side,
                    "elapsed_seconds": round(time.perf_counter() - start, 3),
                    "operation_id": operation["id"],
                }
            )
        status, receipt = post(
            "/api/action", {"message": "Live-check " + side, "automatic": False}
        )
        assert (
            status == 200
            and receipt["ok"]
            and receipt["environment"] == receipt["receipt"]["environment"] == side
        )
        assert (
            receipt["receipt"]["request_id"] == receipt["request_id"]
            and receipt["receipt"]["revision"] == initial["revision"]
        )
        observed = next(
            r for r in get()["requests"] if r["id"] == receipt["request_id"]
        )
        assert observed["ok"] and observed["environment"] == side
        result["requests"].append(
            {k: receipt[k] for k in ("request_id", "environment", "latency_ms")}
        )
    try:
        post("/api/switch", {"environment": "vm"}, origin="https://untrusted.example")
        raise AssertionError("Foreign Origin accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 403
    result["foreign_origin_denied"] = True
    try:
        urllib.request.urlopen(ORIGIN + "/api/state", timeout=10)
        raise AssertionError("Missing session accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 404
    result["missing_session_denied"] = True
    status = get()
    assert status["route"] == first and not status["operation"]
    result.update(
        status="succeeded",
        final_route=first,
        revision=initial["revision"],
        measured_at=time.time(),
    )
    (ROOT / ".local-notes/live-preview/live-check.json").write_text(
        json.dumps(result, indent=2)
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
