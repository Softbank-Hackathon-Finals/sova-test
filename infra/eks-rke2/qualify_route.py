"""Measure the fixed loopback entry under actual EKS/RKE2 route changes.

Every client attempt, including connection failures, is recorded without retries.
This qualifies only bounded stateless HTTP requests, not HA or data migration.
"""

import argparse
from collections import Counter
import concurrent.futures
from datetime import UTC, datetime
import http.client
import json
import os
from pathlib import Path
import sys
import threading
import time

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "src"))
sys.path.insert(0, str(PROJECT / "demo"))
from migration_bridge import MigrationBridge


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=60, choices=range(30, 181))
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    output = root / "measurements" / str(time.time_ns())
    output.mkdir(parents=True, mode=0o700)
    bridge = MigrationBridge(
        8790,
        bootstrap_token_provider=lambda: (root / "bridge-token").read_text().strip(),
    )
    state = bridge.state()
    if (
        state["status"] != "connected"
        or state["state"].get("profile") != "eks-rke2-stateless-v1"
    ):
        raise RuntimeError("Actual cluster profile required")
    binding = state["state"]["revision"]
    if (
        datetime.fromisoformat(state["state"]["expires_at"]) - datetime.now(UTC)
    ).total_seconds() < args.seconds + 30:
        raise RuntimeError("Qualification would outlive registered resources")
    records, transitions, identifiers = [], [], set()
    lock = threading.Lock()
    stop = threading.Event()
    start = time.monotonic()

    def client(worker):
        while not stop.is_set():
            before = time.monotonic()
            conn = http.client.HTTPConnection("127.0.0.1", 8790, timeout=5)
            row = {"worker": worker, "at": time.time(), "ok": False}
            try:
                conn.request("GET", "/quote")
                response = conn.getresponse()
                body = json.loads(response.read(8193))
                row.update(http_status=response.status, result=body)
                row["ok"] = (
                    response.status == 200
                    and body.get("ok") is True
                    and body.get("total") == 220
                    and body.get("environment") in {"aws", "vm"}
                )
                with lock:
                    if body.get("id") in identifiers:
                        row["ok"] = False
                        row["error"] = "repeated_request_id"
                    identifiers.add(body.get("id"))
            except Exception as exc:
                row["error"] = type(exc).__name__
            finally:
                conn.close()
                row["latency_ms"] = round((time.monotonic() - before) * 1000, 3)
                with lock:
                    records.append(row)
                    with (output / "client.jsonl").open("a") as log:
                        log.write(json.dumps(row) + "\n")
            stop.wait(max(0, 0.2 - (time.monotonic() - before)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        clients = [pool.submit(client, i) for i in range(2)]
        try:
            for index in range(4):
                stop.wait(
                    max(
                        0,
                        start + 5 + index * (args.seconds - 10) / 4 - time.monotonic(),
                    )
                )
                current = bridge.state()["state"]
                if current["revision"] != binding:
                    raise RuntimeError("Registration changed during measurement")
                target = "vm" if current["route"] == "aws" else "aws"
                before = time.monotonic()
                transition = {"target": target, "at": time.time(), "confirmed": False}
                try:
                    bridge.action(
                        {
                            "action": "switch",
                            "environment": target,
                            "revision": current["revision"],
                            "route_revision": current["route_revision"],
                        }
                    )
                    after = bridge.state()["state"]
                    transition["confirmed"] = (
                        after["route"] == target
                        and after["route_revision"] == current["route_revision"] + 1
                        and after["workflows"][0]["status"] == "succeeded"
                    )
                except Exception as exc:
                    transition["error"] = type(exc).__name__
                transition["duration_ms"] = round((time.monotonic() - before) * 1000, 3)
                transitions.append(transition)
            stop.wait(max(0, start + args.seconds - time.monotonic()))
        finally:
            stop.set()
            for future in clients:
                future.result()
    latencies = sorted(row["latency_ms"] for row in records)
    summary = {
        "profile": "eks-rke2-stateless-v1",
        "registration_digest": binding,
        "workloads": state["state"]["workloads"],
        "duration_seconds": round(time.monotonic() - start, 3),
        "client_attempts": len(records),
        "failures": sum(not r["ok"] for r in records),
        "responses_by_environment": dict(
            Counter(
                r.get("result", {}).get("environment", "unverified") for r in records
            )
        ),
        "p95_ms": latencies[max(0, (95 * len(latencies) + 99) // 100 - 1)]
        if latencies
        else None,
        "transitions": transitions,
        "automatic_retries": 0,
        "scope": "Two clients, fixed stateless quote, loopback gateway and private tunnels; no DB/files/sessions/public entry/HA qualification",
        "full_migration_verified": False,
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    (root / "latest-qualification.json").write_text(
        json.dumps(
            {
                "summary": str(output / "summary.json"),
                "client_trace": str(output / "client.jsonl"),
            },
            indent=2,
        )
    )
    print(json.dumps(summary, indent=2))
    if summary["failures"] or not all(t["confirmed"] for t in transitions):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
