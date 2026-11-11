"""Explicit, sequential real-local qualification; not a unit-test PASS substitute."""

import argparse
import fcntl
import hashlib
from pathlib import Path
import secrets
import subprocess
import time

from .provision import private_json
from .runtime import Runtime, SCENARIOS, SIGNALS, now
from .support import REQUIRED


def command(runtime, value, *, timeout=240):
    request = {
        "request_id": secrets.token_hex(16),
        "revision": runtime.state["revision"],
        "command": value,
    }
    runtime.submit(request)
    until = time.monotonic() + timeout
    while runtime.busy and time.monotonic() < until:
        time.sleep(0.2)
    if runtime.busy or runtime.state["phase"] == "held":
        raise RuntimeError("local_command_not_confirmed: " + value)


def refused(runtime, value):
    try:
        runtime.submit(
            {
                "request_id": secrets.token_hex(16),
                "revision": runtime.state["revision"],
                "command": value,
            }
        )
    except ValueError:
        return True
    return False


def security_drill(runtime, keys):
    """Raise a hold, prove effects are refused, release with a separate signer."""
    from .security import approve
    from .security_approver import key_file

    command(runtime, "security hold drill-suspected-compromise")
    hold = runtime.state["security"]
    if not hold.get("active"):
        raise RuntimeError("security_hold_not_active")
    blocked = {
        value: refused(runtime, value)
        for value in ("response reset", "response plan", "recovery start")
    }
    if not all(blocked.values()):
        raise RuntimeError("effect_admitted_during_security_hold")
    runtime.observe()  # export fresh revisions for the approver
    approval = approve(
        runtime.root,
        key_file(keys, "recovery-approver"),
        "recovery-approver",
        "drill-contained",
    )
    command(runtime, "security release " + approval)
    if runtime.state["security"].get("active"):
        raise RuntimeError("security_hold_not_released")
    return {
        "hold_id": hold["hold"]["hold_id"],
        "blocked_during_hold": blocked,
        "released_by": runtime.state["security"]["release"]["release"]["approved_by"],
        "release_fingerprint": runtime.state["security"]["release_fingerprint"],
    }


def qualify(root, scenarios, drill_keys=None):
    lock = open(root / "runner.lock", "a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    runtime = Runtime(root)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    files = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in Path(__file__).parent.glob("*.py")
    }
    report = {
        "kind": "sova.local-response.qualification.v1",
        "started_at": now(),
        "base_commit": revision,
        "producer_files_sha256": files,
        "cluster_uid": runtime.settings["cluster_uid"],
        "topology": runtime.topology()["name"],
        "scope": (
            "actual EKS source in the operator's own AWS account and actual local RKE2 target on this Mac; no production/pentest qualification"
            if runtime.topology()["name"] == "hybrid-aws"
            else "actual local RKE2; two namespaces on the same Mac, no AWS/production/pentest qualification"
        ),
        "results": [],
    }
    filename = root / ("qualification-" + secrets.token_hex(4) + ".json")
    try:
        for scenario in scenarios:
            command(runtime, "response reset")
            runtime.select(scenario)
            signal, targets = SIGNALS[scenario]
            record = {"scenario": scenario, "started_at": now(), "passed": False}
            report["results"].append(record)
            private_json(filename, report)
            print("START " + scenario, flush=True)
            for value in (
                f"inject {signal} --target {targets}",
                "response plan",
                "response submit",
                "response approve",
                "response verify",
                "response finalize",
            ):
                command(runtime, value)
                print("CONFIRMED " + scenario + " " + value, flush=True)
            if scenario in {"isolate", "segment"}:
                for value in ("recovery start", "recovery verify", "recovery finalize"):
                    command(runtime, value)
                    print("CONFIRMED " + scenario + " " + value, flush=True)
            record.update(passed=True, completed_at=now(), state=runtime.status())
            private_json(filename, report)
            print("PASS " + scenario, flush=True)
        command(runtime, "response reset")
        if drill_keys:
            report["security_drill"] = security_drill(runtime, drill_keys)
            private_json(filename, report)
            print("PASS security-hold-drill", flush=True)
        report["completed_at"] = now()
        report["passed"] = True
        if set(scenarios) == set(REQUIRED):
            from .support import build, profiles

            private_json(filename, report)
            record = build(report, profiles(runtime.kube), evidence=runtime.evidence)
            private_json(
                root / ("support-record-" + record["record_id"] + ".json"), record
            )
            report["support_record"] = record["record_id"]
            print("QUALIFIED " + record["record_id"], flush=True)
    except Exception as error:
        report["passed"] = False
        report["error"] = type(error).__name__
        report["failure_state"] = runtime.status()
        raise
    finally:
        private_json(filename, report)
        lock.close()
        print("EVIDENCE " + str(filename), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), action="append")
    parser.add_argument(
        "--security-drill-keys",
        type=Path,
        help="approver key directory; runs the security hold drill at the end",
    )
    args = parser.parse_args()
    qualify(
        args.state.resolve(),
        args.scenario
        or [
            "isolate",
            "segment",
            "egress",
            "credentials",
            "patch",
            "restart",
            "scale",
            "migrate",
            "rollback",
        ],
        args.security_drill_keys,
    )


if __name__ == "__main__":
    main()
