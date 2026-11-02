"""Deadline cleanup for this operator-owned EKS/RKE2 qualification run only."""

from datetime import UTC, datetime
import argparse
import fcntl
import json
import os
from pathlib import Path
import subprocess
import signal
import time

import boto3


def command(args, *, timeout=120):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError("Cleanup command failed: " + Path(args[0]).name)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--now", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    if root.stat().st_uid != os.geteuid() or root.stat().st_mode & 0o077:
        raise RuntimeError("Private operator run directory required")
    owner = json.loads((root / "ownership.json").read_text())
    while (
        not args.now
        and datetime.now(UTC) < datetime.fromisoformat(owner["cleanup_at"])
        and not (root / "finish-now").exists()
    ):
        if (root / "cleanup-result.json").exists() and json.loads(
            (root / "cleanup-result.json").read_text()
        ).get("complete"):
            return
        time.sleep(5)
    with (root / "cleanup.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        os.umask(0o077)
        errors = []
        for name in (
            "route-server.json",
            "source-forward.json",
            "target-forward.json",
            "ssm-tunnel.json",
        ):
            metadata = root / name
            if not metadata.exists():
                continue
            process = json.loads(metadata.read_text())
            pid = process["pid"]
            current = subprocess.run(
                ["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True
            )
            if current.returncode == 0:
                bound = str(root) in current.stdout
                if name == "ssm-tunnel.json":
                    bound = (
                        process["host"] in current.stdout
                        and process["instance_id"] in current.stdout
                    )
                if not bound:
                    errors.append("process_identity_unverified:" + name)
                    continue
                try:
                    os.killpg(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        session = boto3.Session(region_name=owner["region"])
        account = session.client("sts").get_caller_identity()["Account"]
        if account != owner["account_id"]:
            raise RuntimeError("Wrong AWS account; no cleanup performed")
        tf = Path(owner["terraform_dir"])
        if tf.resolve() != root / "terraform":
            raise RuntimeError("Unexpected state directory")
        variables = json.loads((tf / "terraform.tfvars.json").read_text())
        if variables["run_id"] != owner["run_id"] or variables["account_id"] != account:
            raise RuntimeError("Ownership variable mismatch")
        try:
            command(
                [
                    "terraform",
                    "-chdir=" + str(tf),
                    "plan",
                    "-destroy",
                    "-input=false",
                    "-lock-timeout=120s",
                    "-out=cleanup.tfplan",
                    "-no-color",
                ],
                timeout=240,
            )
            plan = json.loads(
                command(
                    [
                        "terraform",
                        "-chdir=" + str(tf),
                        "show",
                        "-json",
                        "cleanup.tfplan",
                    ]
                )
            )
            for change in plan.get("resource_changes", []):
                if change["change"]["actions"] not in (["delete"], ["no-op"]):
                    raise RuntimeError("Unexpected cleanup action")
                before = change["change"].get("before") or {}
                tags = before.get("tags_all")
                if tags is not None and tags.get("RunId") != owner["run_id"]:
                    raise RuntimeError("Resource ownership mismatch")
            with (root / "terraform-destroy.log").open("a") as log:
                result = subprocess.run(
                    [
                        "terraform",
                        "-chdir=" + str(tf),
                        "apply",
                        "-input=false",
                        "-no-color",
                        "cleanup.tfplan",
                    ],
                    stdout=log,
                    stderr=log,
                    timeout=2700,
                )
                if result.returncode:
                    errors.append("terraform_cleanup_unverified")
            final = json.loads(
                command(["terraform", "-chdir=" + str(tf), "show", "-json"])
            )
            if final.get("values", {}).get("root_module", {}).get("resources"):
                errors.append("terraform_resources_remaining")
        except Exception as exc:
            errors.append(type(exc).__name__ + ":" + str(exc)[:120])
        try:
            marker = command(
                [
                    "limactl",
                    "shell",
                    "--workdir=/",
                    owner["vm_name"],
                    "--",
                    "sudo",
                    "cat",
                    "/etc/sova-qualification-id",
                ]
            ).strip()
            machine = command(
                [
                    "limactl",
                    "shell",
                    "--workdir=/",
                    owner["vm_name"],
                    "--",
                    "cat",
                    "/etc/machine-id",
                ]
            ).strip()
            if (
                marker != "sova-rke2-qualification-v1"
                or machine != owner["vm_machine_id"]
            ):
                raise RuntimeError("VM ownership mismatch")
            command(["limactl", "stop", "--tty=false", owner["vm_name"]], timeout=90)
        except Exception as exc:
            errors.append("vm:" + type(exc).__name__)
        database = root / "control-db.json"
        if database.exists():
            try:
                db = json.loads(database.read_text())
                if Path(db["data"]).resolve() != root / "pgdata":
                    raise RuntimeError("Wrong control DB path")
                command(
                    [db["pg_ctl"], "-D", db["data"], "-m", "fast", "-w", "stop"],
                    timeout=45,
                )
            except Exception as exc:
                errors.append("control_db:" + type(exc).__name__)
        (root / "cleanup-result.json").write_text(
            json.dumps(
                {
                    "at": datetime.now(UTC).isoformat(),
                    "complete": not errors,
                    "errors": errors,
                },
                indent=2,
            )
            + "\n"
        )


if __name__ == "__main__":
    main()
