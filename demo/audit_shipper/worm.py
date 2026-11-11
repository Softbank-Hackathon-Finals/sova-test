"""Prove, with the writer role itself, that shipped evidence cannot be erased.

For one shipped object version the check tries, as the audit writer:

1. deleting that exact version            -> must be refused,
2. shortening its retention               -> must be refused,
3. an unversioned delete                   -> may add a delete marker only,
4. reading the version back                -> must still match its SHA-256.

A refusal counts only when AWS says AccessDenied; any other failure is
UNKNOWN, never PASS (AT-37, SEC-07).
"""

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import tempfile

from .ship import Aws, ShipError


def attempt(call):
    try:
        call()
    except ShipError as error:
        return "DENIED" if getattr(error, "denied", False) else "UNKNOWN"
    return "ALLOWED"


def check(writer, bucket, receipt):
    key, version = receipt["key"], receipt["version_id"]
    soon = (datetime.now(UTC) + timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    results = {
        "delete_locked_version": attempt(
            lambda: writer(
                "s3api",
                "delete-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version,
            )
        ),
        "shorten_retention": attempt(
            lambda: writer(
                "s3api",
                "put-object-retention",
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version,
                "--retention",
                json.dumps({"Mode": "GOVERNANCE", "RetainUntilDate": soon}),
            )
        ),
        "unversioned_delete": attempt(
            lambda: writer("s3api", "delete-object", "--bucket", bucket, "--key", key)
        ),
    }
    with tempfile.TemporaryDirectory() as scratch:
        target = Path(scratch) / "object"
        writer(
            "s3api",
            "get-object",
            "--bucket",
            bucket,
            "--key",
            key,
            "--version-id",
            version,
            str(target),
        )
        survived = hashlib.sha256(target.read_bytes()).hexdigest() == receipt["sha256"]
    passed = (
        results["delete_locked_version"] == "DENIED"
        and results["shorten_retention"] == "DENIED"
        and results["unversioned_delete"] in {"ALLOWED", "DENIED"}
        and survived
    )
    return {
        "kind": "sova.audit-worm-check.v1",
        "checked_at": datetime.now(UTC).isoformat(),
        "key": key,
        "version_id": version,
        "attempts": results,
        "original_version_intact": survived,
        "verdict": "PASS"
        if passed
        else (
            "FAIL"
            if survived is False
            or "ALLOWED"
            in (results["delete_locked_version"], results["shorten_retention"])
            else "UNKNOWN"
        ),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--writer-role-arn", required=True)
    parser.add_argument("--region", default="ap-northeast-2")
    args = parser.parse_args()
    manifest = json.loads((args.state / "audit-manifest.private.json").read_text())
    receipt = next(iter(manifest["objects"].values()))
    writer = Aws(args.region).assume(args.writer_role_arn)
    result = check(writer, args.bucket, receipt)
    path = args.state / (
        "worm-check-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + ".json"
    )
    path.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, ensure_ascii=False))


if __name__ == "__main__":
    main()
