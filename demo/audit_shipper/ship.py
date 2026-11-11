"""Ship a runner state's evidence to the Object Lock audit bucket.

Only an allowlist of evidence files leaves the state directory; anything
private (keys, kubeconfig, tokens, settings, rotation material, the console
access link, the SQLite files) is refused even if it matches a pattern. The
journal is exported read-only as JSON lines. Every upload is made with the
audit writer role, checked against its SHA-256 checksum and its object lock
retention, and recorded in a private manifest so unchanged files are not
shipped twice. A changed file becomes a new version; old versions stay.
"""

import argparse
import base64
from datetime import UTC, datetime
import fnmatch
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile

ALLOW = (
    "evidence/*.json",
    "evidence-trust.json",
    "support-record-*.json",
    "qualification-*.json",
    "http-qualification-*.json",
    "security-approvers.json",
    "releases/*.json",
    "worm-check-*.json",
)
DENY = (
    "*private*",
    "operator-access.json",
    "kubeconfig*",
    "eks-token*",
    "settings*",
    "rotation*",
    "*.sqlite*",
    "*.lock",
)
MAX_BYTES = 5_000_000


class ShipError(RuntimeError):
    pass


def selected(root):
    root = Path(root)
    for pattern in ALLOW:
        for path in sorted(root.glob(pattern)):
            relative = path.relative_to(root).as_posix()
            if any(
                fnmatch.fnmatch(path.name, deny) or fnmatch.fnmatch(relative, deny)
                for deny in DENY
            ):
                continue
            if (
                path.is_symlink()
                or not path.is_file()
                or path.stat().st_size > MAX_BYTES
            ):
                continue
            yield relative, path


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def export_journal(root, after_seq, out_dir):
    """Read-only JSON lines of journal rows after `after_seq`."""
    database = Path(root) / "responses.sqlite"
    if not database.exists():
        return None, after_seq
    with sqlite3.connect("file:" + str(database) + "?mode=ro", uri=True) as db:
        rows = db.execute(
            "SELECT seq,at,kind,body FROM journal WHERE seq>? ORDER BY seq",
            (after_seq,),
        ).fetchall()
    if not rows:
        return None, after_seq
    path = Path(out_dir) / f"journal-{rows[0][0]:08d}-{rows[-1][0]:08d}.jsonl"
    with open(path, "w", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        for seq, at, kind, body in rows:
            stream.write(
                json.dumps(
                    {"seq": seq, "at": at, "kind": kind, "body": json.loads(body)},
                    ensure_ascii=False,
                )
                + "\n"
            )
    return path, rows[-1][0]


class Aws:
    """Thin AWS CLI wrapper; credentials only ever arrive through the env."""

    def __init__(self, region, env=None, runner=subprocess.run):
        self.region, self.env, self.runner = region, env, runner

    def __call__(self, *args):
        result = self.runner(
            ["aws", *args, "--region", self.region, "--output", "json"],
            capture_output=True,
            text=True,
            timeout=60,
            env=self.env,
        )
        if result.returncode:
            error = ShipError("aws_call_failed: " + " ".join(args[:2]))
            error.denied = "AccessDenied" in result.stderr
            raise error
        return json.loads(result.stdout or "{}")

    def assume(self, role_arn):
        creds = self(
            "sts",
            "assume-role",
            "--role-arn",
            role_arn,
            "--role-session-name",
            "sova-audit-writer",
            "--duration-seconds",
            "900",
        )["Credentials"]
        env = {k: v for k, v in os.environ.items() if not k.startswith("AWS_")}
        env.update(
            AWS_ACCESS_KEY_ID=creds["AccessKeyId"],
            AWS_SECRET_ACCESS_KEY=creds["SecretAccessKey"],
            AWS_SESSION_TOKEN=creds["SessionToken"],
        )
        return Aws(self.region, env, self.runner)


def put(aws, bucket, key, path):
    digest = sha256(path)
    response = aws(
        "s3api",
        "put-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--body",
        str(path),
        "--checksum-algorithm",
        "SHA256",
        "--content-type",
        "application/json",
    )
    expected = base64.b64encode(bytes.fromhex(digest)).decode()
    if response.get("ChecksumSHA256") != expected or not response.get("VersionId"):
        raise ShipError("upload_checksum_or_version_unconfirmed: " + key)
    retention = aws(
        "s3api",
        "get-object-retention",
        "--bucket",
        bucket,
        "--key",
        key,
        "--version-id",
        response["VersionId"],
    )["Retention"]
    until = datetime.fromisoformat(retention["RetainUntilDate"].replace("Z", "+00:00"))
    if retention.get("Mode") not in {
        "GOVERNANCE",
        "COMPLIANCE",
    } or until <= datetime.now(UTC):
        raise ShipError("object_lock_retention_missing: " + key)
    return {
        "key": key,
        "version_id": response["VersionId"],
        "sha256": digest,
        "mode": retention["Mode"],
        "retain_until": retention["RetainUntilDate"],
    }


def ship(root, bucket, writer, prefix, manifest_path):
    root = Path(root)
    try:
        manifest = json.loads(Path(manifest_path).read_text())
    except FileNotFoundError:
        manifest = {"objects": {}, "journal_seq": 0}
    shipped = []
    for relative, path in selected(root):
        digest = sha256(path)
        if manifest["objects"].get(relative, {}).get("sha256") == digest:
            continue
        receipt = put(writer, bucket, prefix + "/" + relative, path)
        manifest["objects"][relative] = receipt
        shipped.append(receipt)
    with tempfile.TemporaryDirectory() as scratch:
        os.chmod(scratch, 0o700)
        journal, last = export_journal(root, manifest["journal_seq"], scratch)
        if journal:
            receipt = put(writer, bucket, prefix + "/journal/" + journal.name, journal)
            manifest["objects"]["journal/" + journal.name] = receipt
            manifest["journal_seq"] = last
            shipped.append(receipt)
    manifest["updated_at"] = datetime.now(UTC).isoformat()
    temporary = Path(str(manifest_path) + ".tmp")
    with open(temporary, "w", opener=lambda p, f: os.open(p, f, 0o600)) as stream:
        json.dump(manifest, stream, indent=2)
    temporary.replace(manifest_path)
    return shipped


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--writer-role-arn", required=True)
    parser.add_argument("--prefix", required=True, help="e.g. hybrid-aws/<state name>")
    parser.add_argument("--region", default="ap-northeast-2")
    args = parser.parse_args()
    os.umask(0o077)
    writer = Aws(args.region).assume(args.writer_role_arn)
    shipped = ship(
        args.state,
        args.bucket,
        writer,
        args.prefix,
        args.state / "audit-manifest.private.json",
    )
    print(
        json.dumps(
            {"shipped": len(shipped), "keys": [r["key"] for r in shipped][:20]},
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
