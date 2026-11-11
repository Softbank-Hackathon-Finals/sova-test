"""kubectl exec credential plugin: `aws eks get-token` with a private cache.

Each kubectl call would otherwise start the AWS CLI. The short-lived token is
reused until one minute before it expires and kept only in the private state
directory (mode 0600). Prints an ExecCredential exactly as `aws eks get-token`.
"""

import argparse
from datetime import UTC, datetime, timedelta
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys


def fresh(value):
    try:
        expires = datetime.fromisoformat(
            value["status"]["expirationTimestamp"].replace("Z", "+00:00")
        )
    except (KeyError, TypeError, ValueError):
        return False
    return expires - datetime.now(UTC) > timedelta(minutes=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--cluster-name", required=True)
    parser.add_argument("--region", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    with open(args.cache.with_suffix(".lock"), "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            value = json.loads(args.cache.read_text())
        except (OSError, ValueError):
            value = None
        if not fresh(value):
            result = subprocess.run(
                [
                    "aws",
                    "eks",
                    "get-token",
                    "--cluster-name",
                    args.cluster_name,
                    "--region",
                    args.region,
                    "--output",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode:
                sys.stderr.write("eks token unavailable\n")
                return 1
            value = json.loads(result.stdout)
            temporary = args.cache.with_suffix(".tmp")
            with open(
                temporary,
                "w",
                opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600),
            ) as stream:
                json.dump(value, stream)
            temporary.replace(args.cache)
    sys.stdout.write(json.dumps(value))
    return 0


if __name__ == "__main__":
    sys.exit(main())
