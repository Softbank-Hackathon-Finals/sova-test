"""Security hold release approver, run by a person other than the operator.

    init     create this approver's Ed25519 key in a directory it owns
    register add the approver's public key to a runner's state (owner action)
    approve  sign a HoldRelease for the runner's currently exported hold

The private key never enters the runner's state directory. The runner checks
the signature, the registration, separation of duties and that the revisions
it signs are still current when the operator submits `security release <id>`.
"""

import argparse
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .provision import private_json
from .security import OPERATOR, approve


def key_file(directory, approver):
    return Path(directory) / ("approver-" + approver + ".private.json")


def init(directory, approver):
    os.umask(0o077)
    path = key_file(directory, approver)
    if path.exists():
        raise SystemExit("approver key already exists")
    key = Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes_raw().hex()
    private_json(
        path,
        {
            "approver": approver,
            "key_id": "ed25519-" + public[:16],
            "private_key_hex": key.private_bytes_raw().hex(),
            "public_key_hex": public,
        },
    )
    return public


def register(state, approver, public_key_hex, days):
    if approver == OPERATOR:
        raise SystemExit("the console operator cannot be a release approver")
    path = Path(state) / "security-approvers.json"
    try:
        approvers = json.loads(path.read_text())
    except FileNotFoundError:
        approvers = {}
    now = datetime.now(UTC)
    approvers[approver] = {
        "key_id": "ed25519-" + public_key_hex[:16],
        "public_key_hex": public_key_hex,
        "valid_from": (now - timedelta(seconds=1)).isoformat(),
        "valid_until": (now + timedelta(days=days)).isoformat(),
        "revoked": False,
    }
    private_json(path, approvers)


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="action", required=True)
    a = sub.add_parser("init")
    a.add_argument("--key-dir", required=True, type=Path)
    a.add_argument("--approver", required=True)
    b = sub.add_parser("register")
    b.add_argument("--state", required=True, type=Path)
    b.add_argument("--approver", required=True)
    b.add_argument("--public-key", required=True)
    b.add_argument("--days", type=int, default=30, choices=range(1, 91))
    c = sub.add_parser("approve")
    c.add_argument("--state", required=True, type=Path)
    c.add_argument("--key-dir", required=True, type=Path)
    c.add_argument("--approver", required=True)
    c.add_argument("--reason", required=True)
    c.add_argument("--minutes", type=int, default=15, choices=range(1, 61))
    args = parser.parse_args()
    if args.action == "init":
        print(init(args.key_dir, args.approver))
    elif args.action == "register":
        register(args.state, args.approver, args.public_key, args.days)
        print("registered " + args.approver)
    else:
        print(
            approve(
                args.state,
                key_file(args.key_dir, args.approver),
                args.approver,
                args.reason,
                args.minutes,
            )
        )


if __name__ == "__main__":
    main()
