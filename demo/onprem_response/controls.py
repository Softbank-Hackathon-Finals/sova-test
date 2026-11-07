"""Operator-local qualification controls; not a product approval protocol."""

import hashlib
import hmac
import json
import os
import re
import stat
from datetime import datetime

DOMAIN = b"sova-owned-trial-control.v1\0"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def seal(key, *, action, request_id, binding, revision, expires_at):
    body = {
        "schema": "owned-trial-control.v1",
        "action": action,
        "request_id": request_id,
        "plan_id": binding["plan_id"],
        "plan_digest": binding["plan_digest"],
        "producer_revision": revision,
        "expires_at": expires_at,
    }
    return {
        "body": body,
        "signature": hmac.new(
            key, DOMAIN + canonical(body), hashlib.sha256
        ).hexdigest(),
    }


def read(path, *, key, binding, revision, at, deadline):
    if not path.exists():
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("private_operator_control_required")
        raw = os.read(fd, 4097)
    finally:
        os.close(fd)
    if len(raw) > 4096:
        raise ValueError("bounded_operator_control_required")
    envelope = json.loads(raw)
    if set(envelope) != {"body", "signature"}:
        raise ValueError("invalid_operator_control")
    body = envelope["body"]
    if set(body) != {
        "schema",
        "action",
        "request_id",
        "plan_id",
        "plan_digest",
        "producer_revision",
        "expires_at",
    }:
        raise ValueError("invalid_operator_control")
    expected = seal(
        key,
        action=body["action"],
        request_id=body["request_id"],
        binding=binding,
        revision=revision,
        expires_at=body["expires_at"],
    )
    expiry = datetime.fromisoformat(body["expires_at"])
    if (
        body != expected["body"]
        or body["schema"] != "owned-trial-control.v1"
        or body["action"] not in {"respond", "stop"}
        or not re.fullmatch(r"[a-f0-9]{32}", body["request_id"])
        or not isinstance(envelope["signature"], str)
        or not hmac.compare_digest(envelope["signature"], expected["signature"])
        or expiry.utcoffset() is None
        or not at < expiry <= deadline
    ):
        raise ValueError("unverified_or_expired_operator_control")
    return body
