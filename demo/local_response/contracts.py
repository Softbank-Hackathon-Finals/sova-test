"""Fixed local scenario vocabulary and deterministic checks."""

from datetime import UTC, datetime
import hashlib
import json
from .kube import Unconfirmed

SCENARIOS = {
    "isolate",
    "segment",
    "egress",
    "credentials",
    "patch",
    "restart",
    "scale",
    "migrate",
    "rollback",
}


SIGNALS = {
    "isolate": ("access-violation", "worker"),
    "segment": ("lateral-movement", "api,worker"),
    "egress": ("suspicious-egress", "worker"),
    "credentials": ("credential-exposure", "vault,api"),
    "patch": ("vulnerable-image", "api"),
    "restart": ("worker-timeout", "worker"),
    "scale": ("queue-pressure", "worker,queue"),
    "migrate": ("placement-change", "api,worker,db"),
    "rollback": ("release-regression", "api"),
}


def now():
    return datetime.now(UTC).isoformat()


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def require(value, error="verification_failed"):
    if not value:
        raise Unconfirmed(error)
    return value

