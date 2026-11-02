"""Owner-bootstrap authentication for a loopback qualification console.

Not enterprise SSO or a boundary against compromise of the owning OS account.
Secrets never appear in HTTP paths, query strings or server access logs.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import threading

from sova.domain.contracts import ContractError, utc


@dataclass(frozen=True, slots=True)
class OperatorSession:
    csrf: str
    expires_at: datetime


class OperatorAuth:
    def __init__(self, *, deadline, clock, bootstrap_seconds=300, session_until=None):
        self.clock = clock
        self.deadline = utc(deadline)
        issued = utc(clock())
        limit = timedelta(hours=12) if session_until is not None else timedelta(hours=2)
        if not issued < self.deadline <= issued + limit:
            raise ContractError("Bounded local operator session required")
        self.session_until = utc(session_until) if session_until is not None else None
        if (
            self.session_until is not None
            and not issued < self.session_until <= self.deadline
        ):
            raise ContractError(
                "Explicit operator expiry must fit the runtime deadline"
            )
        if type(bootstrap_seconds) is not int or not 1 <= bootstrap_seconds <= 300:
            raise ContractError("Bounded bootstrap lifetime required")
        self.bootstrap_until = min(
            self.session_until or self.deadline,
            issued + timedelta(seconds=bootstrap_seconds),
        )
        self._bootstrap_hash = None
        self._sessions = {}
        self._lock = threading.Lock()
        self._window_at = issued
        self._attempts = 0

    @staticmethod
    def _hash(token):
        if type(token) is not str or not 32 <= len(token) <= 128:
            raise ContractError("Invalid local credential")
        try:
            return hashlib.sha256(token.encode("ascii")).hexdigest()
        except UnicodeError as exc:
            raise ContractError("Invalid local credential") from exc

    def issue_bootstrap(self):
        with self._lock:
            if (
                self._bootstrap_hash is not None
                or utc(self.clock()) >= self.bootstrap_until
            ):
                raise ContractError("Bootstrap unavailable")
            token = secrets.token_urlsafe(32)
            self._bootstrap_hash = self._hash(token)
            return token

    def exchange(self, token):
        with self._lock:
            current = utc(self.clock())
            if current - self._window_at >= timedelta(seconds=30):
                self._attempts = 0
                self._window_at = current
            self._attempts += 1
            if self._attempts > 8:
                raise ContractError("Local authentication rate limited")
            supplied = self._hash(token)
            if (
                current >= self.bootstrap_until
                or self._bootstrap_hash is None
                or not hmac.compare_digest(supplied, self._bootstrap_hash)
            ):
                raise ContractError("Local bootstrap denied")
            # Consume atomically. A second browser cannot reuse this grant.
            self._bootstrap_hash = "consumed"
            session_token = secrets.token_urlsafe(32)
            session = OperatorSession(
                secrets.token_urlsafe(32),
                self.session_until
                or min(self.deadline, current + timedelta(minutes=30)),
            )
            self._sessions[self._hash(session_token)] = session
            return session_token, session

    def authenticate(self, token):
        try:
            key = self._hash(token)
        except ContractError:
            return None
        with self._lock:
            session = self._sessions.get(key)
            if session is None:
                return None
            if utc(self.clock()) >= session.expires_at:
                self._sessions.pop(key, None)
                return None
            return session

    def revoke(self, token):
        try:
            key = self._hash(token)
        except ContractError:
            return
        with self._lock:
            self._sessions.pop(key, None)


def write_bootstrap_file(root, *, origin, token, expires_at):
    """Only the OS owner may retrieve the one-time fragment URL."""
    root = Path(root)
    info = root.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ContractError("Owner-private session directory required")
    path = root / "operator-access.json"
    raw = (
        json.dumps(
            {"url": origin + "/#" + token, "expires_at": utc(expires_at).isoformat()},
            indent=2,
        )
        + "\n"
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as target:
        target.write(raw)
    return path
