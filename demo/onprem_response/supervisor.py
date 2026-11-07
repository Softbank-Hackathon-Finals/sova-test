"""Fixed personal demo runner. No browser-supplied command, image or namespace."""

import fcntl
import hashlib
import json
import os
import secrets
import stat
import subprocess
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .controls import seal
from .manifests import validate_names


def private_json(path):
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
            raise ValueError("private_state_required")
        raw = os.read(fd, 120001)
    finally:
        os.close(fd)
    if len(raw) > 120000:
        raise ValueError("bounded_state_required")
    return json.loads(raw)


def write_json(path, value):
    temporary = path.with_suffix(".new")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(fd)
    temporary.replace(path)


@dataclass(frozen=True)
class Settings:
    producer_root: Path
    security_root: Path
    python: Path
    wrapper: Path
    profile: Path
    image: str
    producer_revision: str
    security_revision: str
    wrapper_sha256: str
    profile_sha256: str

    @classmethod
    def read(cls, path):
        value = private_json(path)
        return cls(
            **{
                k: Path(v)
                if k
                in {"producer_root", "security_root", "python", "wrapper", "profile"}
                else v
                for k, v in value.items()
            }
        )

    def validate(self):
        validate_names("00000000", self.image)
        for root, revision, scope in (
            (self.producer_root, self.producer_revision, "demo/onprem_response"),
            (self.security_root, self.security_revision, "src"),
        ):
            actual = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=root, text=True
            ).strip()
            dirty = subprocess.check_output(
                ["git", "status", "--porcelain", "--", scope], cwd=root, text=True
            )
            if actual != revision or dirty:
                raise ValueError("pinned_source_changed")
        for path, expected in (
            (self.wrapper, self.wrapper_sha256),
            (self.profile, self.profile_sha256),
        ):
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError("personal_access_configuration_changed")
        if not self.python.is_file() or not os.access(self.python, os.X_OK):
            raise ValueError("configured_python_unavailable")


class Supervisor:
    def __init__(self, root, settings):
        if root.is_symlink():
            raise ValueError("private_directory_required")
        root.mkdir(parents=True, mode=0o700, exist_ok=True)
        if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
            raise ValueError("private_directory_required")
        self.root, self.settings = root, settings
        self.lock = threading.RLock()
        self.child = None
        self.requests = {}
        self.lockfile = (root / "supervisor.lock").open("a")
        fcntl.flock(self.lockfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        latest = private_json(root / "latest.private.json")
        self.session_id = latest["session_id"] if latest else None
        if self.session_id and (
            len(self.session_id) != 32
            or any(c not in "0123456789abcdef" for c in self.session_id)
        ):
            raise ValueError("invalid_registered_session")

    @property
    def session(self):
        return self.root / ("session-" + self.session_id) if self.session_id else None

    def status(self):
        with self.lock:
            value = {
                "session_id": self.session_id,
                "phase": "idle",
                "plan_id": None,
                "plan_digest": None,
                "steps": [],
                "remaining_seconds": 0,
                "can_prepare": True,
                "can_respond": False,
                "can_stop": False,
                "response_verified": False,
                "cleanup_verified": False,
                "error": None,
            }
            if not self.session_id:
                return value
            state = self.session / "state"
            metadata = private_json(state / "trial.private.json")
            binding = private_json(state / "registration.private.json")
            result = private_json(state / "result.private.json")
            steps = private_json(state / "effects-summary.private.json") or []
            value.update(
                phase="preparing", can_prepare=False, steps=[s["action"] for s in steps]
            )
            if metadata:
                value["remaining_seconds"] = max(
                    0,
                    int(
                        (
                            datetime.fromisoformat(metadata["deadline"])
                            - datetime.now(UTC)
                        ).total_seconds()
                    ),
                )
            if binding:
                value.update(
                    plan_id=binding["plan_id"],
                    plan_digest=binding["plan_digest"],
                    phase="ready",
                    can_stop=True,
                    can_respond=value["remaining_seconds"] >= 240,
                )
            if (self.session / "respond.private.json").exists():
                value.update(phase="responding", can_respond=False, can_stop=False)
            if len(steps) == 4:
                value.update(phase="complete", can_stop=True, response_verified=True)
            if (self.session / "stop.private.json").exists():
                value.update(phase="stopping", can_respond=False, can_stop=False)
            if result:
                cleanup = result.get("cleanup", {})
                clean = bool(cleanup) and all(
                    x == "absence_confirmed" for x in cleanup.values()
                )
                value.update(
                    phase="ended" if clean else "attention",
                    can_prepare=clean,
                    can_respond=False,
                    can_stop=False,
                    cleanup_verified=clean,
                    response_verified=result.get("response_verified") is True,
                    error="trial_failed" if result.get("error_type") else None,
                )
            elif private_json(self.session / "startup.private.json") == {
                "failed_before_spawn": True
            }:
                value.update(
                    phase="connection_failed",
                    can_prepare=True,
                    can_respond=False,
                    can_stop=False,
                    error="worker_not_started",
                )
            elif self.child is not None and self.child.poll() is not None:
                # Wrapper/login/source failures before any resource intent can be
                # retried. Lost resource creation/cleanup always requires inspection.
                intent = state / "requests.private.jsonl"
                mutation = False
                if intent.exists():
                    mutation = any(
                        json.loads(line)["path"]
                        != "/apis/authentication.k8s.io/v1/selfsubjectreviews"
                        for line in intent.read_text().splitlines()
                    )
                value.update(
                    phase="attention" if mutation else "connection_failed",
                    can_prepare=not mutation,
                    can_respond=False,
                    can_stop=False,
                    error="connection_or_trial_failed",
                )
            return value

    def act(self, body):
        with self.lock:
            if set(body) != {
                "action",
                "request_id",
                "session_id",
                "plan_digest",
                "approved",
            }:
                raise ValueError("invalid_demo_action")
            key = body["request_id"]
            if (
                not isinstance(key, str)
                or len(key) != 32
                or any(c not in "0123456789abcdef" for c in key)
            ):
                raise ValueError("request_identity_required")
            digest = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest()
            if key in self.requests:
                if self.requests[key] != digest:
                    raise ValueError("request_identity_conflict")
                return {"accepted": True, "duplicate": True}
            current = self.status()
            if (
                body["session_id"] != current["session_id"]
                or body["plan_digest"] != current["plan_digest"]
            ):
                raise ValueError("demo_scope_changed")
            action = body["action"]
            if body["approved"] is not True:
                raise ValueError("explicit_owned_trial_approval_required")
            if action == "prepare" and current["can_prepare"]:
                self.start()
            elif (
                action in {"respond", "stop"}
                and current["can_respond" if action == "respond" else "can_stop"]
            ):
                state = self.session / "state"
                metadata = private_json(state / "trial.private.json")
                binding = private_json(state / "registration.private.json")
                # Never send credentials or the signature key to the browser.
                key_path = state / "feed-key.private"
                if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
                    raise ValueError("private_control_key_required")
                envelope = seal(
                    key_path.read_bytes(),
                    action=action,
                    request_id=key,
                    binding=binding,
                    revision=self.settings.producer_revision,
                    expires_at=min(
                        datetime.now(UTC) + timedelta(seconds=45),
                        datetime.fromisoformat(metadata["deadline"]),
                    ).isoformat(),
                )
                write_json(self.session / (action + ".private.json"), envelope)
            else:
                raise ValueError("action_not_allowed_in_current_phase")
            self.requests[key] = digest
            return {"accepted": True, "duplicate": False}

    def start(self):
        self.settings.validate()
        self.session_id = secrets.token_hex(16)
        self.session.mkdir(mode=0o700)
        write_json(self.root / "latest.private.json", {"session_id": self.session_id})
        settings = self.settings
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("AWS_", "BRAVO_TEAM_DIRECT_", "OPENAI_"))
            and k not in {"KUBECONFIG", "PYTHONPATH"}
        }
        env.update(
            PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
            PYTHONPATH=os.pathsep.join(
                map(
                    str,
                    (
                        settings.producer_root / "src",
                        settings.security_root / "src",
                        settings.producer_root / "demo",
                    ),
                )
            ),
        )
        command = [
            str(settings.python),
            str(settings.wrapper),
            "--diagnostics",
            str(self.session / "access.private.json"),
            "--",
            str(settings.python),
            "-m",
            "onprem_response.trial",
            "--state",
            str(self.session / "state"),
            "--profile",
            str(settings.profile),
            "--image",
            settings.image,
            "--hold-seconds",
            "120",
            "--operator-control",
            str(self.session),
        ]
        log = (self.session / "worker.private.log").open("xb")
        os.chmod(log.name, 0o600)
        try:
            self.child = subprocess.Popen(
                command,
                cwd=settings.producer_root,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        except OSError:
            write_json(
                self.session / "startup.private.json", {"failed_before_spawn": True}
            )
            raise
        finally:
            log.close()
        write_json(self.session / "process.private.json", {"pid": self.child.pid})
