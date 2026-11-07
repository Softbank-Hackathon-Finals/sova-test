"""OS-owner terminal input for a bounded trial; never accepts a target or shell command."""

import argparse
import secrets
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .controls import seal
from .supervisor import private_json, write_json


def submit(root, action):
    latest = private_json(root / "latest.private.json")
    if latest is None:
        raise ValueError("Prepare a dedicated trial in the UI first")
    session_id = latest["session_id"]
    if len(session_id) != 32 or any(c not in "0123456789abcdef" for c in session_id):
        raise ValueError("Invalid local trial")
    directory = root / ("session-" + session_id)
    state = directory / "state"
    metadata = private_json(state / "trial.private.json")
    binding = private_json(state / "registration.private.json")
    status = private_json(state / "terminal-status.private.json")
    if not metadata or not binding or not status:
        raise ValueError("Trial is not ready")
    if action == "status":
        return {
            "phase": status["phase"],
            "attack_observed": status["attack_observed"],
            "approved": status["approved"],
            "steps": status["steps"],
        }
    target_action = {"attempt": "attempt", "approve": "respond", "stop": "stop"}[action]
    if action == "attempt" and (
        status["attack_observed"] or (state / "attempt-intent.private.json").exists()
    ):
        raise ValueError("Attempt already dispatched; inspect its recorded result")
    if action == "approve":
        binding = private_json(state / "response-plan.private.json")
        if not status["attack_observed"] or binding is None:
            raise ValueError(
                "Actual attack observation and response plan required first"
            )
    key = state / "feed-key.private"
    if key.is_symlink() or key.stat().st_mode & 0o077:
        raise ValueError("Private local trial required")
    nonce = secrets.token_hex(16)
    deadline = datetime.fromisoformat(metadata["deadline"])
    at = datetime.now(UTC)
    if not at + timedelta(seconds=15) < deadline:
        raise ValueError("Trial is expiring; no new request")
    envelope = seal(
        key.read_bytes(),
        action=target_action,
        request_id=nonce,
        binding=binding,
        revision=metadata["source_revision"],
        expires_at=min(at + timedelta(seconds=30), deadline).isoformat(),
    )
    path = directory / (target_action + ".private.json")
    if path.exists():
        raise ValueError("This action is already recorded; no replay")
    write_json(path, envelope)
    if action != "attempt":
        return {"action": action, "accepted": True, "qualification_only": True}
    print(
        "요청: 시험 워크로드에서 이웃 서비스 /protected에 인증 없는 HTTP 요청",
        flush=True,
    )
    print("실제 Pod 실행·독립 감사 결과를 기다립니다. 요청 ID: " + nonce, flush=True)
    until = time.monotonic() + 35
    while time.monotonic() < until:
        receipt = private_json(state / "attack-receipt.private.json")
        if receipt and receipt["nonce"] == nonce:
            return receipt
        if private_json(state / "result.private.json"):
            raise ValueError("Trial stopped; inspect protected evidence")
        time.sleep(0.3)
    raise ValueError("Result unconfirmed; do not replay the attempt")


def main():
    import json

    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("action", choices=["attempt", "approve", "status", "stop"])
    a = p.parse_args()
    try:
        print(json.dumps(submit(a.state, a.action), ensure_ascii=False, indent=2))
    except Exception as e:
        raise SystemExit(
            str(e) if isinstance(e, ValueError) else "Local trial request unconfirmed"
        ) from None


if __name__ == "__main__":
    main()
