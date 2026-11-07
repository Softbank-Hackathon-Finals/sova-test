"""Reuse the fixed supervisor; approvals bind the post-observation response plan."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

from .controls import seal
from .supervisor import Supervisor, private_json, write_json


class TerminalSupervisor(Supervisor):
    worker_module = "onprem_response.terminal"

    def status(self):
        value = super().status()
        value.update(
            attack_observed=False,
            can_attempt=False,
            qualification_only=True,
            scenario="controlled_unauthorized_internal_http_attempt",
        )
        if not self.session:
            return value
        terminal = private_json(self.session / "state/terminal-status.private.json")
        attack = private_json(self.session / "state/attack-receipt.private.json")
        value["attack"] = (
            None
            if attack is None
            else {
                k: attack[k]
                for k in (
                    "nonce",
                    "upstream_status",
                    "actor_pod_uid",
                    "actor_identity_verified",
                    "independent_audit_verified",
                )
            }
        )
        response = private_json(self.session / "state/response-plan.private.json")
        result = private_json(self.session / "state/result.private.json")
        if terminal and not result:
            value["observation_revision"] = terminal["observation_revision"]
            # An effect receipt can precede its independently read-back graph.
            # Completion is visible only after publication of that observation.
            published_complete = (
                terminal["approved"] is True
                and terminal["phase"] in {"switch_route", "watch"}
                and terminal["steps"]
                == [
                    "apply_isolation",
                    "activate_replacement",
                    "verify_replacement",
                    "switch_route",
                ]
            )
            if value["phase"] == "complete" and not published_complete:
                value.update(
                    phase="responding", response_verified=False, can_stop=False
                )
            value["attack_observed"] = terminal["attack_observed"]
            value["can_attempt"] = (
                value["phase"] == "ready" and not terminal["attack_observed"]
            )
            value["can_respond"] = False
            if terminal["attack_observed"] and not terminal["approved"] and response:
                value.update(
                    phase="awaiting_approval",
                    plan_id=response["plan_id"],
                    plan_digest=response["plan_digest"],
                    can_respond=value["remaining_seconds"] >= 90
                    and datetime.now(UTC)
                    < datetime.fromisoformat(response["valid_until"]),
                )
            if (self.session / "respond.private.json").exists() and not value[
                "response_verified"
            ]:
                value.update(phase="responding", can_respond=False, can_attempt=False)
        return value

    def act(self, body):
        if body.get("action") != "respond":
            return super().act(body)
        with self.lock:
            if set(body) != {
                "action",
                "request_id",
                "session_id",
                "plan_digest",
                "approved",
            }:
                raise ValueError("invalid_demo_action")
            current = self.status()
            if (
                body["approved"] is not True
                or not current["can_respond"]
                or body["session_id"] != current["session_id"]
                or body["plan_digest"] != current["plan_digest"]
                or not isinstance(body["request_id"], str)
                or len(body["request_id"]) != 32
                or any(c not in "0123456789abcdef" for c in body["request_id"])
            ):
                raise ValueError("exact_current_response_approval_required")
            response = private_json(self.session / "state/response-plan.private.json")
            metadata = private_json(self.session / "state/trial.private.json")
            keypath = self.session / "state/feed-key.private"
            if keypath.is_symlink() or keypath.stat().st_mode & 0o077:
                raise ValueError("private_control_key_required")
            envelope = seal(
                keypath.read_bytes(),
                action="respond",
                request_id=body["request_id"],
                binding=response,
                revision=self.settings.producer_revision,
                expires_at=min(
                    datetime.now(UTC) + timedelta(seconds=45),
                    datetime.fromisoformat(metadata["deadline"]),
                    datetime.fromisoformat(response["valid_until"]),
                ).isoformat(),
            )
            write_json(self.session / "respond.private.json", envelope)
            self.requests[body["request_id"]] = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest()
            return {"accepted": True, "duplicate": False}
