"""Personal exact-plan approvals; the browser cannot choose a recovery action."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

from .controls import seal
from .supervisor import private_json, write_json
from .terminal_supervisor import TerminalSupervisor


class IncidentSupervisor(TerminalSupervisor):
    worker_module = "onprem_response.incident"

    def status(self):
        value = super().status()
        if not self.session:
            return value
        state = self.session / "state"
        terminal = private_json(state / "terminal-status.private.json")
        plan = private_json(state / "response-plan.private.json")
        result = private_json(state / "result.private.json")
        if not terminal and not result:
            # Registration can precede worker readiness, outbound baselines and
            # the actual preexisting-stream proof. Do not publish early READY.
            value.update(phase="preparing", can_attempt=False, can_respond=False)
        if terminal and not result:
            phase = terminal["phase"]
            kind = terminal.get("pending_kind")
            awaiting = phase == "awaiting_" + str(kind)
            value.update(
                phase="complete"
                if terminal["returned"]
                else phase
                if awaiting
                else "ready"
                if not terminal["attack_observed"]
                else "responding",
                can_prepare=False,
                can_stop=True,
                can_attempt=not terminal["attack_observed"],
                can_respond=awaiting
                and value["remaining_seconds"] >= 60
                and plan is not None
                and not (self.session / (kind + ".private.json")).exists(),
                response_verified=terminal["returned"],
                pending_kind=kind,
                components=terminal["components"],
                revalidated=terminal["revalidated"],
                returned=terminal["returned"],
            )
            if plan:
                value.update(plan_id=plan["plan_id"], plan_digest=plan["plan_digest"])
                value["approval_scope"] = {
                    "selected_components": terminal["components"],
                    "steps": [
                        {
                            "action": s["action"],
                            "component": json.loads(s["parameters_json"])["component"],
                        }
                        for s in plan["plan"]["steps"]
                    ],
                    "image_digest": plan["plan"]["revisions"]["source"],
                    "valid_until": plan["valid_until"],
                    "incident_hold_release": False,
                    "production_resources_affected": False,
                }
                value["can_respond"] = value["can_respond"] and datetime.now(
                    UTC
                ) < datetime.fromisoformat(plan["valid_until"])
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
                raise ValueError("exact_approval_required")
            current = self.status()
            request = body["request_id"]
            encoded = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest()
            if (
                not isinstance(request, str)
                or len(request) != 32
                or any(c not in "0123456789abcdef" for c in request)
            ):
                raise ValueError("request_identity_required")
            if request in self.requests:
                if self.requests[request] != encoded:
                    raise ValueError("request_identity_conflict")
                return {"accepted": True, "duplicate": True}
            if (
                body["approved"] is not True
                or not current["can_respond"]
                or body["session_id"] != current["session_id"]
                or body["plan_digest"] != current["plan_digest"]
            ):
                raise ValueError("current_exact_plan_approval_required")
            kind = current["pending_kind"]
            if kind not in {"respond", "recheck", "return"}:
                raise ValueError("fixed_pending_plan_required")
            state = self.session / "state"
            plan = private_json(state / "response-plan.private.json")
            key = state / "feed-key.private"
            if key.is_symlink() or key.stat().st_mode & 0o077:
                raise ValueError("private_key_required")
            expiry = min(
                datetime.now(UTC) + timedelta(seconds=45),
                datetime.fromisoformat(plan["valid_until"]),
            )
            envelope = seal(
                key.read_bytes(),
                action=kind,
                request_id=request,
                binding=plan,
                revision=self.settings.producer_revision,
                expires_at=expiry.isoformat(),
            )
            path = self.session / (kind + ".private.json")
            if path.exists():
                raise ValueError("approval_already_recorded")
            write_json(path, envelope)
            self.requests[request] = encoded
            return {"accepted": True, "duplicate": False}
