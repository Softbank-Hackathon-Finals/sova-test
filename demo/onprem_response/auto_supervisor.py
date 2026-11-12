"""Exact policy preauthorization using the existing authenticated trial host."""

from datetime import UTC, datetime, timedelta
import hashlib
import json

from .controls import seal
from .incident_supervisor import IncidentSupervisor
from .supervisor import private_json, write_json


class AutoIncidentSupervisor(IncidentSupervisor):
    worker_module = "onprem_response.auto_incident"

    def status(self):
        value = super().status()
        value.update(automatic_mode=True, policy_armed=False)
        if not self.session:
            return value
        state = self.session / "state"
        terminal = private_json(state / "terminal-status.private.json")
        offer = private_json(state / "auto-policy-offer.private.json")
        grant = private_json(state / "auto-policy-grant.private.json")
        result = private_json(state / "result.private.json")
        if not result:
            value["can_attempt"] = False
        if (self.session / "stop.private.json").exists() and not result:
            value.update(
                phase="stopping", can_attempt=False, can_respond=False, can_stop=False
            )
            return value
        if terminal and not result:
            phase = terminal["phase"]
            revoked = (
                terminal.get("policy_revoked") is True
                or (self.session / "revoke.private.json").exists()
            )
            active = bool(grant) and not revoked and value["remaining_seconds"] > 0
            value.update(
                policy_armed=active,
                automatic_dispatched=terminal.get("automatic_dispatched") is True,
                can_attempt=active
                and phase == "armed"
                and not terminal["attack_observed"],
            )
            if offer:
                value["automatic_policy"] = {
                    k: offer[k]
                    for k in (
                        "trigger",
                        "components",
                        "namespace_uids",
                        "actor_pod_uid",
                        "component_pod_uids",
                        "response_plan_digest",
                        "valid_until",
                        "maximum_incidents",
                        "recovery_authorized",
                    )
                }
            if phase == "awaiting_arm":
                value.update(
                    phase="awaiting_arm",
                    pending_kind="arm",
                    plan_id=offer["plan_id"] if offer else None,
                    plan_digest=offer["plan_digest"] if offer else None,
                    can_respond=bool(offer)
                    and value["remaining_seconds"] >= 120
                    and not revoked
                    and not (self.session / "arm.private.json").exists(),
                )
                value["approval_scope"] = (
                    None
                    if not offer
                    else {
                        "automatic_policy": value["automatic_policy"],
                        "steps": [
                            {
                                "action": s["action"],
                                "component": json.loads(s["parameters_json"])[
                                    "component"
                                ],
                            }
                            for s in offer["response_plan"]["steps"]
                        ],
                        "image_digest": offer["response_plan"]["revisions"]["source"],
                        "incident_hold_release": False,
                        "production_resources_affected": False,
                    }
                )
            elif phase == "armed":
                value.update(phase="armed", can_respond=False)
            elif phase == "policy_revoked" or revoked:
                value.update(phase="policy_revoked", can_attempt=False)
                # Revocation stops automatic containment, never authorizes a
                # release. Explicit recovery remains separately reviewable.
                if value.get("pending_kind") == "respond":
                    value["can_respond"] = False
            elif phase == "awaiting_respond":
                value.update(phase="preparing", can_attempt=False, can_respond=False)
            elif not offer:
                value.update(phase="preparing", can_attempt=False, can_respond=False)
        return value

    def act(self, body):
        # A delayed response/retry may arrive after ARMED changed the visible
        # plan. Acknowledge this same request without redispatching its grant.
        request = body.get("request_id")
        with self.lock:
            if isinstance(request, str) and request in self.requests:
                encoded = hashlib.sha256(
                    json.dumps(body, sort_keys=True).encode()
                ).hexdigest()
                if self.requests[request] != encoded:
                    raise ValueError("request_identity_conflict")
                return {"accepted": True, "duplicate": True}
        current = self.status()
        special = (
            body.get("action") == "respond" and current.get("pending_kind") == "arm"
        )
        if not special:
            if (
                body.get("action") == "respond"
                and current.get("pending_kind") == "respond"
            ):
                raise ValueError(
                    "Containment requires prior policy approval, not post-event approval"
                )
            return super().act(body)
        with self.lock:
            if set(body) != {
                "action",
                "request_id",
                "session_id",
                "plan_digest",
                "approved",
            }:
                raise ValueError("exact_policy_approval_required")
            request = body["request_id"]
            if (
                not isinstance(request, str)
                or len(request) != 32
                or any(c not in "0123456789abcdef" for c in request)
            ):
                raise ValueError("request_identity_required")
            encoded = hashlib.sha256(
                json.dumps(body, sort_keys=True).encode()
            ).hexdigest()
            if request in self.requests:
                if self.requests[request] != encoded:
                    raise ValueError("request_identity_conflict")
                return {"accepted": True, "duplicate": True}
            current = self.status()
            if (
                body["approved"] is not True
                or not current["can_respond"]
                or body["session_id"] != current["session_id"]
                or body["plan_digest"] != current["plan_digest"]
            ):
                raise ValueError("current_policy_scope_required")
            state = self.session / "state"
            offer = private_json(state / "auto-policy-offer.private.json")
            key = state / "feed-key.private"
            if key.is_symlink() or key.stat().st_mode & 0o077:
                raise ValueError("private_key_required")
            action = "arm"
            path = self.session / (action + ".private.json")
            if path.exists():
                raise ValueError("policy_control_already_recorded")
            envelope = seal(
                key.read_bytes(),
                action=action,
                request_id=request,
                binding=offer,
                revision=self.settings.producer_revision,
                expires_at=min(
                    datetime.now(UTC) + timedelta(seconds=45),
                    datetime.fromisoformat(offer["valid_until"]),
                ).isoformat(),
            )
            write_json(path, envelope)
            self.requests[request] = encoded
            return {"accepted": True, "duplicate": False}
