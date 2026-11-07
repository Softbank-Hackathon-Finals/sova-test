"""Preapproved owned-fixture containment; recovery still requires exact approvals."""

import argparse
import json
import os
from pathlib import Path
import signal
import time

from sova.domain.contracts import ContractError, canonical_json

from .automatic_policy import TRIGGER, validate_trigger
from .controls import read
from .incident import IncidentTrial, sha
from .supervisor import private_json
from .trial import atomic_json, now


class AutoIncidentTrial(IncidentTrial):
    def __init__(self, *args, **kwargs):
        self.policy_offer = None
        self.policy_grant = None
        self.auto_dispatching = False
        self.auto_dispatched = False
        self.policy_revoked = False
        super().__init__(*args, **kwargs)

    def start(self):
        super().start()
        self.prepare_plan("respond")
        plan = self.pending_plan
        offer = {
            "schema": "owned-auto-containment.v1",
            "trigger": TRIGGER,
            "qualification_only": True,
            "production_resources_affected": False,
            "incident_hold_release": False,
            "recovery_authorized": False,
            "maximum_incidents": 1,
            "producer_revision": self.source_revision,
            "valid_until": self.deadline.isoformat(),
            "components": list(self.components),
            "namespace_uids": dict(self.api.uids),
            "actor_pod_uid": self.old_pods["api"],
            "component_pod_uids": dict(self.old_pods),
            "response_plan_id": plan.plan_id,
            "response_plan_digest": plan.fingerprint,
            "response_plan": plan.document,
        }
        self.policy_offer = {
            **offer,
            "plan_id": "auto-policy-" + self.run_id,
            "plan_digest": sha(offer),
        }
        atomic_json(self.root / "auto-policy-offer.private.json", self.policy_offer)
        self.publish("awaiting_arm")

    def policy_command(self, directory, action):
        if not self.policy_offer:
            return None
        return read(
            directory / (action + ".private.json"),
            key=self.hmac_key,
            binding=self.policy_offer,
            revision=self.source_revision,
            at=now(),
            deadline=self.deadline,
            actions=frozenset({action}),
        )

    def command(self, directory, action):
        if action == "attempt":
            # Precompiling the response must not change the terminal request's
            # registration binding; it is a trigger, never a response approval.
            return read(
                directory / "attempt.private.json",
                key=self.hmac_key,
                binding=self.plan_binding,
                revision=self.source_revision,
                at=now(),
                deadline=self.deadline,
                actions=frozenset({"attempt"}),
            )
        return super().command(directory, action)

    def arm(self, approval):
        if (
            self.policy_grant
            or self.attack_attempted
            or self.phase != "awaiting_arm"
            or now() >= self.pending_plan.valid_until
        ):
            raise ContractError("Policy must be approved before the actual attempt")
        self.assert_current_scope()
        self.policy_grant = {
            "policy_digest": self.policy_offer["plan_digest"],
            "response_plan_digest": self.pending_plan.fingerprint,
            "activated_at": now().isoformat(),
            "valid_until": self.policy_offer["valid_until"],
            "request_id": approval["request_id"],
            "authority": "verified-owner-preauthorization",
            "qualification_only": True,
            "product_approval": False,
        }
        atomic_json(self.root / "auto-policy-grant.private.json", self.policy_grant)
        self.publish("armed")

    def assert_current_scope(self):
        self.api.check_owned()
        for component in self.components:
            pod = self.current_pod("blue", component)
            if pod["metadata"]["uid"] != self.old_pods[component]:
                raise ContractError("Preapproved source Pod was replaced")
        step = self.pending_plan.steps[0]
        command = self.pending_plan.command(
            step.step_id, operation_id=self.pending_plan.plan_id, epoch=1
        )
        self.incident_adapter.validate(command)

    def assert_policy_active(self, directory, *, at):
        if self.policy_command(directory, "revoke"):
            self.policy_revoked = True
        if (
            not self.policy_grant
            or self.policy_revoked
            or self.policy_grant["policy_digest"] != self.policy_offer["plan_digest"]
            or self.policy_grant["response_plan_digest"]
            != self.policy_offer["response_plan_digest"]
            or at >= self.deadline
            or at >= self.pending_plan.valid_until
            or self.command(directory, "stop")
        ):
            raise ContractError(
                "Automatic containment policy inactive, expired or revoked"
            )

    def observe_attempt(self, request_id):
        # The ordinary CLI cannot bypass preauthorization. No HTTP request is
        # issued until the signed owner grant has been consumed by this worker.
        self.assert_policy_active(self.root.parent, at=now())
        return super().observe_attempt(request_id)

    def bind_response(self, source, target, hold_reason):
        # Reuse TerminalTrial's actual outbound request, Pod/owner/IP readback,
        # independent peer audit and nonce. Do not recompile after preapproval.
        self.assert_policy_active(self.root.parent, at=now())
        validate_trigger(
            attack=self.attack,
            intent=private_json(self.root / "attempt-intent.private.json"),
            actor_uid=self.policy_offer["actor_pod_uid"],
            activated_at=self.policy_grant["activated_at"],
            valid_until=self.policy_grant["valid_until"],
            at=now(),
        )
        if (
            self.auto_dispatched
            or self.pending_kind != "respond"
            or self.pending_plan.fingerprint
            != self.policy_offer["response_plan_digest"]
            or tuple(self.policy_offer["components"]) != self.components
            or self.policy_offer["namespace_uids"] != self.api.uids
        ):
            raise ContractError("Single exact preapproved containment plan required")
        self.assert_current_scope()
        dispatch = {
            "policy_digest": self.policy_offer["plan_digest"],
            "response_plan_digest": self.pending_plan.fingerprint,
            "attack_receipt_digest": sha(self.attack),
            "event_nonce": self.attack["nonce"],
            "dispatched_at": now().isoformat(),
            "automatic": True,
            "qualification_only": True,
        }
        path = self.root / "automatic-dispatch-intent.private.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(canonical_json(dispatch))
            stream.flush()
            os.fsync(stream.fileno())
        self.auto_dispatched = True
        self.auto_dispatching = True
        try:
            self.publish("automatic_containment")
            self.accept_plan(dispatch)
        finally:
            self.auto_dispatching = False

    def authorize(self, command, permit, at, mutation):
        if self.auto_dispatching:
            self.assert_policy_active(self.root.parent, at=at)
            if command.plan_digest != self.policy_offer["response_plan_digest"]:
                raise ContractError("Recovery is not covered by automatic containment")
        return super().authorize(command, permit, at, mutation)

    def publish(self, phase, *, record_event=True):
        super().publish(phase, record_event=record_event)
        if not self.expanded_ready:
            return
        path = self.root / "terminal-status.private.json"
        status = private_json(path)
        status.update(
            automatic_mode=True,
            policy_armed=self.policy_grant is not None and not self.policy_revoked,
            policy_revoked=self.policy_revoked,
            automatic_dispatched=self.auto_dispatched,
        )
        atomic_json(path, status)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--operator-control", type=Path, required=True)
    parser.add_argument("--hold-seconds", type=int, default=60)
    parser.add_argument(
        "--components",
        choices=["api", "api,worker"],
        default=os.environ.get("SOVA_OWNED_TRIAL_COMPONENTS", "api,worker"),
    )
    args = parser.parse_args()
    if not 0 <= args.hold_seconds <= 120:
        parser.error("Bounded observation interval required")
    os.umask(0o077)
    trial = AutoIncidentTrial(
        args.state,
        args.image,
        json.loads(args.profile.read_text()),
        components=tuple(args.components.split(",")),
    )
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    result = {
        "qualification_only": True,
        "product_workflow_qualified": False,
        "response_verified": False,
        "automatic_mode": True,
    }
    try:
        trial.start()
        until = None
        while now() < trial.deadline:
            if trial.command(args.operator_control, "stop") or (
                until and time.monotonic() >= until
            ):
                break
            if trial.policy_command(args.operator_control, "revoke"):
                trial.policy_revoked = True
                trial.publish("policy_revoked")
            if not trial.policy_grant and not trial.policy_revoked:
                approval = trial.policy_command(args.operator_control, "arm")
                if approval:
                    trial.arm(approval)
            if (
                trial.policy_grant
                and not trial.policy_revoked
                and not trial.attack_attempted
            ):
                request = trial.command(args.operator_control, "attempt")
                if request:
                    trial.observe_attempt(request["request_id"])
            if (
                trial.attack
                and not trial.returned
                and trial.pending_kind in {"recheck", "return"}
            ):
                approval = trial.command(args.operator_control, trial.pending_kind)
                if approval:
                    trial.accept_plan(approval)
                    if trial.returned:
                        result.update(
                            response_verified=True,
                            automatic_containment_dispatched=trial.auto_dispatched,
                            partial_containment_verified=True,
                            verification_failure_held=True,
                            revalidation_verified=True,
                            source_return_verified=True,
                            incident_hold_active=True,
                        )
                        until = time.monotonic() + args.hold_seconds
            trial.publish(trial.phase, record_event=False)
            time.sleep(0.5)
    except BaseException as error:
        result["error_type"] = type(error).__name__
        if not isinstance(error, KeyboardInterrupt):
            raise
    finally:
        result["cleanup"] = trial.close()
        atomic_json(args.state / "result.private.json", result)


if __name__ == "__main__":
    main()
