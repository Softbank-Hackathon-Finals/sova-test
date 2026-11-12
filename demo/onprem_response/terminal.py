"""Terminal-triggered real HTTP denial and guarded owned-workload containment.

Only newly owned stateless trial namespaces. No production plan/approval, model
credentials, arbitrary command, exploit, destination URL or shared-app changes.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import signal
import time
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from sova.domain.contracts import ContractError, canonical_json

from .controls import read
from .egress import EgressProbe
from .terminal_fixture import terminal_manifests
from .trial import Adapter, Routes, Trial, atomic_json, now


class ProxyRoutes(Routes):
    def __init__(self, api, source, target):
        self.api, self.source, self.target = api, source, target

    def call(self, path, body=None):
        if (
            path not in {"/health", "/route", "/entry", "/attempt"}
            and not re.fullmatch(r"/probe\?target=(blue|green|neighbor)", path)
            and not re.fullmatch(r"/audit\?nonce=[a-f0-9]{32}", path)
        ):
            raise ContractError("Fixed trial proxy path required")
        nonce = secrets.token_hex(16)
        query = (
            (path + ("&" if "?" in path else "?") + "request_id=" + nonce)
            if body is None
            else path
        )
        route = (
            f"/api/v1/namespaces/{self.api.namespaces['probe']}/services/probe:8080/proxy"
            + query
        )
        value = self.api.request("POST" if body is not None else "GET", route, body)
        if path.startswith("/probe") or path == "/entry":
            if value.get("ok") and value.get("response", {}).get("request_id") != nonce:
                raise ContractError("Independent trial response nonce mismatch")
        return value


class ProxyAdapter(Adapter):
    def __init__(self, *, egress_probe, **kwargs):
        super().__init__(**kwargs)
        self.egress_probe = egress_probe

    def probe(self, target):
        if target not in {"blue", "green"}:
            raise ContractError("Fixed trial probe target required")
        value = self.routes.call("/probe?target=" + target)
        body = value.get("response", {})
        if value.get("ok") and (
            body.get("application") != self.application_id
            or body.get("environment") != target
            or body.get("component") != "api"
        ):
            raise ContractError("Independent trial identity mismatch")
        result = dict(
            ok=value.get("ok") is True,
            target=target,
            request_id=body.get("request_id"),
            observed_at=now().isoformat(),
            basis="independent-pod-http-over-tailnet-api",
            new_connection_blocked=value.get("connected") is False
            and value.get("error") == "upstream_unreachable",
        )
        self.last_probes[target] = result
        return result

    def probe_alive(self):
        return self.routes.call("/health") == {"ok": True, "probe": "alive"}

    def readback(self, command, at):
        value = super().readback(command, at)
        if command.action == "apply_isolation" and not self.routes.call(
            "/probe?target=neighbor"
        ).get("ok"):
            raise ContractError(
                "Healthy neighbor control failed; isolation unconfirmed"
            )
        if command.action == "apply_isolation":
            proof = self.egress_probe.denied()
            value = replace(value, evidence_json=canonical_json(value.evidence | proof))
        return value


class TerminalTrial(Trial):
    def __init__(self, *args, **kwargs):
        self.attack = None
        self.approved = False
        self.attack_attempted = False
        super().__init__(*args, **kwargs)

    def documents(self):
        return terminal_manifests(self.run_id, self.image)

    def connect_probe(self):
        # Transport goes through the existing authenticated tailnet Kubernetes
        # API and its fixed Service proxy. No port-forward or new public host.
        self.port = 0
        self.routes = ProxyRoutes(self.api, self.ns["blue"], self.ns["green"])
        if self.routes.call("/health") != {"ok": True, "probe": "alive"}:
            raise ContractError("Owned direct probe unavailable")

    @property
    def response_binding(self):
        return {"plan_id": self.plan.plan_id, "plan_digest": self.plan.fingerprint}

    def command(self, directory, action):
        binding = (
            self.response_binding
            if action == "respond" and hasattr(self, "plan")
            else self.plan_binding
        )
        return read(
            directory / (action + ".private.json"),
            key=self.hmac_key,
            binding=binding,
            revision=self.source_revision,
            at=now(),
            deadline=self.deadline,
            actions=frozenset({"attempt", "respond", "stop"}),
        )

    def record_prepared_plan(self, hold):
        # An available plan is not an approval. Approval is recorded only after
        # the operator accepts this exact compiled response digest.
        atomic_json(
            self.root / "response-plan.private.json",
            {
                **self.response_binding,
                "valid_until": self.plan.valid_until.isoformat(),
                "plan": self.plan.document,
                "approved": False,
                "attack_receipt_sha256": hashlib.sha256(
                    json.dumps(self.attack, sort_keys=True).encode()
                ).hexdigest(),
                "qualification_only": True,
            },
        )

    def bind_response(self, source, target, hold_reason):
        # Reuse compilation, guard and effect ledger; replace only the existing
        # owned adapter's transport with the same fixed API connection.
        self.egress_probe = EgressProbe(
            self.api,
            application_id=self.app,
            actor_uid=self.attack["actor_pod_uid"],
            peer_deployment_uid=self.neighbor["metadata"]["uid"],
        )
        baseline = self.egress_probe.baseline()
        atomic_json(self.root / "egress-baseline.private.json", baseline)
        super().bind_response(source, target, hold_reason)
        self.adapter = ProxyAdapter(
            kubeconfig=os.environ["KUBECONFIG"],
            binding=self.binding,
            source_namespace_uid=self.api.uids[self.ns["blue"]],
            target_namespace_uid=self.api.uids[self.ns["green"]],
            probe_port=0,
            routes=self.routes,
            api=self.api,
            egress_probe=self.egress_probe,
        )

    def authorize(self, command, permit, at, mutation):
        if not self.approved:
            raise ContractError("Current exact trial response approval required")
        pods = self.api.request("GET", f"/api/v1/namespaces/{self.ns['blue']}/pods")[
            "items"
        ]
        if not any(
            p.get("metadata", {}).get("uid") == self.attack["actor_pod_uid"]
            and not p["metadata"].get("deletionTimestamp")
            for p in pods
        ):
            raise ContractError("Observed actor Pod was replaced; require a new trial")
        return super().authorize(command, permit, at, mutation)

    def observe_attempt(self, request_id):
        if self.attack_attempted:
            raise ContractError("Trial attempt already dispatched; no replay")
        self.api.check_owned()
        if not all(
            self.routes.call("/probe?target=" + side).get("ok")
            for side in ("blue", "neighbor")
        ):
            raise ContractError("Normal actor and neighbor controls required")
        self.attack_attempted = True
        atomic_json(
            self.root / "attempt-intent.private.json",
            {"nonce": request_id, "at": now().isoformat(), "retry": False},
        )
        try:
            response = self.routes.call("/attempt", {"nonce": request_id})
        except ContractError:
            # These Pods are freshly created, credential-free fixed fixtures.
            # Preserve their bounded diagnostics before exact-UID cleanup.
            try:
                pods = self.api.request(
                    "GET", f"/api/v1/namespaces/{self.ns['blue']}/pods"
                )
                logs = []
                for pod in pods["items"]:
                    if (
                        pod["metadata"].get("labels", {}).get("app.kubernetes.io/name")
                        != "api"
                    ):
                        continue
                    name = pod["metadata"]["name"]
                    raw = self.api.client.get(
                        f"/api/v1/namespaces/{self.ns['blue']}/pods/{name}/log",
                        params={
                            "container": "api",
                            "tailLines": 25,
                            "limitBytes": 4096,
                        },
                        timeout=3,
                    )
                    if raw.status_code == 200 and len(raw.content) <= 4096:
                        logs.append(
                            {"pod_uid": pod["metadata"]["uid"], "log": raw.text}
                        )
                atomic_json(
                    self.root / "fixture-failure.private.json", {"actor_logs": logs}
                )
            except Exception:
                pass
            raise
        audit = self.routes.call("/audit?nonce=" + request_id).get("audit")
        pods = self.api.request("GET", f"/api/v1/namespaces/{self.ns['blue']}/pods")[
            "items"
        ]
        selector = self.source["spec"]["selector"]["matchLabels"]
        selected = [
            p
            for p in pods
            if all(
                p["metadata"].get("labels", {}).get(k) == v for k, v in selector.items()
            )
            and not p["metadata"].get("deletionTimestamp")
        ]
        if (
            len(selected) != 1
            or not isinstance(audit, dict)
            or response.get("nonce") != request_id
            or response.get("application") != self.app
            or response.get("authorization_denied") is not True
            or response.get("upstream_status") != 403
            or response.get("actor_pod_uid") != selected[0]["metadata"]["uid"]
            or audit.get("actor_pod_uid") != selected[0]["metadata"]["uid"]
            or audit.get("actor_ip") != selected[0]["status"].get("podIP")
            or audit.get("application") != self.app
            or audit.get("nonce") != request_id
            or audit.get("status") != 403
        ):
            raise ContractError(
                "Actual actor Pod and independent denial audit must match"
            )
        owners = [
            o
            for o in selected[0]["metadata"].get("ownerReferences", [])
            if o.get("controller") is True
        ]
        if (
            len(owners) != 1
            or owners[0].get("kind") != "ReplicaSet"
            or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,252}", owners[0].get("name", ""))
        ):
            raise ContractError("Actor Pod controller ownership unconfirmed")
        replica = self.api.request(
            "GET",
            f"/apis/apps/v1/namespaces/{self.ns['blue']}/replicasets/{owners[0]['name']}",
        )
        deployment_owners = [
            o
            for o in replica["metadata"].get("ownerReferences", [])
            if o.get("controller") is True
        ]
        if (
            replica["metadata"].get("uid") != owners[0].get("uid")
            or len(deployment_owners) != 1
            or deployment_owners[0].get("kind") != "Deployment"
            or deployment_owners[0].get("uid") != self.source["metadata"]["uid"]
        ):
            raise ContractError("Actor Pod does not belong to registered Deployment")
        self.attack = {
            "nonce": request_id,
            "actor_pod_uid": response["actor_pod_uid"],
            "upstream_status": 403,
            "observed_at": now().isoformat(),
            "actor_identity_verified": True,
            "independent_audit_verified": True,
            "kind": "controlled_unauthorized_internal_http_attempt",
        }
        atomic_json(self.root / "attack-receipt.private.json", self.attack)
        self.bind_response(
            self.snapshot("blue"),
            self.snapshot("green"),
            "controlled-unauthorized-internal-access",
        )

    def publish(self, phase, *, record_event=True):
        from .terminal_projection import projection

        self.observation_started_at = now()
        self.phase = phase
        self.snapshot_revision += 1
        self.probes = {
            target: self.routes.call("/probe?target=" + target)
            for target in ("blue", "green", "neighbor")
        }
        self.entry = self.routes.call("/entry")
        if self.adapter and any(s["action"] == "apply_isolation" for s in self.steps):
            self.isolation = self.adapter.readback(
                self.plan.command("apply_isolation", operation_id=self.app, epoch=1),
                now(),
            )
        if record_event:
            self.events.append(
                {"phase": phase, "occurred_at": self.observation_started_at.isoformat()}
            )
        document = projection(self)
        self.write_feed(document)
        atomic_json(
            self.root / "terminal-status.private.json",
            {
                "phase": phase,
                "observation_revision": document["revision"],
                "attack_observed": self.attack is not None,
                "approved": self.approved,
                "response_binding": self.response_binding
                if hasattr(self, "plan")
                else None,
                "steps": [s["action"] for s in self.steps],
                "deadline": self.deadline.isoformat(),
                "qualification_only": True,
            },
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--profile", type=Path, required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--operator-control", type=Path, required=True)
    p.add_argument("--hold-seconds", type=int, default=120)
    args = p.parse_args()
    os.umask(0o077)
    if not 0 <= args.hold_seconds <= 300:
        p.error("Bounded observation interval required")
    trial = TerminalTrial(args.state, args.image, json.loads(args.profile.read_text()))
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    result = {
        "qualification_only": True,
        "product_workflow_qualified": False,
        "response_verified": False,
    }
    complete_until = None
    try:
        trial.start()
        print(
            "READY: terminal attempt is accepted only for this owned workload.",
            flush=True,
        )
        while now() < trial.deadline - timedelta(seconds=40):
            if complete_until is not None and now() >= complete_until:
                break
            if trial.command(args.operator_control, "stop"):
                break
            request = (
                None
                if trial.attack_attempted
                else trial.command(args.operator_control, "attempt")
            )
            if request and not trial.attack_attempted:
                trial.observe_attempt(request["request_id"])
                print(
                    "OBSERVED: actual internal unauthorized request returned HTTP 403; Pod identity and independent audit matched.",
                    flush=True,
                )
            if trial.attack and not trial.approved:
                approval = trial.command(args.operator_control, "respond")
                if approval:
                    if trial.deadline - now() < timedelta(seconds=90):
                        raise ContractError("Insufficient bounded response time")
                    trial.approved = True
                    atomic_json(
                        trial.root / "approved-trial.private.json",
                        dict(
                            approval,
                            approved_at=now().isoformat(),
                            not_a_product_approval=True,
                        ),
                    )
                    trial.publish("approved")
                    for action in (
                        "apply_isolation",
                        "activate_replacement",
                        "verify_replacement",
                        "switch_route",
                    ):
                        trial.execute(action)
                        print("CONFIRMED: " + action, flush=True)
                        time.sleep(2)
                    result["response_verified"] = True
                    complete_until = min(
                        trial.deadline - timedelta(seconds=40),
                        now() + timedelta(seconds=args.hold_seconds),
                    )
            trial.publish(
                "watch"
                if result["response_verified"]
                else "awaiting_approval"
                if trial.attack
                else "normal",
                record_event=False,
            )
            time.sleep(3)
    except BaseException as error:
        result["error_type"] = type(error).__name__
        if not isinstance(error, KeyboardInterrupt):
            raise
    finally:
        result["cleanup"] = trial.close()
        atomic_json(args.state / "result.private.json", result)


if __name__ == "__main__":
    main()
