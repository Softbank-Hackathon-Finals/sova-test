"""Versioned owner-only partial-containment qualification using the existing ledger.

The finite adapter below is a fixture adapter, not a T10 approval authority or
an attack detector. No arbitrary app, namespace, image, URL or command is accepted.
"""

import argparse
import hashlib
import json
import os
import secrets
import signal
import time
from pathlib import Path

from sova.application.effects import UncertainEffect
from sova.domain.contracts import (
    ContractError,
    EffectObservation,
    EffectStatus,
    ExecutionPermit,
    ResourceScope,
    canonical_json,
)
from sova_security.contracts.evidence import Gate, RevisionSet, VerificationObligation
from sova_security.contracts.plans import LifecyclePlan, PlanPurpose, PlanStep

from .controls import read
from .egress import EgressProbe
from .expanded_fixture import expanded_manifests
from .terminal import ProxyRoutes, TerminalTrial
from .trial import atomic_json, now


def sha(value):
    return hashlib.sha256(canonical_json(value, limit=131072).encode()).hexdigest()


class IncidentRoutes(ProxyRoutes):
    def call(self, path, body=None):
        # Fixed paths/finite component enums only; credentials remain in TrialAPI.
        import re

        if not (
            path
            in {
                "/streams",
                "/streams/open",
                "/streams/close",
                "/worker-route",
                "/return-route",
                "/pipeline",
            }
            or re.fullmatch(r"/probe\?target=(blue|green)-worker", path)
        ):
            return super().call(path, body)
        nonce = secrets.token_hex(16)
        query = path + ("&" if "?" in path else "?") + "request_id=" + nonce
        value = self.api.request(
            "POST" if body is not None else "GET",
            f"/api/v1/namespaces/{self.api.namespaces['probe']}/services/probe:8080/proxy"
            + (path if body is not None else query),
            body,
        )
        if (
            path.startswith("/probe")
            and value.get("ok")
            and value.get("response", {}).get("request_id") != nonce
        ):
            raise ContractError("Fresh component response required")
        if path == "/pipeline" and value.get("request_id") != nonce:
            raise ContractError("Fresh business response required")
        return value


class ComponentEgress(EgressProbe):
    def __init__(self, *args, component, **kwargs):
        super().__init__(*args, **kwargs)
        self.component = component

    def call(self):
        nonce = secrets.token_hex(16)
        value = self.api.request(
            "POST",
            f"/api/v1/namespaces/{self.api.namespaces['blue']}/services/{self.component}:8080/proxy/egress-check",
            {"nonce": nonce},
        )
        if not (
            value.get("nonce") == nonce
            and value.get("application") == self.application_id
            and value.get("actor_pod_uid") == self.actor_uid
            and value.get("baseline_cached") is True
            and self.peer
            == {"uid": value.get("peer_pod_uid"), "ip": value.get("peer_ip")}
        ):
            raise ContractError("Current component egress binding required")
        return value


class IncidentAdapter:
    adapter_id = "owned-incident-qualification-v2"

    def __init__(self, trial):
        self.trial = trial

    def validate(self, command):
        t = self.trial
        if (
            command.fingerprint not in t.commands
            or command.adapter_id != self.adapter_id
        ):
            raise ContractError("Unregistered incident command")
        t.api.check_owned()
        for side in ("blue", "green"):
            for component in ("api", "worker", "neighbor"):
                if (side, component) not in t.artifacts:
                    continue
                doc = t.api.get("deployment", side, component)
                record = t.artifacts[side, component]
                cm = t.api.get("configmap", side, component + "-code")
                if (
                    doc["metadata"]["uid"] != record["uid"]
                    or sha(doc["spec"]["template"]) != record["template"]
                    or sha({"uid": cm["metadata"]["uid"], "data": cm["data"]})
                    != record["code"]
                    or cm.get("immutable") is not True
                ):
                    raise ContractError(
                        "Registered clean artifact/configuration changed"
                    )

    def apply(self, command):
        self.validate(command)
        t = self.trial
        c = command.parameters["component"]
        action = command.action
        if action == "isolate":
            if t.policies(c):
                raise ContractError("Existing policies require separate review")
            policy = t.api.create(t.policy(c))
            t.policy_uids[c] = policy["metadata"]["uid"]
        elif action in {"fence", "activate", "restore"}:
            side = "green" if action == "activate" else "blue"
            old, new = (1, 0) if action == "fence" else (0, 1)
            doc = t.api.get("deployment", side, c)
            t.api.request(
                "PATCH",
                f"/apis/apps/v1/namespaces/{t.ns[side]}/deployments/{c}",
                [
                    {
                        "op": "test",
                        "path": "/metadata/uid",
                        "value": doc["metadata"]["uid"],
                    },
                    {
                        "op": "test",
                        "path": "/metadata/resourceVersion",
                        "value": doc["metadata"]["resourceVersion"],
                    },
                    {"op": "test", "path": "/spec/replicas", "value": old},
                    {"op": "replace", "path": "/spec/replicas", "value": new},
                ],
                patch=True,
            )
            if action != "fence":
                t.wait(side, c)
            else:
                t.wait_absent(c)
                t.routes.call("/streams/close", {"component": c, "nonce": t.streams[c]})
        elif action in {"inject_failure", "clear_failure"}:
            pod = t.current_pod("green", c)
            t.api.request(
                "POST",
                f"/api/v1/namespaces/{t.ns['green']}/pods/{pod['metadata']['name']}:8080/proxy/fault",
                {"failed": action == "inject_failure"},
            )
            if action == "clear_failure":
                t.wait("green", c)
        elif action == "release_policy":
            # Retain the policy until the fresh original passes artifact and HTTP checks.
            t.clean_source(c)
            p = t.policies(c)
            if len(p) != 1 or p[0]["metadata"]["uid"] != t.policy_uids[c]:
                raise ContractError("Isolation policy identity changed")
            t.api.request(
                "DELETE",
                f"/apis/networking.k8s.io/v1/namespaces/{t.ns['blue']}/networkpolicies/{p[0]['metadata']['name']}",
                {
                    "apiVersion": "v1",
                    "kind": "DeleteOptions",
                    "preconditions": {
                        "uid": t.policy_uids[c],
                        "resourceVersion": p[0]["metadata"]["resourceVersion"],
                    },
                },
            )
        elif action in {"switch", "return"}:
            side = "green" if action == "switch" else "blue"
            t.checked_probe(side, c)
            if action == "switch" and not t.revalidated:
                raise ContractError("Separate successful revalidation required")
            if action == "return":
                t.clean_source(c)
            route = t.route(c)
            source, target = (
                (t.ns["blue"], t.ns["green"])
                if action == "switch"
                else (t.ns["green"], t.ns["blue"])
            )
            body = {
                "source": source,
                "target": target,
                "expected_revision": route["revision"],
                "plan_digest": command.plan_digest,
            }
            if action == "return":
                body["component"] = c
            t.routes.call(
                "/return-route"
                if action == "return"
                else "/route"
                if c == "api"
                else "/worker-route",
                body,
            )
        elif action != "verify":
            raise ContractError("Finite incident action required")

    def readback(self, command, at):
        self.validate(command)
        t = self.trial
        c, action = command.parameters["component"], command.action
        facts = {
            "action": action,
            "component": c,
            "selected_components": list(t.components),
            "incident_hold_active": True,
        }
        if action == "isolate":
            p = t.policies(c)
            if (
                len(p) != 1
                or p[0]["metadata"]["uid"] != t.policy_uids[c]
                or p[0]["spec"] != t.policy(c)["spec"]
            ):
                raise ContractError("Exact component policy required")
            for _ in range(2):
                proof = t.probe("blue", c)
                if (
                    proof.get("connected") is not False
                    or proof.get("error") != "upstream_unreachable"
                ):
                    raise ContractError("New ingress connection was not denied")
            facts.update(t.egress[c].denied(), ingress_new_connection_denied=True)
        elif action == "fence":
            t.wait_absent(c)
            stream = t.routes.call("/streams")["streams"][c]
            if (
                stream.get("pod_uid") != t.old_pods[c]
                or stream.get("nonce") != t.streams[c]
                or stream.get("client_socket_closed") is not True
            ):
                raise ContractError("Registered old stream termination unconfirmed")
            facts.update(
                original_pod_absent=True,
                client_socket_closed=True,
                old_pod_uid=t.old_pods[c],
                mechanism="source-pod-fence-and-probe-socket-close",
                natural_eof=stream.get("eof") is True,
            )
        elif action in {"activate", "clear_failure", "verify"}:
            proof = t.checked_probe("green", c)
            facts.update(
                http_nonce=proof["response"]["request_id"],
                pod_uid=proof["response"]["pod_uid"],
            )
        elif action == "inject_failure":
            proof = t.probe("green", c)
            if proof.get("ok"):
                raise ContractError("Failure injection did not change actual response")
            facts.update(actual_verification_failed=True)
        elif action == "restore":
            facts.update(t.clean_source(c))
        elif action == "release_policy":
            if t.policies(c):
                raise ContractError("Component policy removal unconfirmed")
            facts.update(t.clean_source(c))
            t.checked_probe("blue", c)
        elif action in {"switch", "return"}:
            expected = t.ns["green" if action == "switch" else "blue"]
            route = t.route(c)
            if (
                route.get("environment_id") != expected
                or route.get("plan_digest") != command.plan_digest
            ):
                raise ContractError("Actual route readback mismatch")
            proof = t.checked_probe("green" if action == "switch" else "blue", c)
            facts.update(
                route_revision=route["revision"],
                environment_id=expected,
                pod_uid=proof["response"]["pod_uid"],
            )
        # An independent, unselected component must remain accessible throughout.
        if not t.routes.call("/probe?target=neighbor").get("ok"):
            raise ContractError("Unselected neighbor unavailable")
        facts["neighbor_healthy"] = True
        return EffectObservation(
            command.scope,
            command.fingerprint,
            EffectStatus.APPLIED,
            at,
            canonical_json(facts),
        )


class IncidentTrial(TerminalTrial):
    def __init__(self, *args, components=("api", "worker"), **kwargs):
        if components not in {("api",), ("worker",), ("api", "worker")}:
            raise ContractError("Only explicitly admitted stateless components")
        self.components = components
        self.artifacts, self.egress, self.old_pods, self.streams = {}, {}, {}, {}
        self.commands, self.receipts, self.policy_uids = {}, {}, {}
        self.active_plan = None
        self.stage, self.revalidated, self.returned = "normal", False, False
        self.expanded_ready = False
        super().__init__(*args, **kwargs)

    def documents(self):
        return expanded_manifests(self.run_id, self.image)

    def connect_probe(self):
        self.port = 0
        self.routes = IncidentRoutes(self.api, self.ns["blue"], self.ns["green"])

    def start(self):
        super().start()
        self.wait("blue", "worker")
        for side, components in (
            ("blue", ("api", "worker", "neighbor")),
            ("green", ("api", "worker")),
        ):
            for c in components:
                dep = self.api.get("deployment", side, c)
                cm = self.api.get("configmap", side, c + "-code")
                self.artifacts[side, c] = {
                    "uid": dep["metadata"]["uid"],
                    "template": sha(dep["spec"]["template"]),
                    "code": sha({"uid": cm["metadata"]["uid"], "data": cm["data"]}),
                }
        for c in self.components:
            pod = self.current_pod("blue", c)
            self.old_pods[c] = pod["metadata"]["uid"]
            self.egress[c] = ComponentEgress(
                self.api,
                component=c,
                application_id=self.app,
                actor_uid=self.old_pods[c],
                peer_deployment_uid=self.neighbor["metadata"]["uid"],
            )
            self.egress[c].baseline()
            self.streams[c] = secrets.token_hex(16)
            self.routes.call(
                "/streams/open", {"component": c, "nonce": self.streams[c]}
            )
        time.sleep(1)
        streams = self.routes.call("/streams")["streams"]
        if not all(
            streams[c].get("alive")
            and streams[c].get("pod_uid") == self.old_pods[c]
            and streams[c].get("lines", 0) >= 1
            for c in self.components
        ):
            raise ContractError("Actual preexisting connection baseline required")
        self.incident_adapter = IncidentAdapter(self)
        self.expanded_ready = True
        self.publish("normal")

    def current_pod(self, side, component):
        dep = self.api.get("deployment", side, component)
        pods = self.api.request("GET", f"/api/v1/namespaces/{self.ns[side]}/pods")[
            "items"
        ]
        found = []
        for pod in pods:
            meta = pod["metadata"]
            if (
                meta.get("labels", {}).get("app.kubernetes.io/name") != component
                or meta.get("labels", {}).get("app.kubernetes.io/part-of") != self.app
                or meta.get("deletionTimestamp")
                or pod.get("status", {}).get("phase") != "Running"
            ):
                continue
            owners = [
                o
                for o in meta.get("ownerReferences", [])
                if o.get("controller") is True
            ]
            if len(owners) != 1 or owners[0].get("kind") != "ReplicaSet":
                raise ContractError("Registered component controller required")
            rs = self.api.request(
                "GET",
                f"/apis/apps/v1/namespaces/{self.ns[side]}/replicasets/{owners[0]['name']}",
            )
            parents = [
                o
                for o in rs["metadata"].get("ownerReferences", [])
                if o.get("controller") is True
            ]
            if (
                rs["metadata"]["uid"] != owners[0].get("uid")
                or len(parents) != 1
                or parents[0].get("kind") != "Deployment"
                or parents[0].get("uid") != dep["metadata"]["uid"]
            ):
                raise ContractError("Exact Deployment owner required")
            found.append(pod)
        if len(found) != 1:
            raise ContractError("One current component Pod required")
        return found[0]

    def wait_absent(self, component):
        until = time.monotonic() + 25
        while time.monotonic() < until:
            pods = self.api.request(
                "GET", f"/api/v1/namespaces/{self.ns['blue']}/pods"
            )["items"]
            if not any(p["metadata"]["uid"] == self.old_pods[component] for p in pods):
                return
            time.sleep(0.5)
        raise ContractError("Original execution still exists")

    def probe(self, side, component):
        return self.routes.call(
            "/probe?target=" + side + ("-worker" if component == "worker" else "")
        )

    def checked_probe(self, side, component):
        result = self.probe(side, component)
        pod = self.current_pod(side, component)
        body = result.get("response", {})
        if not (
            result.get("ok")
            and body.get("application") == self.app
            and body.get("environment") == side
            and body.get("component") == component
            and body.get("pod_uid") == pod["metadata"]["uid"]
        ):
            raise ContractError("Actual current component HTTP verification failed")
        return result

    def clean_source(self, component):
        pod = self.current_pod("blue", component)
        if pod["metadata"]["uid"] == self.old_pods[component]:
            raise ContractError("Original incident Pod cannot be unquarantined")
        nonce = secrets.token_hex(16)
        result = self.api.request(
            "GET",
            f"/api/v1/namespaces/{self.ns['blue']}/pods/{pod['metadata']['name']}:8080/proxy/health?nonce={nonce}",
        )
        # Pod proxy does not propagate an X-Request-ID header. This fixed fixture
        # echoes the nonce query explicitly; UID/configuration are checked too.
        if not (
            result.get("pod_uid") == pod["metadata"]["uid"]
            and result.get("application") == self.app
            and result.get("probe_nonce") == nonce
        ):
            raise ContractError("Fresh restored source probe mismatch")
        images = pod.get("status", {}).get("containerStatuses", [])
        if len(images) != 1 or self.image.split("@", 1)[1] not in images[0].get(
            "imageID", ""
        ):
            raise ContractError("Running image digest differs from admitted artifact")
        return {
            "new_source_pod_uid": pod["metadata"]["uid"],
            "old_source_pod_uid": self.old_pods[component],
            "same_registered_image": True,
            "fresh_source_probe": True,
        }

    def policies(self, component):
        rows = self.api.request(
            "GET",
            f"/apis/networking.k8s.io/v1/namespaces/{self.ns['blue']}/networkpolicies",
        )["items"]
        result = []
        for row in rows:
            selector = row["spec"]["podSelector"]
            if selector.get("matchExpressions"):
                raise ContractError("Unreviewed expression policy")
            labels = selector.get("matchLabels", {})
            if all(
                {
                    "app.kubernetes.io/name": component,
                    "app.kubernetes.io/part-of": self.app,
                }.get(k)
                == v
                for k, v in labels.items()
            ):
                result.append(row)
        return result

    def policy(self, component):
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "isolate-" + component,
                "namespace": self.ns["blue"],
                "labels": {"sova.io/trial": self.run_id},
                "annotations": {
                    "sova.io/incident": self.run_id,
                    "sova.io/source-uid": self.artifacts["blue", component]["uid"],
                },
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "app.kubernetes.io/name": component,
                        "app.kubernetes.io/part-of": self.app,
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }

    def route(self, component):
        return self.routes.call("/route" if component == "api" else "/worker-route")

    def prepare_plan(self, kind):
        cset = self.components
        if kind == "respond":
            actions = [(a, c) for a in ("isolate", "fence", "activate") for c in cset]
            actions += [("inject_failure", cset[0]), ("verify", cset[0])]
        elif kind == "recheck":
            actions = (
                [("clear_failure", cset[0])]
                + [("verify", c) for c in cset]
                + [("switch", c) for c in reversed(cset)]
            )
        elif kind == "return":
            actions = [
                (a, c)
                for a in ("restore", "release_policy", "return")
                for c in reversed(cset)
            ]
        else:
            raise ContractError("Unknown qualification plan")
        steps = []
        for action, c in actions:
            side = (
                "green"
                if action
                in {"activate", "inject_failure", "clear_failure", "verify", "switch"}
                else "blue"
            )
            key = action + "-" + c
            steps.append(
                PlanStep(
                    key,
                    ResourceScope(
                        "onprem-qualification",
                        self.app,
                        self.ns[side],
                        self.ns[side] + "/deployment/" + c,
                    ),
                    IncidentAdapter.adapter_id,
                    action,
                    canonical_json(
                        {
                            "component": c,
                            "selected": list(cset),
                            "incident": self.run_id,
                            "artifact": self.artifacts[side, c],
                            "namespaces": self.api.uids,
                        }
                    ),
                    self.artifacts[side, c]["uid"],
                    () if not steps else (steps[-1].step_id,),
                )
            )
        binding = {
            "namespaces": self.api.uids,
            "components": list(cset),
            "artifacts": {s + ":" + c: v for (s, c), v in self.artifacts.items()},
            "old_pods": self.old_pods,
            "streams": self.streams,
            "routes": {c: self.route(c) for c in cset},
            "kind": kind,
        }
        plan = LifecyclePlan(
            "incident-" + self.run_id + "-" + kind,
            "onprem-qualification",
            self.app,
            "qualification-compiler",
            PlanPurpose.SECURITY_RESPONSE
            if kind == "respond"
            else PlanPurpose.RECOVERY,
            RevisionSet(
                self.image.split("@sha256:")[1],
                sha(binding),
                sha({"policy": "owned-stateless-incident-v2"}),
                sha({"namespaces": self.api.uids}),
            ),
            self.deadline,
            tuple(steps),
            (
                VerificationObligation(
                    "current-owner-and-artifact",
                    steps[0].scope,
                    Gate.PREFLIGHT,
                    "owned-incident-v2",
                ),
            ),
            origin_plan_digest=None if kind == "respond" else self.origin_plan,
            reason="owner-only stateless qualification; incident hold preserved",
        )
        self.pending_kind, self.pending_plan = kind, plan
        for step in plan.steps:
            command = plan.command(step.step_id, operation_id=plan.plan_id, epoch=1)
            self.commands[command.fingerprint] = command
        if kind == "respond":
            self.origin_plan = plan.fingerprint
        atomic_json(
            self.root / "response-plan.private.json",
            {
                "plan_id": plan.plan_id,
                "plan_digest": plan.fingerprint,
                "valid_until": plan.valid_until.isoformat(),
                "plan": plan.document,
                "kind": kind,
                "approved": False,
                "qualification_only": True,
            },
        )
        self.publish("awaiting_" + kind)

    def bind_response(self, source, target, hold_reason):
        # The existing terminal path has already checked the real actor Pod,
        # ReplicaSet/Deployment owner and independent 403 audit at this point.
        if not self.attack or self.attack.get("actor_identity_verified") is not True:
            raise ContractError("Actual terminal incident required")
        self.prepare_plan("respond")

    def authorize(self, command, permit, at, mutation):
        if (
            at >= self.deadline
            or not self.active_plan
            or command.plan_digest != self.active_plan.fingerprint
        ):
            raise ContractError("Exact current approved qualification plan required")
        if command.fingerprint not in self.commands:
            raise ContractError("Unknown command")
        step = next(s for s in self.active_plan.steps if s.step_id == command.step_id)
        for dependency in step.depends_on:
            previous = self.active_plan.command(
                dependency, operation_id=self.active_plan.plan_id, epoch=1
            )
            if self.receipts.get(previous.fingerprint) != EffectStatus.APPLIED:
                raise ContractError("Previous effect is not confirmed")
        self.api.verify_identity()
        return True

    def accept_plan(self, approval):
        self.active_plan = self.pending_plan
        self.approved = True
        atomic_json(
            self.root / (self.pending_kind + "-approval.private.json"),
            dict(
                approval,
                approved_at=now().isoformat(),
                personal_qualification_only=True,
                product_approval=False,
            ),
        )
        for step in self.active_plan.steps:
            if step.action == "switch":
                verified = [s for s in self.active_plan.steps if s.action == "verify"]
                if not verified:
                    raise ContractError("Current complete verifier set required")
                self.revalidated = len(verified) == len(self.components) and all(
                    self.receipts.get(
                        self.active_plan.command(
                            s.step_id, operation_id=self.active_plan.plan_id, epoch=1
                        ).fingerprint
                    )
                    == EffectStatus.APPLIED
                    for s in verified
                )
            command = self.active_plan.command(
                step.step_id, operation_id=self.active_plan.plan_id, epoch=1
            )
            permit = ExecutionPermit(
                command.scope,
                command.operation_id,
                command.plan_digest,
                command.fingerprint,
                1,
                command.expires_at,
            )
            try:
                record = self.executor.execute(command, permit, self.incident_adapter)
            except UncertainEffect:
                if self.pending_kind == "respond" and step.action == "verify":
                    # Only this read-only verification may be followed by a NEW
                    # plan. Never replay an uncertain mutation.
                    if any(
                        self.route(c)["environment_id"] != self.ns["blue"]
                        for c in self.components
                    ):
                        raise ContractError(
                            "Failed verification changed a route"
                        ) from None
                    atomic_json(
                        self.root / "verification-failure.private.json",
                        {
                            "command_digest": command.fingerprint,
                            "read_only_effect": True,
                            "route_unchanged": True,
                            "incident_hold_active": True,
                            "at": now().isoformat(),
                        },
                    )
                    self.publish("verification_failed")
                    self.prepare_plan("recheck")
                    return
                raise
            self.receipts[command.fingerprint] = record.status
            self.steps.append(
                {
                    "action": step.step_id,
                    "command_digest": command.fingerprint,
                    "observed_at": record.observation.observed_at.isoformat(),
                    "observation": record.observation.evidence,
                }
            )
            atomic_json(self.root / "effects-summary.private.json", self.steps)
            self.publish(step.step_id)
        if self.pending_kind == "recheck":
            self.revalidated = True
            self.publish("switched")
            self.prepare_plan("return")
        elif self.pending_kind == "return":
            self.returned = True
            self.publish("returned")

    def command(self, directory, action):
        plan = getattr(self, "pending_plan", None)
        binding = (
            {"plan_id": plan.plan_id, "plan_digest": plan.fingerprint}
            if action != "stop" and plan
            else self.plan_binding
        )
        return read(
            directory / (action + ".private.json"),
            key=self.hmac_key,
            binding=binding,
            revision=self.source_revision,
            at=now(),
            deadline=self.deadline,
            actions=frozenset({"attempt", "respond", "recheck", "return", "stop"}),
        )

    def publish(self, phase, *, record_event=True):
        if not self.expanded_ready:
            return
        from .incident_projection import projection

        self.phase, self.observation_started_at = phase, now()
        self.snapshot_revision += 1
        if record_event:
            self.events.append({"phase": phase, "occurred_at": now().isoformat()})
        self.write_feed(projection(self))
        plan = getattr(self, "pending_plan", None)
        atomic_json(
            self.root / "terminal-status.private.json",
            {
                "phase": phase,
                "observation_revision": self.snapshot_revision,
                "attack_observed": bool(self.attack),
                "approved": self.approved,
                "steps": [s["action"] for s in self.steps],
                "deadline": self.deadline.isoformat(),
                "pending_kind": self.pending_kind if plan else None,
                "response_binding": {
                    "plan_id": plan.plan_id,
                    "plan_digest": plan.fingerprint,
                }
                if plan
                else None,
                "returned": self.returned,
                "revalidated": self.revalidated,
                "components": list(self.components),
                "qualification_only": True,
            },
        )


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--profile", type=Path, required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--operator-control", type=Path, required=True)
    p.add_argument("--hold-seconds", type=int, default=60)
    p.add_argument(
        "--components", choices=["api", "worker", "api,worker"], default="api,worker"
    )
    args = p.parse_args()
    if not 0 <= args.hold_seconds <= 120:
        p.error("Bounded observation interval required")
    os.umask(0o077)
    trial = IncidentTrial(
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
    }
    try:
        trial.start()
        until = None
        while now() < trial.deadline:
            if trial.command(args.operator_control, "stop") or (
                until and time.monotonic() >= until
            ):
                break
            if not trial.attack_attempted:
                request = trial.command(args.operator_control, "attempt")
                if request:
                    trial.observe_attempt(request["request_id"])
            if trial.attack and not trial.returned:
                approval = trial.command(args.operator_control, trial.pending_kind)
                if approval:
                    trial.accept_plan(approval)
                    if trial.returned:
                        result.update(
                            response_verified=True,
                            partial_containment_verified=True,
                            verification_failure_held=True,
                            revalidation_verified=True,
                            source_return_verified=True,
                            incident_hold_active=True,
                        )
                        until = time.monotonic() + args.hold_seconds
            trial.publish(trial.phase, record_event=False)
            time.sleep(1)
    except BaseException as error:
        result["error_type"] = type(error).__name__
        if not isinstance(error, KeyboardInterrupt):
            raise
    finally:
        result["cleanup"] = trial.close()
        atomic_json(args.state / "result.private.json", result)


if __name__ == "__main__":
    main()
