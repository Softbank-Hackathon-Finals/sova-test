"""Owned local k3s response qualification adapter, NOT a production credential broker.

No arbitrary kubeconfig, command, URL or manifest is accepted from the browser.
All mutations are limited to a registered test Deployment / owned NetworkPolicy.
"""

from datetime import UTC, datetime
import http.client
import hashlib
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from sova.domain.contracts import (
    ContractError,
    EffectObservation,
    EffectStatus,
    canonical_json,
)
from sova.security.domain.security_response import ACTIONS


def identity(resource):
    match = re.fullmatch(
        r"k8s://([a-z0-9-]+)/Deployment/([a-z0-9-]+)#([a-zA-Z0-9-]+)",
        resource.scope.resource_id,
    )
    if not match:
        raise ContractError("Only registered named Deployment identities supported")
    return match.groups()


class IndependentPodProbe:
    def __init__(self, probe_port, *, application_id="order-service", components=None):
        self.probe_port = probe_port
        self.application_id = application_id
        self.expected_components = components or {"blue": "api", "green": "api"}
        self.last_probes = {}

    def probe(self, target):
        if target not in {"blue", "green"}:
            raise ContractError("Unregistered test probe target")
        request_id = secrets.token_hex(16)
        connection = http.client.HTTPConnection("127.0.0.1", self.probe_port, timeout=3)
        try:
            connection.request(
                "GET", "/probe?target=" + target, headers={"X-Request-ID": request_id}
            )
            response = connection.getresponse()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise ContractError("Independent probe failed")
            result = json.loads(raw)
            if not isinstance(result, dict) or result.get("target") != target:
                raise ContractError("Probe binding mismatch")
            if result.get("ok"):
                body = result.get("response", {})
                if (
                    body.get("request_id") != request_id
                    or body.get("environment") != target
                    or body.get("application") != self.application_id
                    or body.get("component") != self.expected_components[target]
                ):
                    raise ContractError("Workload response identity mismatch")
            # Only safe fields leave the fixed test app/probe boundary.
            safe = {
                "ok": result.get("ok") is True,
                "target": target,
                "request_id": request_id,
                "duration_ms": result.get("duration_ms"),
                "observed_at": datetime.now(UTC).isoformat(),
                "basis": "independent-pod-http",
                "new_connection_blocked": result.get("connected") is False
                and result.get("error") == "upstream_unreachable",
            }
            self.last_probes[target] = safe
            return safe
        finally:
            connection.close()

    def probe_alive(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.probe_port, timeout=2)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            body = json.loads(response.read(1024))
            return response.status == 200 and body == {"ok": True, "probe": "alive"}
        finally:
            connection.close()


class OwnedKubernetesResponse(IndependentPodProbe):
    adapter_id = "sova-stateless-security-response"

    def __init__(
        self,
        *,
        kubeconfig,
        binding,
        source_namespace_uid,
        target_namespace_uid,
        probe_port,
        routes,
        route_id="test-entry",
    ):
        self.kubeconfig = Path(kubeconfig)
        self.binding = binding
        self.namespace_uids = {
            "source": source_namespace_uid,
            "target": target_namespace_uid,
        }
        self.probe_port = probe_port
        self.routes = routes
        self.route_id = route_id
        self.last_probes = {}
        self.application_id = binding.source.graph.application_id
        self.source_ns, self.source_name, self.source_uid = identity(
            binding.source_resource
        )
        self.target_ns, self.target_name, self.target_uid = identity(
            binding.target_resource
        )
        if self.source_ns == self.target_ns:
            raise ContractError("Distinct registered test namespaces required")
        self.initial_source = self.get("deployment", self.source_ns, self.source_name)
        self.initial_target = self.get("deployment", self.target_ns, self.target_name)
        self.expected_components = {"blue": self.source_name, "green": self.target_name}
        self.service_identities = {}
        for environment, snapshot, namespace, name in (
            ("source", binding.source, self.source_ns, self.source_name),
            ("target", binding.target, self.target_ns, self.target_name),
        ):
            resource = next(
                (r for r in snapshot.graph.resources if r.node_id == "service:" + name),
                None,
            )
            if resource is None:
                raise ContractError("Registered Service identity is required")
            self.service_identities[environment] = resource.scope.resource_id.split(
                "#"
            )[-1]
        self.target_template = self.initial_target["spec"]["template"]
        self.target_configuration = self.configuration_projection(
            self.target_ns, self.target_template
        )
        if (
            hashlib.sha256(
                canonical_json(self.target_configuration, limit=65536).encode()
            ).hexdigest()
            != binding.profile.configuration_digest
        ):
            raise ContractError(
                "Clean target configuration does not match admitted profile"
            )
        self.selector = self.initial_source["spec"]["selector"]["matchLabels"]
        self.check_workload_selector(self.initial_source, self.source_name)
        self.check_workload_selector(self.initial_target, self.target_name)
        self.route_before = self.routes.get(
            binding.source.graph.application_id, route_id
        )

    def workload_selector(self, name):
        return {
            "app.kubernetes.io/name": name,
            "app.kubernetes.io/part-of": self.application_id,
        }

    def check_workload_selector(self, workload, name):
        expected = self.workload_selector(name)
        spec = workload.get("spec", {})
        selector = spec.get("selector", {})
        labels = spec.get("template", {}).get("metadata", {}).get("labels", {})
        if (
            selector.get("matchLabels") != expected
            or selector.get("matchExpressions")
            or any(labels.get(k) != v for k, v in expected.items())
        ):
            raise ContractError("Exact application and component selector required")

    def kube(self, *args, input=None, timeout=20):
        result = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                str(self.kubeconfig),
                "--request-timeout=10s",
                *args,
            ],
            input=input,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode:
            raise ContractError(
                "Owned Kubernetes operation refused; inspect local state"
            )
        return result.stdout

    def get(self, kind, namespace, name):
        return json.loads(self.kube("-n", namespace, "get", kind, name, "-o", "json"))

    def configuration_projection(self, namespace, template):
        maps = []
        for volume in template.get("spec", {}).get("volumes", []):
            if set(volume) - {"name", "configMap"} or "configMap" not in volume:
                raise ContractError(
                    "Stateless test profile only supports immutable code ConfigMaps"
                )
            name = volume["configMap"]["name"]
            if not re.fullmatch(r"[a-z0-9-]+", name):
                raise ContractError("Unregistered ConfigMap name")
            data = self.get("configmap", namespace, name)
            if data.get("immutable") is not True:
                raise ContractError("Admitted code ConfigMaps must be immutable")
            maps.append(
                {
                    "name": name,
                    "uid": data["metadata"]["uid"],
                    "data_digest": hashlib.sha256(
                        canonical_json(data.get("data", {}), limit=65536).encode()
                    ).hexdigest(),
                }
            )
        return {"template": template, "configmaps": maps}

    def check_identities(self):
        for label, ns, name, uid in [
            ("source", self.source_ns, self.source_name, self.source_uid),
            ("target", self.target_ns, self.target_name, self.target_uid),
        ]:
            namespace = json.loads(self.kube("get", "namespace", ns, "-o", "json"))
            current = self.get("deployment", ns, name)
            self.check_workload_selector(current, name)
            if (
                namespace["metadata"]["uid"] != self.namespace_uids[label]
                or current["metadata"]["uid"] != uid
            ):
                raise ContractError("Registered namespace/Deployment was recreated")
            if (
                current["metadata"].get("labels", {}).get("app.kubernetes.io/part-of")
                != self.binding.source.graph.application_id
            ):
                raise ContractError("Deployment application ownership changed")
        for environment, namespace, name in (
            ("source", self.source_ns, self.source_name),
            ("target", self.target_ns, self.target_name),
        ):
            service = self.get("service", namespace, name)
            if (
                service["metadata"]["uid"] != self.service_identities[environment]
                or service["spec"].get("selector") != self.workload_selector(name)
                or service["spec"].get("type") != "ClusterIP"
                or service["spec"].get("externalName")
            ):
                raise ContractError("Registered Service routing identity changed")
            if not any(
                p.get("port") == 8080 and p.get("targetPort") == 8080
                for p in service["spec"].get("ports", [])
            ):
                raise ContractError("Registered Service port changed")
        target = self.get("deployment", self.target_ns, self.target_name)
        if target["spec"].get("replicas") not in (0, 1):
            raise ContractError("Replacement replica count outside admitted profile")
        if (
            target["spec"]["template"] != self.target_template
            or self.configuration_projection(self.target_ns, target["spec"]["template"])
            != self.target_configuration
        ):
            raise ContractError("Approved clean target template/configuration changed")

    def wait_replacement_ready(self):
        # Named GET is sufficient; do not silently require the broader watch/list
        # grants used by `kubectl rollout status` in an administrator session.
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            target = json.loads(
                self.kube(
                    "-n",
                    self.target_ns,
                    "get",
                    "deployment",
                    self.target_name,
                    "-o",
                    "json",
                    timeout=min(10, remaining),
                )
            )
            if target["metadata"]["uid"] != self.target_uid:
                raise ContractError("Replacement identity changed while waiting")
            self.check_workload_selector(target, self.target_name)
            if (
                target["spec"].get("replicas") != 1
                or target["spec"]["template"] != self.target_template
            ):
                raise ContractError("Replacement changed while waiting")
            if (
                target.get("status", {}).get("readyReplicas") == 1
                and target["status"].get("observedGeneration", 0)
                >= target["metadata"]["generation"]
            ):
                return
            time.sleep(min(0.5, max(0, deadline - time.monotonic())))
        raise ContractError("Replacement readiness deadline exceeded")

    def policy(self, command):
        name = "sova-quarantine-" + command.plan_digest[:20]
        return {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": name,
                "namespace": self.source_ns,
                "labels": {
                    "io.sova/session": "security-20261101",
                    "app.kubernetes.io/part-of": self.binding.source.graph.application_id,
                },
                "annotations": {
                    "io.sova/plan-digest": command.plan_digest,
                    "io.sova/source-uid": self.source_uid,
                },
            },
            "spec": {
                "podSelector": {"matchLabels": self.selector},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],
                "egress": [],
            },
        }

    def validate(self, command):
        if (
            command.adapter_id != self.adapter_id
            or command.action not in ACTIONS
            or command.step_id != command.action
            or command.parameters != self.binding.document
        ):
            raise ContractError("Unregistered response command")
        expected = (
            self.binding.source_resource
            if command.action == ACTIONS[0]
            else self.binding.target_resource
        )
        if (
            command.scope != expected.scope
            or command.expected_revision != expected.resource_revision
        ):
            raise ContractError("Response command scope/revision mismatch")
        self.check_identities()

    def apply(self, command):
        self.validate(command)
        if command.action == "apply_isolation":
            policies = json.loads(
                self.kube("-n", self.source_ns, "get", "networkpolicy", "-o", "json")
            )["items"]
            if policies:
                raise ContractError(
                    "Existing additive NetworkPolicies require separate review"
                )
            self.kube("create", "-f", "-", input=json.dumps(self.policy(command)))
        elif command.action == "activate_replacement":
            patch = [
                {"op": "test", "path": "/metadata/uid", "value": self.target_uid},
                {"op": "test", "path": "/spec/template", "value": self.target_template},
                {"op": "test", "path": "/spec/replicas", "value": 0},
                {"op": "replace", "path": "/spec/replicas", "value": 1},
            ]
            self.kube(
                "-n",
                self.target_ns,
                "patch",
                "deployment",
                self.target_name,
                "--type=json",
                "-p",
                json.dumps(patch),
            )
            self.wait_replacement_ready()
        elif command.action == "verify_replacement":
            if not self.probe("green")["ok"]:
                raise ContractError("Clean replacement actual HTTP verification failed")
        elif command.action == "switch_route":
            if not self.probe("green")["ok"]:
                raise ContractError("Target is no longer ready")
            self.routes.switch(
                command.scope.application_id,
                self.route_id,
                source=self.binding.source_resource.scope.environment_id,
                target=self.binding.target_resource.scope.environment_id,
                expected_revision=self.route_before["revision"],
                plan_digest=command.plan_digest,
            )

    def readback(self, command, now):
        self.check_identities()
        facts = {"action": command.action, "basis": "owned-local-k3s-test"}
        applied = False
        if command.action == "apply_isolation":
            expected = self.policy(command)
            observed = self.get(
                "networkpolicy", self.source_ns, expected["metadata"]["name"]
            )
            exact = (
                observed["metadata"].get("annotations", {}).get("io.sova/plan-digest")
                == command.plan_digest
                and observed["metadata"]["namespace"] == self.source_ns
                and observed["spec"].get("podSelector")
                == expected["spec"]["podSelector"]
                and set(observed["spec"].get("policyTypes", []))
                == {"Ingress", "Egress"}
                and not observed["spec"].get("ingress", [])
                and not observed["spec"].get("egress", [])
            )
            denied = []
            for _ in range(3):
                if not self.probe_alive():
                    raise ContractError(
                        "Probe path is unavailable, not isolation proof"
                    )
                denied.append(self.probe("blue")["new_connection_blocked"])
                if all(denied) and len(denied) >= 2:
                    break
                time.sleep(0.2)
            policies = json.loads(
                self.kube("-n", self.source_ns, "get", "networkpolicy", "-o", "json")
            )["items"]
            applied = exact and len(policies) == 1 and len(denied) >= 2 and all(denied)
            facts.update(
                policy_uid=observed["metadata"]["uid"],
                new_connection_denied=applied,
                probe_path_alive=self.probe_alive(),
            )
        elif command.action == "activate_replacement":
            target = self.get("deployment", self.target_ns, self.target_name)
            applied = (
                target["spec"]["replicas"] == 1
                and target["status"].get("readyReplicas", 0) == 1
                and target["status"].get("observedGeneration", 0)
                >= target["metadata"]["generation"]
            )
            facts.update(
                target_uid=self.target_uid,
                ready_replicas=target["status"].get("readyReplicas", 0),
            )
        elif command.action == "verify_replacement":
            proof = self.probe("green")
            applied = proof["ok"]
            facts.update(
                request_id=proof["request_id"],
                target_environment=self.binding.target_resource.scope.environment_id,
            )
        elif command.action == "switch_route":
            route = self.routes.get(command.scope.application_id, self.route_id)
            proof = self.probe("green")
            applied = (
                route["environment_id"]
                == self.binding.target_resource.scope.environment_id
                and route["plan_digest"] == command.plan_digest
                and proof["ok"]
            )
            facts.update(
                route_revision=route["revision"],
                target_environment=route["environment_id"],
                request_id=proof["request_id"],
            )
        return EffectObservation(
            command.scope,
            command.fingerprint,
            EffectStatus.APPLIED if applied else EffectStatus.UNKNOWN,
            now,
            canonical_json(facts),
        )
