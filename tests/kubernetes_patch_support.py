"""Synthetic Kubernetes protocol fixtures; live qualification is separate."""

from copy import deepcopy
from datetime import timedelta

from sova.adapters.kubernetes.image_patch import (
    ADAPTER_ID,
    KubernetesImagePatchRegistration,
    KubernetesImagePatchAdapter,
    deployment_configuration,
)
from sova.domain.discovery import KubernetesReadRegistration
from sova.domain.contracts import (
    ResourceScope,
    EffectCommand,
    canonical_json,
    ContractError,
)
from sova_security.domain.remediation import TestedArtifact


def image_patch_bundle(now):
    scope = ResourceScope(
        "tenant-a", "app-a", "cluster-a", "k8s://owned/Deployment/api#deployment-one"
    )
    reader = KubernetesReadRegistration(
        scope.tenant_id,
        scope.application_id,
        scope.environment_id,
        "local-qualification",
        "https://localhost:6443",
        ("127.0.0.1",),
        "c" * 64,
        "owned",
        "namespace-one",
        1,
        now,
        now + timedelta(minutes=10),
    )
    labels = {
        "app.kubernetes.io/name": "api",
        "app.kubernetes.io/part-of": scope.application_id,
    }
    workload = {
        "kind": "Deployment",
        "apiVersion": "apps/v1",
        "metadata": {
            "name": "api",
            "namespace": "owned",
            "uid": "deployment-one",
            "resourceVersion": "10",
            "generation": 1,
            "labels": labels,
            "annotations": {"deployment.kubernetes.io/revision": "1"},
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": labels},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "containers": [
                        {
                            "name": "http",
                            "image": "registry.example/owned/probe@sha256:" + "a" * 64,
                            "ports": [{"containerPort": 8080}],
                        }
                    ]
                },
            },
        },
    }
    config = deployment_configuration(workload)
    artifact = TestedArtifact(scope, "b" * 64, "d" * 64, config, "e" * 64)
    reg = KubernetesImagePatchRegistration(
        reader,
        scope,
        "api",
        "deployment-one",
        "http",
        "registry.example/owned/probe",
        "a" * 64,
        config,
        "10",
        1,
        artifact,
        "1" * 64,
        "2" * 64,
        "3" * 64,
        now,
        now + timedelta(minutes=5),
    )
    command = EffectCommand(
        scope,
        "operation",
        "patch-1",
        ADAPTER_ID,
        "apply-verified-patch",
        "once",
        "f" * 64,
        "10",
        1,
        now + timedelta(minutes=2),
        canonical_json(
            {
                "request_digest": reg.request_digest,
                "receipt_digest": reg.receipt_digest,
                "proposal_digest": reg.proposal_digest,
                "artifact": artifact.document,
            }
        ),
    )
    state = {
        "workload": workload,
        "namespace_uid": "namespace-one",
        "registration": reg,
        "allowed": True,
        "authenticated": True,
        "time": now,
        "calls": [],
        "late": lambda: None,
        "lost_response": False,
        "conflict": False,
    }

    class Transport:
        registration_digest = reg.fingerprint

        def namespace(self):
            return {
                "kind": "Namespace",
                "metadata": {"name": "owned", "uid": state["namespace_uid"]},
            }

        def deployment(self):
            state["late"]()
            return deepcopy(state["workload"])

        def patch_image(self, operations):
            state["calls"].append(deepcopy(operations))
            if state["conflict"]:
                raise ContractError("Synthetic conditional test failed")
            current = state["workload"]
            assert operations[0]["value"] == current["metadata"]["uid"]
            assert operations[1]["value"] == current["metadata"]["resourceVersion"]
            assert operations[2]["value"] == current["spec"]["template"]
            current["metadata"]["annotations"] = operations[3]["value"]
            current["spec"]["template"]["spec"]["containers"][0]["image"] = operations[
                4
            ]["value"]
            current["metadata"]["resourceVersion"] = "11"
            if state["lost_response"]:
                raise TimeoutError("Synthetic response lost after atomic patch")
            return deepcopy(current)

    adapter = KubernetesImagePatchAdapter(
        reg,
        transport=Transport(),
        current_registration=lambda: state["registration"],
        authenticate_registration=lambda _: state["authenticated"],
        authorize=lambda *_: state["allowed"],
        clock=lambda: state["time"],
    )
    return reg, command, adapter, state
