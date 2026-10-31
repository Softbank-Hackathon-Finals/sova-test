"""Normalize a bounded, scoped Kubernetes export without invoking kubectl.

Service selector relationships are declarations, NOT observed traffic. Secret
payloads and env values are never copied into the normalized graph.
"""

from datetime import datetime

from sova.domain.contracts import ContractError, ResourceScope, identifier
from sova.domain.system_graph import (
    Portability,
    RelationKind,
    ResourceKind,
    SystemGraph,
    SystemRelation,
    SystemResource,
)

ALLOWED_KINDS = {"Deployment", "StatefulSet", "Service", "PersistentVolumeClaim"}


def _snapshot_graph(
    document,
    *,
    tenant_id,
    application_id,
    environment_id,
    namespace,
    location,
    observed_at: datetime,
    valid_until: datetime,
):
    for value in (tenant_id, application_id, environment_id, namespace, location):
        identifier(value)
    if (
        not isinstance(document, dict)
        or document.get("kind") != "List"
        or not isinstance(document.get("items"), list)
        or not 1 <= len(document["items"]) <= 128
    ):
        raise ContractError("Bounded Kubernetes List export required")
    resources = []
    relations = []
    workloads = {}
    services = []
    claims = {}
    claim_refs = []
    seen_uids = set()
    for item in document["items"]:
        if not isinstance(item, dict) or item.get("kind") not in ALLOWED_KINDS:
            raise ContractError(
                "Unsupported inventory kind; secret payloads are forbidden"
            )
        metadata = item.get("metadata", {})
        kind = item["kind"]
        spec = item.get("spec", {})
        if not isinstance(spec, dict):
            raise ContractError("Resource spec must be an object")
        if (
            not isinstance(metadata, dict)
            or metadata.get("namespace") != namespace
            or not isinstance(metadata.get("labels"), dict)
            or metadata["labels"].get("app.kubernetes.io/part-of") != application_id
        ):
            raise ContractError(
                "Kubernetes export crosses registered namespace/application"
            )
        name = identifier(metadata.get("name"), "resource name")
        uid = identifier(metadata.get("uid"), "resource uid")
        revision = identifier(metadata.get("resourceVersion"), "resource version")
        if uid in seen_uids:
            raise ContractError("Duplicate Kubernetes UID")
        seen_uids.add(uid)
        node_id = kind.lower() + ":" + name
        requirements = [
            "live-collection-not-verified",
            "kubernetes-rbac-and-network-policy",
            "declared-links-not-traffic",
        ]
        resource_kind = ResourceKind.SERVICE
        portability = Portability.UNKNOWN
        requirements.append("application-and-external-dependencies-review")
        if kind in {"Deployment", "StatefulSet"}:
            template = spec.get("template", {})
            template_spec = template.get("spec", {})
            labels = template.get("metadata", {}).get("labels", {})
            if not isinstance(labels, dict):
                raise ContractError("Workload labels required")
            workloads[node_id] = labels
            if kind == "StatefulSet":
                requirements.append("state-and-volume-migration-review")
                portability = Portability.UNKNOWN
            for container in template_spec.get("containers", []):
                for env in container.get("env", []):
                    if "value" in env:
                        requirements.append("plaintext-environment-review")
                    if "valueFrom" in env:
                        requirements.append(
                            "external-config-and-secret-reference-review"
                        )
                if container.get("envFrom"):
                    requirements.append("external-config-and-secret-reference-review")
            for volume in template_spec.get("volumes", []):
                if "persistentVolumeClaim" in volume:
                    claim_refs.append(
                        (node_id, volume["persistentVolumeClaim"].get("claimName"))
                    )
                if "secret" in volume:
                    requirements.append("secret-mount-review")
        elif kind == "PersistentVolumeClaim":
            resource_kind = ResourceKind.STORAGE
            portability = Portability.UNKNOWN
            requirements.extend(
                ["storage-driver-and-data-copy", "backup-and-restore-verification"]
            )
            claims[name] = node_id
        elif kind == "Service":
            resource_kind = ResourceKind.EDGE
            selector = spec.get("selector", {})
            if not isinstance(selector, dict):
                raise ContractError("Service selector required")
            services.append((node_id, selector))
            requirements.extend(
                ["service-endpoint-readback", "stable-ingress-and-session-review"]
            )
            if spec.get("type") == "ExternalName":
                requirements.append("external-dns-dependency-review")
                portability = Portability.UNKNOWN
        resources.append(
            SystemResource(
                node_id,
                name,
                ResourceScope(
                    tenant_id,
                    application_id,
                    environment_id,
                    "k8s://" + namespace + "/" + kind + "/" + name + "#" + uid,
                ),
                resource_kind,
                "kubernetes",
                location,
                revision,
                portability,
                tuple(sorted(set(requirements))),
            )
        )
    for source, selector in services:
        if selector:
            for target, labels in workloads.items():
                if all(labels.get(key) == value for key, value in selector.items()):
                    relations.append(
                        SystemRelation(source, target, RelationKind.USES, True)
                    )
    for source, claim in claim_refs:
        if claim not in claims:
            raise ContractError("PVC dependency omitted from inventory")
        relation = SystemRelation(source, claims[claim], RelationKind.USES, True)
        if relation not in relations:
            relations.append(relation)
    return SystemGraph(
        tenant_id,
        application_id,
        1,
        "kubernetes_snapshot",
        observed_at,
        valid_until,
        tuple(resources),
        tuple(relations),
    )


def snapshot_graph(document, **scope):
    """Fail closed for malformed nested snapshots; never emit raw input in errors."""
    try:
        return _snapshot_graph(document, **scope)
    except (AttributeError, TypeError, KeyError, ValueError) as exc:
        raise ContractError("Invalid or incomplete scoped Kubernetes snapshot") from exc
