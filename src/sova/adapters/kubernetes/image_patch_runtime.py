"""Read-only Deployment rollout and runtime image identity collection.

Use a separately scoped reader credential for independent verification. Ready
Pods are not functional, security-fix, data-safety or source-provenance proof.
The collector emits no PASS authorization and never changes a workload.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import re

from sova.adapters.kubernetes.image_patch import KubernetesImagePatchAdapter, MARKER
from sova.domain.contracts import ContractError, ResourceScope, canonical_json, utc
from sova_security.domain.assessment import Document


@dataclass(frozen=True, slots=True)
class KubernetesRuntimeSnapshot(Document):
    scope: ResourceScope
    registration_digest: str
    command_digest: str
    image_digest: str
    resource_version: str
    rollout_ready: bool
    reasons: tuple[str, ...]
    pod_set_digest: str
    observed_image_digests: tuple[str, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        from sova.domain.contracts import digest, identifier

        if (
            not isinstance(self.scope, ResourceScope)
            or type(self.rollout_ready) is not bool
        ):
            raise ContractError("Typed runtime snapshot required")
        for key in (
            "registration_digest",
            "command_digest",
            "image_digest",
            "pod_set_digest",
        ):
            digest(getattr(self, key))
        identifier(self.resource_version)
        if (
            type(self.observed_image_digests) is not tuple
            or len(self.observed_image_digests) > 10
        ):
            raise ContractError("Bounded runtime image observations required")
        for value in self.observed_image_digests:
            digest(value)
        known = {
            "desired-spec-unconfirmed",
            "controller-not-observed",
            "rollout-incomplete",
            "rollout-failed",
            "pod-set-incomplete",
            "pod-owner-unconfirmed",
            "pod-not-ready",
            "runtime-image-unverified",
        }
        if (
            type(self.reasons) is not tuple
            or len(self.reasons) > 8
            or len(set(self.reasons)) != len(self.reasons)
            or not set(self.reasons) <= known
            or self.rollout_ready != (not self.reasons)
        ):
            raise ContractError("Consistent fixed runtime reasons required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if (
            not self.observed_at
            < self.valid_until
            <= self.observed_at + timedelta(seconds=30)
        ):
            raise ContractError("Bounded runtime observation window required")


def _items(value, kind):
    if (
        type(value) is not dict
        or value.get("kind") != kind + "List"
        or type(value.get("metadata")) is not dict
        or value["metadata"].get("continue")
        or type(value.get("items")) is not list
        or len(value["items"]) > 32
        or any(type(v) is not dict for v in value["items"])
    ):
        raise ContractError("Complete bounded rollout child list required")
    return value["items"]


def _controller(value):
    meta = value.get("metadata")
    if type(meta) is not dict or type(meta.get("uid")) is not str:
        raise ContractError("Typed rollout child metadata required")
    refs = meta.get("ownerReferences", [])
    if (
        type(refs) is not list
        or len(refs) > 8
        or any(type(r) is not dict for r in refs)
    ):
        raise ContractError("Bounded rollout owner references required")
    controllers = [r for r in refs if r.get("controller") is True]
    if len(controllers) != 1:
        return None
    return controllers[0]


class KubernetesRuntimeCollector:
    def __init__(
        self,
        registration,
        *,
        transport,
        current_registration,
        authenticate_registration,
        authorize,
        clock,
    ):
        self.reader = KubernetesImagePatchAdapter(
            registration,
            transport=transport,
            current_registration=current_registration,
            authenticate_registration=authenticate_registration,
            authorize=authorize,
            clock=clock,
        )
        self.clock = clock

    def collect(self, command):
        reader = self.reader
        reg = reader.registration
        started = utc(self.clock())
        reader._authority(command, "security:read-image-patch")
        deployment = reader._deployment(command)
        replica_sets = _items(reader.transport.children("replicasets"), "ReplicaSet")
        pods = _items(reader.transport.children("pods"), "Pod")
        reasons = set()
        meta, spec, status = (
            deployment["metadata"],
            deployment["spec"],
            deployment.get("status", {}),
        )
        if type(status) is not dict:
            raise ContractError("Typed rollout status required")
        if (
            meta.get("annotations", {}).get(MARKER) != command.fingerprint
            or spec["template"]["spec"]["containers"][0]["image"] != reg.image
        ):
            reasons.add("desired-spec-unconfirmed")
        generation, observed = meta.get("generation"), status.get("observedGeneration")
        if (
            type(generation) is not int
            or type(observed) is not int
            or observed < generation
        ):
            reasons.add("controller-not-observed")
        for key in (
            "replicas",
            "updatedReplicas",
            "readyReplicas",
            "availableReplicas",
        ):
            if type(status.get(key)) is not int or status[key] != reg.replicas:
                reasons.add("rollout-incomplete")
        unavailable = status.get("unavailableReplicas", 0)
        if type(unavailable) is not int or unavailable != 0:
            reasons.add("rollout-incomplete")
        conditions = status.get("conditions", [])
        if (
            type(conditions) is not list
            or len(conditions) > 16
            or any(type(c) is not dict for c in conditions)
        ):
            raise ContractError("Bounded rollout conditions required")
        if any(c.get("reason") == "ProgressDeadlineExceeded" for c in conditions):
            reasons.add("rollout-failed")
        expected_labels = {
            "app.kubernetes.io/name": reg.deployment_name,
            "app.kubernetes.io/part-of": reg.scope.application_id,
        }

        def identity(value):
            m = value.get("metadata", {})
            if (
                type(m) is not dict
                or m.get("namespace") != reg.reader.namespace
                or type(m.get("labels")) is not dict
                or any(
                    m.get("labels", {}).get(k) != v for k, v in expected_labels.items()
                )
            ):
                raise ContractError("Rollout child is outside registered selector")

        matching_rs = set()
        for rs in replica_sets:
            identity(rs)
            owner = _controller(rs)
            rs_spec = rs.get("spec", {})
            rs_template = rs_spec.get("template", {}) if type(rs_spec) is dict else {}
            rs_pod = rs_template.get("spec", {}) if type(rs_template) is dict else {}
            rs_containers = rs_pod.get("containers", []) if type(rs_pod) is dict else []
            if (
                type(rs_containers) is list
                and len(rs_containers) == 1
                and type(rs_containers[0]) is dict
                and rs_containers[0].get("image") == reg.image
                and rs_containers[0].get("name") == reg.container_name
                and owner is not None
                and owner.get("kind") == "Deployment"
                and owner.get("uid") == reg.deployment_uid
                and owner.get("name") == reg.deployment_name
            ):
                matching_rs.add(rs["metadata"]["uid"])
        observed_images, pod_ids = [], []
        if len(pods) != reg.replicas:
            reasons.add("pod-set-incomplete")
        seen = set()
        for pod in pods:
            identity(pod)
            owner = _controller(pod)
            m = pod["metadata"]
            if m["uid"] in seen:
                raise ContractError("Duplicate runtime Pod identity")
            seen.add(m["uid"])
            pod_ids.append(m["uid"])
            if (
                owner is None
                or owner.get("kind") != "ReplicaSet"
                or owner.get("uid") not in matching_rs
            ):
                reasons.add("pod-owner-unconfirmed")
            pod_spec, ps = pod.get("spec", {}), pod.get("status", {})
            if type(pod_spec) is not dict or type(ps) is not dict:
                raise ContractError("Typed runtime Pod required")
            pcs = pod_spec.get("containers")
            states = ps.get("containerStatuses")
            pc = ps.get("conditions", [])
            if (
                type(pc) is not list
                or len(pc) > 32
                or any(type(c) is not dict for c in pc)
            ):
                raise ContractError("Bounded Pod conditions required")
            if (
                ps.get("phase") != "Running"
                or m.get("deletionTimestamp")
                or not any(
                    c.get("type") == "Ready" and c.get("status") == "True" for c in pc
                )
            ):
                reasons.add("pod-not-ready")
            if (
                type(pcs) is not list
                or len(pcs) != 1
                or type(pcs[0]) is not dict
                or pcs[0].get("name") != reg.container_name
                or pcs[0].get("image") != reg.image
                or pod_spec.get("initContainers")
                or pod_spec.get("ephemeralContainers")
            ):
                reasons.add("runtime-image-unverified")
                continue
            if (
                type(states) is not list
                or len(states) != 1
                or type(states[0]) is not dict
            ):
                reasons.add("runtime-image-unverified")
                continue
            cs = states[0]
            if (
                cs.get("name") != reg.container_name
                or cs.get("ready") is not True
                or type(cs.get("state")) is not dict
                or type(cs["state"].get("running")) is not dict
            ):
                reasons.add("pod-not-ready")
            image_id = cs.get("imageID")
            image_match = (
                re.fullmatch(
                    r"(?:docker-pullable://)?"
                    + re.escape(reg.repository)
                    + r"@sha256:([0-9a-f]{64})",
                    image_id,
                )
                if type(image_id) is str
                else None
            )
            if image_match is None or image_match.group(1) != reg.artifact.image_digest:
                reasons.add("runtime-image-unverified")
            else:
                observed_images.append(image_match.group(1))
        reader._authority(command, "security:read-image-patch")
        # Re-read the registered object after observing its children. A recreated
        # or concurrently changed Deployment cannot borrow the earlier pod proof.
        final_deployment = reader._deployment(command)
        if final_deployment != deployment:
            raise ContractError("Deployment changed during runtime collection")
        final = utc(self.clock())
        if final < started:
            raise ContractError("Runtime collection clock moved backwards")
        return KubernetesRuntimeSnapshot(
            reg.scope,
            reg.fingerprint,
            command.fingerprint,
            reg.artifact.image_digest,
            meta["resourceVersion"],
            not reasons,
            tuple(sorted(reasons)),
            hashlib.sha256(
                canonical_json({"pod_uids": sorted(pod_ids)}).encode()
            ).hexdigest(),
            tuple(sorted(observed_images)),
            final,
            min(reg.read_until, final + timedelta(seconds=30)),
        )
