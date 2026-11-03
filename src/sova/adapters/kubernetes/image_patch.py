"""Exact Deployment image replacement through the registered Kubernetes API.

No arbitrary manifest, shell, kubeconfig exec, tag or fallback target. A persisted
spec is only an applied effect; runtime readiness and independent postflight are
separate observations. The host retains approvals, leases and incident holds.
"""

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
import re
from urllib.parse import urlsplit

from sova.adapters.kubernetes.https import KubernetesHTTPS
from sova.domain.discovery import KubernetesReadRegistration
from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    utc,
)
from sova.domain.contracts import EffectCommand, EffectObservation, EffectStatus
from sova_security.contracts.authority import require_accept, require_authentication
from sova_security.domain.remediation import TestedArtifact
from sova_security.domain.patch_execution import ACTION

ADAPTER_ID = "sova-kubernetes-image-patch-v1"
MARKER = "sova.security/patch-command"


def _name(value):
    if type(value) is not str or not re.fullmatch(
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value
    ):
        raise ContractError("Registered Kubernetes DNS label required")
    return value


def _uid(value):
    if type(value) is not str or not re.fullmatch(r"[a-zA-Z0-9-]{1,128}", value):
        raise ContractError("Explicit Kubernetes UID required")
    return value


def _repository(value):
    if type(value) is not str or not 1 <= len(value) <= 512 or value != value.lower():
        raise ContractError("Fixed OCI repository required")
    try:
        parsed = urlsplit("https://" + value)
        if (
            not parsed.hostname
            or not re.fullmatch(r"[a-z0-9.-]+", parsed.hostname)
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/")
            or ":" in parsed.path
            or any(
                not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", p) or p in {".", ".."}
                for p in parsed.path[1:].split("/")
            )
            or not 1 <= (443 if parsed.port is None else parsed.port) <= 65535
            or parsed.netloc + parsed.path != value
        ):
            raise ValueError()
    except ValueError as exc:
        raise ContractError("Canonical OCI repository required") from exc
    return value


def deployment_configuration(deployment):
    """Hash exact admitted Deployment settings except image and owned metadata."""
    if type(deployment) is not dict or type(deployment.get("spec")) is not dict:
        raise ContractError("Deployment configuration object required")
    metadata = deployment.get("metadata")
    if type(metadata) is not dict:
        raise ContractError("Deployment metadata required")
    labels, annotations = metadata.get("labels"), metadata.get("annotations", {})
    if type(labels) is not dict or type(annotations) is not dict:
        raise ContractError("Deployment labels and annotations required")
    spec = deepcopy(deployment["spec"])
    template = spec.get("template")
    pod = template.get("spec") if type(template) is dict else None
    containers = pod.get("containers") if type(pod) is dict else None
    if (
        type(containers) is not list
        or len(containers) != 1
        or type(containers[0]) is not dict
        or pod.get("initContainers")
        or pod.get("ephemeralContainers")
    ):
        raise ContractError(
            "Image patch profile requires one container without init/ephemeral containers"
        )
    if type(containers[0].get("image")) is not str:
        raise ContractError("Explicit base container image required")
    containers[0]["image"] = "<admitted-image>"
    value = {
        "spec": spec,
        "labels": labels,
        "annotations": {
            k: v
            for k, v in annotations.items()
            if k not in {MARKER, "deployment.kubernetes.io/revision"}
        },
    }
    return hashlib.sha256(canonical_json(value, limit=65536).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class KubernetesImagePatchRegistration:
    reader: KubernetesReadRegistration
    scope: ResourceScope
    deployment_name: str
    deployment_uid: str
    container_name: str
    repository: str
    base_image_digest: str
    base_configuration_digest: str
    resource_version: str
    replicas: int
    artifact: TestedArtifact
    request_digest: str
    receipt_digest: str
    proposal_digest: str
    registered_at: datetime
    valid_until: datetime
    base_command_digest: str | None = None
    read_until: datetime | None = None

    def __post_init__(self):
        if (
            not isinstance(self.reader, KubernetesReadRegistration)
            or not isinstance(self.scope, ResourceScope)
            or not isinstance(self.artifact, TestedArtifact)
        ):
            raise ContractError("Typed image patch registration required")
        _name(self.deployment_name)
        _name(self.container_name)
        _uid(self.deployment_uid)
        _repository(self.repository)
        if self.base_command_digest is not None:
            digest(self.base_command_digest)
        if (
            (
                self.reader.tenant_id,
                self.reader.application_id,
                self.reader.environment_id,
            )
            != (
                self.scope.tenant_id,
                self.scope.application_id,
                self.scope.environment_id,
            )
            or self.scope.resource_id
            != f"k8s://{self.reader.namespace}/Deployment/{self.deployment_name}#{self.deployment_uid}"
            or self.artifact.scope != self.scope
        ):
            raise ContractError("Image patch resource registration crosses scope")
        for key in (
            "base_image_digest",
            "base_configuration_digest",
            "request_digest",
            "receipt_digest",
            "proposal_digest",
        ):
            digest(getattr(self, key))
        if (
            self.artifact.configuration_digest != self.base_configuration_digest
            or self.artifact.image_digest == self.base_image_digest
        ):
            raise ContractError(
                "This image-only profile cannot change configuration or reuse the base image"
            )
        if type(self.resource_version) is not str or not re.fullmatch(
            r"[A-Za-z0-9._:-]{1,128}", self.resource_version
        ):
            raise ContractError("Exact registered Kubernetes resourceVersion required")
        if type(self.replicas) is not int or not 1 <= self.replicas <= 10:
            raise ContractError("Bounded positive replica registration required")
        object.__setattr__(self, "registered_at", utc(self.registered_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if (
            not self.reader.registered_at
            <= self.registered_at
            < self.valid_until
            <= min(self.reader.valid_until, self.registered_at + timedelta(minutes=30))
        ):
            raise ContractError("Bounded image patch registration required")

        read_until = (
            self.valid_until if self.read_until is None else utc(self.read_until)
        )
        if (
            not self.valid_until
            <= read_until
            <= min(self.reader.valid_until, self.registered_at + timedelta(hours=24))
        ):
            raise ContractError(
                "Bounded read-only reconciliation registration required"
            )
        object.__setattr__(self, "read_until", read_until)

    @property
    def image(self):
        return self.repository + "@sha256:" + self.artifact.image_digest

    @property
    def document(self):
        from dataclasses import asdict

        return {
            "schema_version": 1,
            "reader_digest": self.reader.fingerprint,
            "scope": asdict(self.scope),
            "deployment_name": self.deployment_name,
            "deployment_uid": self.deployment_uid,
            "container_name": self.container_name,
            "repository": self.repository,
            "base_image_digest": self.base_image_digest,
            "base_configuration_digest": self.base_configuration_digest,
            "resource_version": self.resource_version,
            "replicas": self.replicas,
            "artifact": self.artifact.document,
            "request_digest": self.request_digest,
            "receipt_digest": self.receipt_digest,
            "proposal_digest": self.proposal_digest,
            "registered_at": self.registered_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "base_command_digest": self.base_command_digest,
            "read_until": self.read_until.isoformat(),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()

    def require_current(self, now, *, mutation=False):
        self.reader.require_current(now)
        deadline = self.valid_until if mutation else self.read_until
        if not self.registered_at <= utc(now) < deadline:
            raise ContractError("Image patch registration expired/future")


class KubernetesImagePatchHTTPS(KubernetesHTTPS):
    def __init__(self, registration, *, ca_pem, token_provider):
        if not isinstance(registration, KubernetesImagePatchRegistration):
            raise ContractError("Typed registered image transport required")
        super().__init__(
            registration.reader, ca_pem=ca_pem, token_provider=token_provider
        )
        self.patch_registration = registration

    @property
    def registration_digest(self):
        return self.patch_registration.fingerprint

    @property
    def deployment_path(self):
        r = self.patch_registration
        return f"/apis/apps/v1/namespaces/{r.reader.namespace}/deployments/{r.deployment_name}"

    def namespace(self):
        return self._request(
            "GET", "/api/v1/namespaces/" + self.registration.namespace, {}, timeout=3
        )

    def deployment(self):
        return self._request("GET", self.deployment_path, {}, timeout=3)

    def children(self, kind):
        if kind not in {"pods", "replicasets"}:
            raise ContractError("Only registered rollout children can be read")
        r = self.patch_registration
        path = (
            "/api/v1" if kind == "pods" else "/apis/apps/v1"
        ) + f"/namespaces/{r.reader.namespace}/{kind}"
        return self._request(
            "GET",
            path,
            {
                "labelSelector": f"app.kubernetes.io/name={r.deployment_name},app.kubernetes.io/part-of={r.scope.application_id}",
                "limit": "32",
            },
            timeout=3,
        )

    def patch_image(self, operations):
        r = self.patch_registration
        expected = [
            ("test", "/metadata/uid"),
            ("test", "/metadata/resourceVersion"),
            ("test", "/spec/template"),
            ("add", "/metadata/annotations"),
            ("replace", "/spec/template/spec/containers/0/image"),
        ]
        if (
            type(operations) is not list
            or len(operations) != len(expected)
            or any(
                type(op) is not dict
                or set(op) != {"op", "path", "value"}
                or (op["op"], op["path"]) != key
                for op, key in zip(operations, expected, strict=True)
            )
        ):
            raise ContractError("Only fixed conditional image patch operations allowed")
        if (
            operations[0]["value"] != r.deployment_uid
            or operations[1]["value"] != r.resource_version
            or operations[-1]["value"] != r.image
        ):
            raise ContractError("Image mutation differs from registration")
        annotations = operations[3]["value"]
        if type(annotations) is not dict or MARKER not in annotations:
            raise ContractError("Exact command marker required")
        digest(annotations[MARKER])
        canonical_json({"patch": operations}, limit=65536)
        return self._request(
            "PATCH",
            self.deployment_path,
            {},
            timeout=5,
            body=json.dumps(
                operations,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode(),
        )


class KubernetesImagePatchAdapter:
    adapter_id = ADAPTER_ID

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
        if (
            not isinstance(registration, KubernetesImagePatchRegistration)
            or transport.registration_digest != registration.fingerprint
        ):
            raise ContractError("Registered image patch transport differs")
        self.registration, self.transport = registration, transport
        self.current_registration, self.authenticate_registration = (
            current_registration,
            authenticate_registration,
        )
        self.authorize, self.clock = authorize, clock

    def _authority(self, command, action):
        self.validate(command)
        require_authentication(self.authenticate_registration, self.registration)
        require_accept(self.authorize, command, action)
        if self.current_registration() != self.registration:
            raise ContractError("Image patch registration changed/revoked")
        self.registration.require_current(
            self.clock(), mutation=action == "security:apply-image-patch"
        )
        if (
            action == "security:apply-image-patch"
            and utc(self.clock()) >= command.expires_at
        ):
            raise ContractError("Image mutation command expired")

    def validate(self, command):
        r = self.registration
        if (
            not isinstance(command, EffectCommand)
            or command.adapter_id != self.adapter_id
            or command.action != ACTION
            or command.scope != r.scope
            or command.expected_revision != r.resource_version
        ):
            raise ContractError("Image patch command differs from registered resource")
        expected = {
            "request_digest": r.request_digest,
            "receipt_digest": r.receipt_digest,
            "proposal_digest": r.proposal_digest,
            "artifact": r.artifact.document,
        }
        if command.parameters != expected:
            raise ContractError(
                "Image patch artifact differs from approved registration"
            )
        r.require_current(self.clock())

    def _deployment(self, command):
        namespace = self.transport.namespace()
        r = self.registration
        if (
            type(namespace) is not dict
            or namespace.get("kind") != "Namespace"
            or type(namespace.get("metadata")) is not dict
            or namespace.get("metadata", {}).get("name") != r.reader.namespace
            or namespace.get("metadata", {}).get("uid") != r.reader.namespace_uid
        ):
            raise ContractError("Registered namespace was recreated")
        value = self.transport.deployment()
        if type(value) is not dict or value.get("kind") != "Deployment":
            raise ContractError("Registered Deployment required")
        m = value.get("metadata", {})
        if type(m) is not dict or type(value.get("spec")) is not dict:
            raise ContractError("Typed registered Deployment metadata/spec required")
        configuration = deployment_configuration(value)
        if (m.get("name"), m.get("namespace"), m.get("uid")) != (
            r.deployment_name,
            r.reader.namespace,
            r.deployment_uid,
        ) or m.get("deletionTimestamp"):
            raise ContractError("Registered Deployment identity changed")
        labels = {
            "app.kubernetes.io/name": r.deployment_name,
            "app.kubernetes.io/part-of": r.scope.application_id,
        }
        spec = value["spec"]
        if (
            spec.get("selector") != {"matchLabels": labels}
            or any(
                spec.get("template", {}).get("metadata", {}).get("labels", {}).get(k)
                != v
                for k, v in labels.items()
            )
            or any(m.get("labels", {}).get(k) != v for k, v in labels.items())
        ):
            raise ContractError("Exact registered workload selectors required")
        if (
            spec.get("replicas") != r.replicas
            or type(spec.get("replicas")) is not int
            or configuration != r.base_configuration_digest
            or spec["template"]["spec"]["containers"][0].get("name") != r.container_name
        ):
            raise ContractError("Admitted image-only configuration drifted")
        self._authority(command, "security:read-image-patch")
        return value

    def apply(self, command):
        self._authority(command, "security:apply-image-patch")
        value = self._deployment(command)
        r = self.registration
        if (
            value["metadata"].get("resourceVersion") != r.resource_version
            or value["spec"]["template"]["spec"]["containers"][0]["image"]
            != r.repository + "@sha256:" + r.base_image_digest
        ):
            raise ContractError("Image patch base changed before conditional mutation")
        annotations = dict(value["metadata"].get("annotations", {}))
        if annotations.get(MARKER) != r.base_command_digest:
            raise ContractError(
                "Existing patch marker differs from registered predecessor"
            )
        annotations[MARKER] = command.fingerprint
        operations = [
            {"op": "test", "path": "/metadata/uid", "value": r.deployment_uid},
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": r.resource_version,
            },
            {
                "op": "test",
                "path": "/spec/template",
                "value": value["spec"]["template"],
            },
            {"op": "add", "path": "/metadata/annotations", "value": annotations},
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/image",
                "value": r.image,
            },
        ]
        self._authority(command, "security:apply-image-patch")
        self.transport.patch_image(
            operations
        )  # Exactly one conditional request; no retry.

    def readback(self, command, now):
        self._authority(command, "security:read-image-patch")
        value = self._deployment(command)
        r = self.registration
        marker = value["metadata"].get("annotations", {}).get(MARKER)
        image = value["spec"]["template"]["spec"]["containers"][0]["image"]
        status = (
            EffectStatus.APPLIED
            if marker == command.fingerprint and image == r.image
            else EffectStatus.UNKNOWN
        )
        # A matching spec is not rollout/health proof; postflight must check those.
        return EffectObservation(
            command.scope,
            command.fingerprint,
            status,
            utc(now),
            canonical_json(
                {
                    "basis": "kubernetes-spec-readback",
                    "resource_version": value["metadata"]["resourceVersion"],
                    "image_digest": r.artifact.image_digest
                    if status == EffectStatus.APPLIED
                    else None,
                    "runtime_verified": False,
                }
            ),
        )
