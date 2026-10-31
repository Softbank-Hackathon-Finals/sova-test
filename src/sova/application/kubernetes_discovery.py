"""All-or-nothing, scoped, bounded collection. No claim of atomic cross-kind state."""

from datetime import timedelta
from dataclasses import replace
import hashlib
import time

from sova.adapters.kubernetes.inventory import snapshot_graph
from sova.domain.contracts import ContractError, canonical_json
from sova.domain.system_graph import SystemGraph
from sova.ports.kubernetes import KubernetesReadTransport

COLLECTIONS = (
    ("Deployment", "apps/v1", "deployments"),
    ("StatefulSet", "apps/v1", "statefulsets"),
    ("Service", "v1", "services"),
    ("PersistentVolumeClaim", "v1", "persistentvolumeclaims"),
)


class KubernetesDiscovery:
    def __init__(
        self,
        registration,
        transport: KubernetesReadTransport,
        *,
        authorize,
        clock,
        monotonic=time.monotonic,
        projection=None,
    ):
        if transport.registration_digest != registration.fingerprint:
            raise ContractError("Transport registration mismatch")
        self.registration = registration
        self.transport = transport
        self.authorize = authorize
        self.clock = clock
        self.monotonic = monotonic
        self.projection = projection

    def inspect(self, *, actor):
        reg = self.registration
        start = self.clock()
        deadline = self.monotonic() + 30

        def get(path, query):
            reg.require_current(self.clock())
            # Caller is supplied by a trusted boundary; authorize must recheck it.
            # A matching actor string alone is never considered authentication.
            self.authorize(actor, reg, "inventory:read")
            left = deadline - self.monotonic()
            if left <= 0:
                raise ContractError("Inventory collection deadline exceeded")
            result = self.transport.get(path, query, timeout=min(left, 5))
            if self.monotonic() > deadline:
                raise ContractError("Inventory collection deadline exceeded")
            return result

        namespace_path = "/api/v1/namespaces/" + reg.namespace

        def check_namespace():
            data = get(namespace_path, {})
            if not isinstance(data, dict) or not isinstance(data.get("metadata"), dict):
                raise ContractError("Invalid namespace response")
            if (
                not isinstance(data, dict)
                or data.get("kind") != "Namespace"
                or data.get("metadata", {}).get("uid") != reg.namespace_uid
                or data.get("metadata", {}).get("name") != reg.namespace
            ):
                raise ContractError("Namespace identity changed")

        check_namespace()
        items = []
        versions = {}
        for kind, api, plural in COLLECTIONS:
            base = "/api/" + api if api == "v1" else "/apis/" + api
            path = base + "/namespaces/" + reg.namespace + "/" + plural
            continuation = ""
            seen = set()
            version = None
            for _ in range(8):
                query = {
                    "labelSelector": "app.kubernetes.io/part-of=" + reg.application_id,
                    "limit": "32",
                }
                if continuation:
                    query["continue"] = continuation
                data = get(path, query)
                if (
                    not isinstance(data, dict)
                    or data.get("kind") != kind + "List"
                    or not isinstance(data.get("items"), list)
                    or not isinstance(data.get("metadata"), dict)
                ):
                    raise ContractError("Invalid collection response")
                rv = data["metadata"].get("resourceVersion")
                token = data["metadata"].get("continue", "")
                if (
                    not isinstance(rv, str)
                    or not rv
                    or len(rv) > 256
                    or (version is not None and version != rv)
                ):
                    raise ContractError("Collection version changed during pagination")
                version = rv
                if not isinstance(token, str) or len(token) > 4096 or token in seen:
                    raise ContractError("Invalid or repeated continuation")
                for item in data["items"]:
                    if not isinstance(item, dict) or item.get("kind", kind) != kind:
                        raise ContractError("Unexpected collection item kind")
                    # Kubernetes typed lists normally omit GVK on each item.
                    # Derive only absent GVK from the validated collection route.
                    if item.get("apiVersion", api) != api:
                        raise ContractError("Unexpected collection item API version")
                    items.append({**item, "kind": kind, "apiVersion": api})
                if len(items) > 128:
                    raise ContractError("Inventory resource limit exceeded")
                if not token:
                    break
                seen.add(token)
                continuation = token
            else:
                raise ContractError("Inventory pagination limit exceeded")
            versions[plural] = version
        check_namespace()
        reg.require_current(self.clock())
        self.authorize(actor, reg, "inventory:read")
        end = self.clock()
        if end < start:
            raise ContractError("Inventory clock moved backwards")
        graph = snapshot_graph(
            {"kind": "List", "items": items},
            tenant_id=reg.tenant_id,
            application_id=reg.application_id,
            environment_id=reg.environment_id,
            namespace=reg.namespace,
            location=reg.location,
            observed_at=start,
            valid_until=min(start + timedelta(minutes=5), reg.valid_until),
        )
        graph = SystemGraph(
            graph.tenant_id,
            graph.application_id,
            reg.revision,
            "kubernetes_api",
            graph.observed_at,
            graph.valid_until,
            tuple(
                replace(
                    resource,
                    requirements=tuple(
                        "api-configuration-observed-not-runtime"
                        if item == "live-collection-not-verified"
                        else item
                        for item in resource.requirements
                    ),
                )
                for resource in graph.resources
            ),
            graph.relations,
        )
        graph.require_current(end)
        proof = {
            "registration_digest": reg.fingerprint,
            "namespace_uid": reg.namespace_uid,
            "collection_versions": versions,
            "started_at": start.isoformat(),
            "completed_at": end.isoformat(),
            "graph_digest": graph.fingerprint,
            "observation": "scoped-api-declarations; not atomic across kinds; not traffic or readiness verification",
        }
        result = {
            "graph": graph.document,
            "collection": proof,
            "collection_digest": hashlib.sha256(
                canonical_json(proof).encode()
            ).hexdigest(),
            "executable": False,
        }
        if self.projection is not None:
            result["projection"] = self.projection(tuple(items), graph)
            canonical_json(result["projection"], limit=524288)
        return result
