"""Environment-neutral registered graph; registration is not verified discovery.

Consumer -> dependency edges may contain cycles. Movement groups are SCCs,
not a claim that every member must physically move together under all policies.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    identifier,
    utc,
)


class ResourceKind(StrEnum):
    SERVICE = "service"
    DATABASE = "database"
    STORAGE = "storage"
    WORKER = "worker"
    QUEUE = "queue"
    IDENTITY = "identity"
    SECRET = "secret"
    AI = "ai"
    OBSERVABILITY = "observability"
    EDGE = "edge"


class Portability(StrEnum):
    PORTABLE = "portable"
    CONFIGURATION = "configuration_change"
    TRANSFORMATION = "source_transformation"
    PROVIDER_BOUND = "provider_bound"
    UNKNOWN = "unknown"


class RelationKind(StrEnum):
    CALLS = "calls"
    READS = "reads"
    WRITES = "writes"
    USES = "uses"
    REPLICATES = "replicates"


@dataclass(frozen=True, slots=True)
class SystemResource:
    node_id: str
    name: str
    scope: ResourceScope
    kind: ResourceKind
    backend: str
    location: str
    resource_revision: str
    portability: Portability
    requirements: tuple[str, ...] = ()

    def __post_init__(self):
        for field in ("node_id", "name", "backend", "location", "resource_revision"):
            identifier(
                getattr(self, field),
                field,
                limit=2048 if field == "resource_revision" else 256,
            )
        if (
            not isinstance(self.scope, ResourceScope)
            or not isinstance(self.kind, ResourceKind)
            or not isinstance(self.portability, Portability)
        ):
            raise ContractError("Typed resource scope/kind/portability required")
        if type(self.requirements) is not tuple or len(self.requirements) > 32:
            raise ContractError("Bounded unique immutable requirements required")
        for requirement in self.requirements:
            identifier(requirement, "requirement")
        if len(set(self.requirements)) != len(self.requirements):
            raise ContractError("Duplicate requirements")

    @property
    def document(self):
        return {
            "id": self.node_id,
            "name": self.name,
            "scope": {
                key: getattr(self.scope, key)
                for key in (
                    "tenant_id",
                    "application_id",
                    "environment_id",
                    "resource_id",
                )
            },
            "kind": str(self.kind),
            "backend": self.backend,
            "location": self.location,
            "resource_revision": self.resource_revision,
            "portability": str(self.portability),
            "requirements": list(self.requirements),
        }


@dataclass(frozen=True, slots=True)
class SystemRelation:
    source: str
    target: str
    kind: RelationKind
    required: bool

    def __post_init__(self):
        identifier(self.source, "relation source")
        identifier(self.target, "relation target")
        if not isinstance(self.kind, RelationKind) or type(self.required) is not bool:
            raise ContractError("Typed relation kind and required flag needed")

    @property
    def document(self):
        return {
            "source": self.source,
            "target": self.target,
            "kind": str(self.kind),
            "required": self.required,
        }


@dataclass(frozen=True, slots=True)
class SystemGraph:
    tenant_id: str
    application_id: str
    revision: int
    origin: str
    observed_at: datetime
    valid_until: datetime
    resources: tuple[SystemResource, ...]
    relations: tuple[SystemRelation, ...]

    def __post_init__(self):
        identifier(self.tenant_id, "tenant")
        identifier(self.application_id, "application")
        if (
            type(self.revision) is not int
            or self.revision < 1
            or self.origin
            not in {
                "registration",
                "kubernetes_snapshot",
                "kubernetes_api",
                "local_demo",
            }
        ):
            raise ContractError("Valid graph revision and origin required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Graph validity must be positive")
        if (
            type(self.resources) is not tuple
            or not 1 <= len(self.resources) <= 128
            or type(self.relations) is not tuple
            or len(self.relations) > 512
        ):
            raise ContractError("Bounded immutable graph required")
        ids = set()
        scopes = set()
        for resource in self.resources:
            if not isinstance(resource, SystemResource):
                raise ContractError("Typed graph resource required")
            if (resource.scope.tenant_id, resource.scope.application_id) != (
                self.tenant_id,
                self.application_id,
            ):
                raise ContractError("Graph crosses tenant/application")
            if resource.node_id in ids or resource.scope in scopes:
                raise ContractError("Duplicate node/resource scope")
            ids.add(resource.node_id)
            scopes.add(resource.scope)
        edges = set()
        for relation in self.relations:
            if not isinstance(relation, SystemRelation):
                raise ContractError("Typed graph relation required")
            if relation.source not in ids or relation.target not in ids:
                raise ContractError("Unregistered relation endpoint")
            key = (relation.source, relation.target, relation.kind)
            if key in edges:
                raise ContractError("Duplicate graph relation")
            edges.add(key)
        object.__setattr__(
            self, "resources", tuple(sorted(self.resources, key=lambda r: r.node_id))
        )
        object.__setattr__(
            self,
            "relations",
            tuple(
                sorted(self.relations, key=lambda r: (r.source, r.target, str(r.kind)))
            ),
        )
        canonical_json(self.document, limit=262144)

    @property
    def document(self):
        return {
            "schema_version": 1,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "revision": self.revision,
            "origin": self.origin,
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "resources": [
                r.document for r in sorted(self.resources, key=lambda r: r.node_id)
            ],
            "relations": [
                r.document
                for r in sorted(
                    self.relations, key=lambda r: (r.source, r.target, str(r.kind))
                )
            ],
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=262144).encode()
        ).hexdigest()

    def require_current(self, now):
        if not self.observed_at <= utc(now) < self.valid_until:
            raise ContractError("Graph expired or from the future")

    def impact_candidates(self, failed_nodes):
        """Potential consumers only. This does NOT mark observed failures/attacks."""
        if not isinstance(failed_nodes, (set, frozenset)) or not failed_nodes <= set(
            r.node_id for r in self.resources
        ):
            raise ContractError("Registered failed node set required")
        affected = set(failed_nodes)
        changed = True
        while changed:
            changed = False
            for relation in self.relations:
                if relation.target in affected and relation.source not in affected:
                    affected.add(relation.source)
                    changed = True
        return tuple(sorted(affected - set(failed_nodes)))

    def movement_groups(self):
        """Stable strongly connected dependency groups, dependencies first."""
        adjacency = {r.node_id: set() for r in self.resources}
        for edge in self.relations:
            adjacency[edge.source].add(edge.target)
        index = 0
        indices = {}
        low = {}
        stack = []
        active = set()
        groups = []

        def visit(node):
            nonlocal index
            indices[node] = low[node] = index
            index += 1
            stack.append(node)
            active.add(node)
            for target in sorted(adjacency[node]):
                if target not in indices:
                    visit(target)
                    low[node] = min(low[node], low[target])
                elif target in active:
                    low[node] = min(low[node], indices[target])
            if low[node] == indices[node]:
                group = []
                while True:
                    item = stack.pop()
                    active.remove(item)
                    group.append(item)
                    if item == node:
                        break
                groups.append(tuple(sorted(group)))

        for node in sorted(adjacency):
            if node not in indices:
                visit(node)
        return tuple(groups)
