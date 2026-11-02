"""Revision-bound sanitized security snapshots and workload-response events."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova.domain.system_graph import SystemGraph
from sova.security.domain.posture import PostureFinding
from sova.security.domain.governance import scope_document


@dataclass(frozen=True, slots=True)
class SecuritySnapshot:
    graph: SystemGraph
    findings: tuple[PostureFinding, ...]
    collection_digest: str

    def __post_init__(self):
        if (
            not isinstance(self.graph, SystemGraph)
            or type(self.findings) is not tuple
            or len(self.findings) > 512
        ):
            raise ContractError("Bounded typed security snapshot required")
        digest(self.collection_digest)
        resources = {r.scope: r for r in self.graph.resources}
        seen = set()
        for finding in self.findings:
            if not isinstance(finding, PostureFinding):
                raise ContractError("Typed security finding required")
            resource = resources.get(finding.scope)
            if (
                resource is None
                or resource.resource_revision != finding.resource_revision
                or finding.observed_at != self.graph.observed_at
                or finding.valid_until != self.graph.valid_until
            ):
                raise ContractError("Finding not bound to graph revision and validity")
            key = (finding.scope, finding.control_id)
            if key in seen:
                raise ContractError("Duplicate scoped security finding")
            seen.add(key)
        object.__setattr__(
            self,
            "findings",
            tuple(
                sorted(self.findings, key=lambda f: (f.scope.resource_id, f.control_id))
            ),
        )
        canonical_json(self.document, limit=524288)

    @property
    def document(self):
        return {
            "schema_version": 1,
            "graph": self.graph.document,
            "findings": [
                f.document
                for f in sorted(
                    self.findings, key=lambda x: (x.scope.resource_id, x.control_id)
                )
            ],
            "collection_digest": self.collection_digest,
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=524288).encode()
        ).hexdigest()


class SecurityEventKind(StrEnum):
    OBSERVED = "security_observed"
    HOLD_OPENED = "security_hold_opened"
    RESPONSE_PLANNED = "response_planned"
    RESPONSE_APPROVED = "response_approved"
    ISOLATION_VERIFIED = "isolation_verified"
    REPLACEMENT_VERIFIED = "replacement_verified"
    ROUTE_SWITCHED = "route_switched"
    RECOVERY_VERIFIED = "recovery_verified"
    EFFECT_UNKNOWN = "effect_unknown"


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    event_id: str
    scope: ResourceScope
    snapshot_digest: str
    graph_digest: str
    kind: SecurityEventKind
    node_ids: tuple[str, ...]
    recorded_at: datetime
    details_json: str

    def __post_init__(self):
        identifier(self.event_id)
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.kind, SecurityEventKind
        ):
            raise ContractError("Typed security event scope/kind required")
        digest(self.snapshot_digest)
        digest(self.graph_digest)
        if type(self.node_ids) is not tuple or not 1 <= len(self.node_ids) <= 32:
            raise ContractError("Bounded immutable security subjects required")
        for node in self.node_ids:
            identifier(node)
        if len(set(self.node_ids)) != len(self.node_ids):
            raise ContractError("Duplicate event subject")
        from sova.domain.contracts import public_json

        details = public_json(self.details_json)
        if set(details) - {
            "request_id",
            "hold_id",
            "plan_digest",
            "effect_digest",
            "source_environment",
            "target_environment",
            "target_snapshot_digest",
            "basis",
            "result",
            "actor_id",
            "previous_event_id",
        }:
            raise ContractError("Unregistered event detail fields")
        for value in details.values():
            identifier(value, "event detail", limit=256)
        for key in ("plan_digest", "effect_digest", "target_snapshot_digest"):
            if key in details:
                digest(details[key])
        object.__setattr__(self, "details_json", canonical_json(details))
        object.__setattr__(self, "recorded_at", utc(self.recorded_at))

    @property
    def document(self):
        from sova.domain.contracts import public_json

        return {
            "event_id": self.event_id,
            "scope": scope_document(self.scope),
            "snapshot_digest": self.snapshot_digest,
            "graph_digest": self.graph_digest,
            "kind": str(self.kind),
            "node_ids": list(self.node_ids),
            "recorded_at": self.recorded_at.isoformat(),
            "details": public_json(self.details_json),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()
