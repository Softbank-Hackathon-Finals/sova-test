"""Compile declared dependencies into mandatory resource-specific obligations.

This binds a registered inventory, not verified discovery or target mapping. New
resource kinds cannot silently disappear, and declared requirements stay unknown
until their exact verifier contract is qualified. Nothing executes here.
"""

from dataclasses import replace
from datetime import datetime
import hashlib

from sova.domain.contracts import ContractError, ResourceScope, canonical_json, utc
from sova.domain.evidence import Gate, VerificationObligation
from sova.domain.migration_program import (
    MigrationArea,
    ProgramRequirement,
    six_area_program,
)
from sova.domain.system_graph import ResourceKind, RelationKind, SystemGraph

# Protection objectives, not claims that these provider-specific probes exist.
_CHECKS = {
    ResourceKind.SERVICE: (
        (
            MigrationArea.MIGRATION,
            "behavior",
            Gate.BEHAVIOR,
            "resource-business-behavior-v1",
        ),
        (
            MigrationArea.SANDBOX,
            "image-readback",
            Gate.PREFLIGHT,
            "resource-image-readback-v1",
        ),
    ),
    ResourceKind.DATABASE: (
        (
            MigrationArea.MIGRATION,
            "data-boundary",
            Gate.PREFLIGHT,
            "resource-data-boundary-v1",
        ),
        (
            MigrationArea.MIGRATION,
            "sequence",
            Gate.PREFLIGHT,
            "resource-sequence-state-v1",
        ),
        (
            MigrationArea.MIGRATION,
            "recovery",
            Gate.PREFLIGHT,
            "resource-new-write-recovery-v1",
        ),
    ),
    ResourceKind.STORAGE: (
        (
            MigrationArea.MIGRATION,
            "objects",
            Gate.PREFLIGHT,
            "resource-object-content-metadata-v1",
        ),
        (
            MigrationArea.GOVERNANCE,
            "object-access",
            Gate.PROTECTION,
            "resource-object-access-denial-v1",
        ),
    ),
    ResourceKind.WORKER: (
        (
            MigrationArea.MIGRATION,
            "worker-drain",
            Gate.PREFLIGHT,
            "resource-worker-drain-v1",
        ),
        (
            MigrationArea.MIGRATION,
            "job-replay",
            Gate.BEHAVIOR,
            "resource-job-idempotency-v1",
        ),
    ),
    ResourceKind.QUEUE: (
        (
            MigrationArea.MIGRATION,
            "pending-items",
            Gate.PREFLIGHT,
            "resource-pending-queue-state-v1",
        ),
        (
            MigrationArea.DESTINATION,
            "delivery",
            Gate.BEHAVIOR,
            "resource-delivery-semantics-v1",
        ),
    ),
    ResourceKind.IDENTITY: (
        (
            MigrationArea.GOVERNANCE,
            "identity-map",
            Gate.PROTECTION,
            "resource-principal-permission-map-v1",
        ),
        (
            MigrationArea.GOVERNANCE,
            "cross-principal",
            Gate.PROTECTION,
            "resource-unauthorized-access-denial-v1",
        ),
    ),
    ResourceKind.SECRET: (
        (
            MigrationArea.DESTINATION,
            "rotation",
            Gate.PROTECTION,
            "resource-secret-rotation-v1",
        ),
        (
            MigrationArea.DESTINATION,
            "old-secret-denial",
            Gate.PROTECTION,
            "resource-stale-secret-denial-v1",
        ),
    ),
    ResourceKind.AI: (
        (
            MigrationArea.AI_RESIDENCY,
            "location",
            Gate.CHANGE,
            "resource-ai-location-v1",
        ),
        (
            MigrationArea.AI_RESIDENCY,
            "quality",
            Gate.BEHAVIOR,
            "resource-ai-quality-v1",
        ),
        (
            MigrationArea.AI_RESIDENCY,
            "fallback",
            Gate.PROTECTION,
            "resource-ai-fallback-denial-v1",
        ),
    ),
    ResourceKind.OBSERVABILITY: (
        (
            MigrationArea.COST_OBSERVABILITY,
            "telemetry",
            Gate.PREFLIGHT,
            "resource-telemetry-receipt-v1",
        ),
        (
            MigrationArea.DESTINATION,
            "alerting",
            Gate.PROTECTION,
            "resource-alert-route-v1",
        ),
    ),
    ResourceKind.EDGE: (
        (
            MigrationArea.MIGRATION,
            "route-readback",
            Gate.PREFLIGHT,
            "resource-ingress-readback-v1",
        ),
        (
            MigrationArea.GOVERNANCE,
            "tls-and-session",
            Gate.PROTECTION,
            "resource-tls-session-policy-v1",
        ),
    ),
}


def dependency_check_catalog(graph):
    if not isinstance(graph, SystemGraph):
        raise ContractError("Typed registered dependency graph required")
    rows = []
    for node in graph.resources:
        for area, name, gate, verifier in _CHECKS[node.kind]:
            rows.append(
                {
                    "node_id": node.node_id,
                    "area": str(area),
                    "check": name,
                    "gate": int(gate),
                    "verifier": verifier,
                    "qualification": "unverified",
                }
            )
        for requirement in node.requirements:
            rows.append(
                {
                    "node_id": node.node_id,
                    "area": str(MigrationArea.GOVERNANCE),
                    "check": "declared-requirement",
                    "declared_requirement": requirement,
                    "gate": int(Gate.REQUIREMENTS),
                    "verifier": "resource-declared-requirement-v1",
                    "qualification": "unverified",
                }
            )
    for relation in graph.relations:
        if relation.kind == RelationKind.WRITES:
            rows.append(
                {
                    "node_id": relation.source,
                    "dependency_id": relation.target,
                    "area": str(MigrationArea.MIGRATION),
                    "check": "writer-fencing",
                    "gate": int(Gate.PREFLIGHT),
                    "verifier": "resource-writer-fencing-v1",
                    "qualification": "unverified",
                }
            )
    return rows


def compile_dependency_program(
    graph,
    source_scope,
    target_scope,
    revisions,
    *,
    issued_at: datetime,
    valid_until: datetime,
    now: datetime,
):
    if (
        not isinstance(graph, SystemGraph)
        or not isinstance(source_scope, ResourceScope)
        or not isinstance(target_scope, ResourceScope)
    ):
        raise ContractError("Typed graph and registered scopes required")
    graph.require_current(now)
    if (graph.tenant_id, graph.application_id) != (
        source_scope.tenant_id,
        source_scope.application_id,
    ):
        raise ContractError("Program source and dependency graph differ")
    if (
        not graph.observed_at <= utc(issued_at) <= utc(now)
        or utc(valid_until) > graph.valid_until
    ):
        raise ContractError("Program may not predate or outlive its inventory")
    base = six_area_program(
        source_scope,
        target_scope,
        revisions,
        issued_at=issued_at,
        valid_until=valid_until,
    )
    compiled = []
    graph_digest = graph.fingerprint
    catalog = dependency_check_catalog(graph)
    for check in catalog:
        if len(compiled) + len(base.requirements) >= 256:
            raise ContractError(
                "Migration requirement capacity exceeded; split registered scope explicitly"
            )
        binding = hashlib.sha256(
            canonical_json({"graph_digest": graph_digest, "check": check}).encode()
        ).hexdigest()
        name = check["area"] + ":dependency:" + binding
        compiled.append(
            ProgramRequirement(
                MigrationArea(check["area"]),
                VerificationObligation(
                    name, target_scope, Gate(check["gate"]), check["verifier"]
                ),
                f"{check['node_id']}: {check['check']}",
            )
        )
    program = replace(base, requirements=base.requirements + tuple(compiled))
    return {
        "program": program,
        "graph_digest": graph_digest,
        "source_inventory_verified": False,
        "target_mapping_complete": False,
        "execution_authorized": False,
        "dependency_checks": catalog,
    }
