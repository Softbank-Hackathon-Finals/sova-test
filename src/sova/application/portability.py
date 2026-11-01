"""Read-only portability assessment; a proposal is not an executable plan."""

from datetime import datetime

from sova.domain.contracts import identifier, utc
from sova.domain.system_graph import Portability, ResourceKind, SystemGraph
from sova.domain.migration_program import six_area_catalog
from sova.domain.dependency_requirements import dependency_check_catalog


REQUIRED_VERIFICATIONS = (
    "source-and-target-ownership",
    "target-capability-and-qualification",
    "all-writers-inventory",
    "protection-equivalence",
    "data-residency",
    "price-and-migration-budget",
    "sandbox-behavior-comparison",
    "source-dependency-denial-rehearsal",
    "single-writer-handoff",
    "post-cutover-read-write",
    "recovery-after-new-writes",
    "cleanup-and-residual-dependencies",
)


def assess_portability(
    graph: SystemGraph, *, target_environment: str, target_backend: str, now: datetime
):
    graph.require_current(now)
    identifier(target_environment, "target environment")
    identifier(target_backend, "target backend")
    nodes = {n.node_id: n for n in graph.resources}
    if target_environment in {n.scope.environment_id for n in graph.resources}:
        raise ValueError("Target must be a distinct registered environment identifier")
    items = []
    for resource in sorted(graph.resources, key=lambda n: n.node_id):
        recommendation = {
            Portability.PORTABLE: "revalidate-and-redeploy",
            Portability.CONFIGURATION: "prepare-configuration-change",
            Portability.TRANSFORMATION: "sandbox-transformation-candidate",
            Portability.PROVIDER_BOUND: "retain-or-replace-with-approval",
            Portability.UNKNOWN: "inspect-before-planning",
        }[resource.portability]
        items.append(
            {
                "node_id": resource.node_id,
                "kind": str(resource.kind),
                "source_backend": resource.backend,
                "recommendation": recommendation,
                "assessment_basis": "api-declaration-not-runtime-verification"
                if graph.origin == "kubernetes_api"
                else "registered-assertion-not-runtime-verification",
                "requirements": list(resource.requirements),
            }
        )
    groups = []
    for index, group in enumerate(graph.movement_groups(), 1):
        groups.append(
            {
                "unit_id": f"unit-{index}",
                "resources": list(group),
                "review_together": len(group) > 1,
                "contains_database": any(
                    nodes[n].kind == ResourceKind.DATABASE for n in group
                ),
                "ordering": "dependency-first-review-only; permitted retained links require a separate policy decision",
            }
        )
    return {
        "schema_version": 1,
        "status": "proposal-only",
        "executable": False,
        "graph_digest": graph.fingerprint,
        "graph_revision": graph.revision,
        "tenant_id": graph.tenant_id,
        "application_id": graph.application_id,
        "assessed_at": utc(now).isoformat(),
        "target": {
            "environment_id": target_environment,
            "backend": target_backend,
            "readiness": "unverified",
        },
        "lock_in_map": items,
        "review_units": groups,
        "required_verifications": list(REQUIRED_VERIFICATIONS),
        "required_areas": six_area_catalog(),
        "dependency_verifications": dependency_check_catalog(graph),
        "rehearsal": {
            "mode": "isolated-source-dependency-denial",
            "targets": [n.node_id for n in graph.resources],
            "must_preserve_management_and_observation_paths": True,
            "runtime_implemented": False,
        },
        "blockers": [
            "target-registration-and-live-evidence-required",
            "adapter-qualification-required",
            "authenticated-approval-required",
            "data-and-recovery-path-not-integrated",
        ],
    }
