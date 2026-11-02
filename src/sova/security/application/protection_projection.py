"""Read-only configuration comparison from authenticated collector snapshots.

This derived display is not a published policy, approval or execution permit.
Kubernetes configuration checks cannot establish IAM, encryption or HA parity.
"""

from datetime import timedelta
import hashlib
from sova.domain.contracts import ContractError, canonical_json, utc
from sova.security.domain.security_events import SecuritySnapshot
from sova.security.domain.posture import FindingBasis
from sova.security.domain.protection_parity import (
    Availability,
    ProtectionEndpoint,
    ProtectionRequirement,
    ProtectionPolicy,
    assess_protection,
)
from sova.domain.evidence import EvidenceRecord
from sova.security.domain.governance import ControlFamily


CONFIGURATION_OBJECTIVES = {
    "no-privileged": (
        ControlFamily.IDENTITY,
        "Disallow privileged workload configuration",
    ),
    "non-root": (ControlFamily.IDENTITY, "Require non-root workload configuration"),
    "no-escalation": (
        ControlFamily.IDENTITY,
        "Disallow privilege escalation in workload configuration",
    ),
    "drop-capabilities": (
        ControlFamily.IDENTITY,
        "Drop additional Linux capabilities in workload configuration",
    ),
    "read-only-root": (
        ControlFamily.IDENTITY,
        "Require read-only root filesystem configuration",
    ),
    "runtime-seccomp": (
        ControlFamily.IDENTITY,
        "Require a declared allowed seccomp profile",
    ),
    "no-host-namespaces": (
        ControlFamily.NETWORK,
        "Disallow host namespace sharing in workload configuration",
    ),
    "no-host-mounts": (
        ControlFamily.NETWORK,
        "Disallow host path mounts in workload configuration",
    ),
    "no-auto-token": (
        ControlFamily.SECRETS,
        "Disable automatic service account token mounting",
    ),
    "no-literal-sensitive-env": (
        ControlFamily.SECRETS,
        "Reject recognized literal sensitive environment settings",
    ),
    "digest-pinned-images": (
        ControlFamily.POLICY,
        "Pin declared workload images by OCI digest",
    ),
    "bounded-resources": (
        ControlFamily.POLICY,
        "Declare positive bounded CPU and memory limits",
    ),
}


def compare_configuration(
    source, target, *, source_node, target_node, now, max_age_seconds=15
):
    now = utc(now)
    if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 60:
        raise ContractError("Bounded configuration comparison freshness required")
    if any(
        not isinstance(s, SecuritySnapshot) or s.graph.origin != "kubernetes_api"
        for s in (source, target)
    ):
        raise ContractError("Actual registered Kubernetes collection required")
    resources = []
    for snapshot, node in [(source, source_node), (target, target_node)]:
        snapshot.graph.require_current(now)
        if now - snapshot.graph.observed_at > timedelta(seconds=max_age_seconds):
            raise ContractError("Configuration comparison observations are stale")
        resource = next(
            (r for r in snapshot.graph.resources if r.node_id == node), None
        )
        if resource is None or resource.backend != "kubernetes":
            raise ContractError("Registered Kubernetes comparison subject required")
        resources.append(resource)
    requirements = []
    records = []
    configuration_digests = {}
    for snapshot, resource in zip((source, target), resources):
        values = {
            f.source_digest for f in snapshot.findings if f.scope == resource.scope
        }
        if len(values) > 1:
            raise ContractError("Inconsistent configuration projection provenance")
        configuration_digests[resource.scope] = next(iter(values), "0" * 64)
    for control, (family, objective) in CONFIGURATION_OBJECTIVES.items():
        endpoints = []
        for snapshot, resource in zip((source, target), resources):
            finding = next(
                (
                    f
                    for f in snapshot.findings
                    if f.scope == resource.scope and f.control_id == control
                ),
                None,
            )
            if finding is not None and (
                finding.basis != FindingBasis.CONFIGURATION or finding.family != family
            ):
                raise ContractError(
                    "Unexpected configuration comparison verifier or family"
                )
            endpoints.append(
                ProtectionEndpoint(
                    resource.scope,
                    "unclassified",
                    "pod-template:" + control,
                    Availability.AVAILABLE,
                    Availability.AVAILABLE,
                    hashlib.sha256(
                        canonical_json(resource.document).encode()
                    ).hexdigest(),
                    configuration_digests[resource.scope],
                    hashlib.sha256(
                        canonical_json(
                            {
                                "scope": resource.document["scope"],
                                "location": resource.location,
                            }
                        ).encode()
                    ).hexdigest(),
                    "sova-kubernetes-configuration-v1",
                )
            )
        requirements.append(
            ProtectionRequirement(control, family, objective, *endpoints)
        )
    policy = ProtectionPolicy(
        source.graph.tenant_id,
        source.graph.application_id,
        1,
        tuple(requirements),
        max(source.graph.observed_at, target.graph.observed_at),
        min(
            source.graph.valid_until,
            target.graph.valid_until,
            source.graph.observed_at + timedelta(seconds=max_age_seconds),
            target.graph.observed_at + timedelta(seconds=max_age_seconds),
        ),
    )
    for requirement in policy.requirements:
        for side, snapshot, resource in [
            ("source", source, resources[0]),
            ("target", target, resources[1]),
        ]:
            finding = next(
                (
                    f
                    for f in snapshot.findings
                    if f.scope == resource.scope
                    and f.control_id == requirement.requirement_id
                ),
                None,
            )
            if finding:
                endpoint = getattr(requirement, side)
                records.append(
                    EvidenceRecord(
                        "comparison:" + side + ":" + finding.fingerprint,
                        requirement.obligation(side).obligation_id,
                        finding.scope,
                        endpoint.revisions(policy.fingerprint),
                        finding.verifier_version,
                        finding.observed_at,
                        min(finding.valid_until, policy.valid_until),
                        finding.result,
                        "posture:" + finding.fingerprint,
                        finding.fingerprint,
                    )
                )
    report = assess_protection(policy, tuple(records), now=now)
    return {
        **report,
        "basis": "configuration_only",
        "execution_authority": False,
        "source_snapshot": source.fingerprint,
        "target_snapshot": target.fingerprint,
        "unverified": [
            "runtime-enforcement",
            "cross-application-secret-denial",
            "encryption",
            "audit",
            "backup-and-restore",
            "availability",
            "whole-environment-equivalence",
        ],
    }
