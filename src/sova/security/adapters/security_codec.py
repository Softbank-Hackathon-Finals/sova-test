"""Strict sanitized security record codecs; never accept raw provider documents."""

from datetime import datetime
import hashlib
from sova.adapters.registration.graph_codec import exact, decode_graph
from sova.domain.contracts import ContractError, ResourceScope, canonical_json
from sova.domain.evidence import VerificationResult
from sova.security.domain.governance import ControlFamily
from sova.security.domain.posture import FindingBasis, PostureFinding
from sova.security.domain.security_events import (
    SecuritySnapshot,
    SecurityEvent,
    SecurityEventKind,
)


def decode_finding(data):
    try:
        exact(
            data,
            (
                "control_id",
                "family",
                "scope",
                "resource_revision",
                "result",
                "basis",
                "reason_code",
                "source_digest",
                "observed_at",
                "valid_until",
            ),
        )
        exact(
            data["scope"],
            ("tenant_id", "application_id", "environment_id", "resource_id"),
        )
        return PostureFinding(
            data["control_id"],
            ControlFamily(data["family"]),
            ResourceScope(**data["scope"]),
            data["resource_revision"],
            VerificationResult(data["result"]),
            FindingBasis(data["basis"]),
            data["reason_code"],
            data["source_digest"],
            datetime.fromisoformat(data["observed_at"]),
            datetime.fromisoformat(data["valid_until"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Invalid security finding") from exc


def decode_snapshot(data):
    try:
        exact(data, ("schema_version", "graph", "findings", "collection_digest"))
        if (
            type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or not isinstance(data["findings"], list)
        ):
            raise ContractError("Unsupported security snapshot schema")
        return SecuritySnapshot(
            decode_graph(data["graph"]),
            tuple(decode_finding(item) for item in data["findings"]),
            data["collection_digest"],
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Invalid security snapshot") from exc


def snapshot_from_collection(collection):
    try:
        graph = decode_graph(collection["graph"])
        projection, proof = collection["projection"], collection["collection"]
        if (
            projection.get("verifier") != "sova-kubernetes-configuration-v1"
            or projection.get("graph_digest") != graph.fingerprint
            or proof.get("graph_digest") != graph.fingerprint
        ):
            raise ContractError("Security projection graph mismatch")
        if (
            hashlib.sha256(canonical_json(proof).encode()).hexdigest()
            != collection["collection_digest"]
        ):
            raise ContractError("Collection proof digest mismatch")
        findings = tuple(decode_finding(f) for f in projection["findings"])
        if any(f.basis != FindingBasis.CONFIGURATION for f in findings):
            raise ContractError(
                "Configuration collector cannot assert runtime enforcement"
            )
        return SecuritySnapshot(graph, findings, collection["collection_digest"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Collection has no valid security projection") from exc


def decode_event(data):
    try:
        exact(
            data,
            (
                "event_id",
                "scope",
                "snapshot_digest",
                "graph_digest",
                "kind",
                "node_ids",
                "recorded_at",
                "details",
            ),
        )
        exact(
            data["scope"],
            ("tenant_id", "application_id", "environment_id", "resource_id"),
        )
        if not isinstance(data["node_ids"], list):
            raise ContractError("Event subjects list required")
        return SecurityEvent(
            data["event_id"],
            ResourceScope(**data["scope"]),
            data["snapshot_digest"],
            data["graph_digest"],
            SecurityEventKind(data["kind"]),
            tuple(data["node_ids"]),
            datetime.fromisoformat(data["recorded_at"]),
            canonical_json(data["details"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Invalid security event") from exc
