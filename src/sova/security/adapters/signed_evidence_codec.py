"""Strict schema, no request-supplied public keys or algorithm negotiation."""

from datetime import datetime
from sova.adapters.registration.graph_codec import exact
from sova.domain.contracts import ContractError, ResourceScope
from sova.domain.evidence import EvidenceRecord, RevisionSet, VerificationResult
from sova.security.domain.signed_evidence import EvidenceEnvelope


def decode_envelope(data):
    try:
        exact(
            data,
            (
                "schema_version",
                "algorithm",
                "issuer_id",
                "key_id",
                "issued_at",
                "evidence",
                "signature",
            ),
        )
        if (
            type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or data["algorithm"] != "Ed25519"
        ):
            raise ContractError("Unsupported evidence envelope schema/algorithm")
        record = data["evidence"]
        exact(
            record,
            (
                "evidence_id",
                "obligation_id",
                "scope",
                "revisions",
                "verifier_version",
                "observed_at",
                "valid_until",
                "result",
                "artifact_id",
                "artifact_digest",
                "justification",
                "approved_by",
            ),
        )
        exact(
            record["scope"],
            ("tenant_id", "application_id", "environment_id", "resource_id"),
        )
        exact(record["revisions"], ("source", "configuration", "policy", "environment"))
        evidence = EvidenceRecord(
            **{
                k: v
                for k, v in record.items()
                if k
                not in {"scope", "revisions", "observed_at", "valid_until", "result"}
            },
            scope=ResourceScope(**record["scope"]),
            revisions=RevisionSet(**record["revisions"]),
            observed_at=datetime.fromisoformat(record["observed_at"]),
            valid_until=datetime.fromisoformat(record["valid_until"]),
            result=VerificationResult(record["result"]),
        )
        return EvidenceEnvelope(
            data["issuer_id"],
            data["key_id"],
            datetime.fromisoformat(data["issued_at"]),
            evidence,
            data["signature"],
        )
    except (KeyError, ValueError, TypeError, UnicodeError) as exc:
        raise ContractError("Invalid signed evidence envelope") from exc
