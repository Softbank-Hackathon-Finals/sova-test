"""Signed evidence envelopes and exact verifier/scope trust, not user login."""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import re

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    identifier,
    utc,
)
from sova.domain.evidence import EvidenceRecord


def evidence_document(record):
    if not isinstance(record, EvidenceRecord):
        raise ContractError("Typed evidence required")
    if record.justification is not None:
        identifier(record.justification, "evidence justification", limit=2048)
    if record.approved_by is not None:
        identifier(record.approved_by, "evidence approver")
    data = asdict(record)
    data["result"] = str(record.result)
    data["observed_at"] = record.observed_at.isoformat()
    data["valid_until"] = record.valid_until.isoformat()
    return data


@dataclass(frozen=True, slots=True)
class EvidenceEnvelope:
    issuer_id: str
    key_id: str
    issued_at: datetime
    evidence: EvidenceRecord
    signature_hex: str

    def __post_init__(self):
        identifier(self.issuer_id)
        identifier(self.key_id)
        if not isinstance(self.evidence, EvidenceRecord):
            raise ContractError("Typed signed evidence required")
        if not isinstance(self.signature_hex, str) or not re.fullmatch(
            "[0-9a-f]{128}", self.signature_hex
        ):
            raise ContractError("Ed25519 signature required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        canonical_json(self.document, limit=16384)

    @property
    def payload(self):
        return {
            "schema_version": 1,
            "algorithm": "Ed25519",
            "issuer_id": self.issuer_id,
            "key_id": self.key_id,
            "issued_at": self.issued_at.isoformat(),
            "evidence": evidence_document(self.evidence),
        }

    @property
    def signing_bytes(self):
        return (
            b"SOVA-EVIDENCE-ENVELOPE-V1\x00"
            + canonical_json(self.payload, limit=16384).encode()
        )

    @property
    def document(self):
        return {**self.payload, "signature": self.signature_hex}

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=16384).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class VerifierTrust:
    issuer_id: str
    key_id: str
    public_key_hex: str
    allowed_scopes: tuple[ResourceScope, ...]
    allowed_verifiers: tuple[str, ...]
    valid_from: datetime
    valid_until: datetime
    revoked: bool = False

    def __post_init__(self):
        identifier(self.issuer_id)
        identifier(self.key_id)
        if not isinstance(self.public_key_hex, str) or not re.fullmatch(
            "[0-9a-f]{64}", self.public_key_hex
        ):
            raise ContractError("Raw Ed25519 public key required")
        if (
            type(self.allowed_scopes) is not tuple
            or not 1 <= len(self.allowed_scopes) <= 256
            or any(not isinstance(s, ResourceScope) for s in self.allowed_scopes)
        ):
            raise ContractError("Explicit verifier resource scopes required")
        if len(set(self.allowed_scopes)) != len(self.allowed_scopes):
            raise ContractError("Duplicate verifier scopes")
        if (
            type(self.allowed_verifiers) is not tuple
            or not 1 <= len(self.allowed_verifiers) <= 32
        ):
            raise ContractError("Explicit verifier versions required")
        for version in self.allowed_verifiers:
            identifier(version)
        if (
            len(set(self.allowed_verifiers)) != len(self.allowed_verifiers)
            or type(self.revoked) is not bool
        ):
            raise ContractError("Invalid verifier trust policy")
        object.__setattr__(self, "valid_from", utc(self.valid_from))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.valid_from:
            raise ContractError("Invalid trust validity")

    def require_authorized(self, envelope, now):
        now = utc(now)
        record = envelope.evidence
        if (envelope.issuer_id, envelope.key_id) != (
            self.issuer_id,
            self.key_id,
        ) or self.revoked:
            raise ContractError("Unknown or revoked verifier")
        if (
            not self.valid_from
            <= record.observed_at
            <= envelope.issued_at
            <= now
            < min(record.valid_until, self.valid_until)
        ):
            raise ContractError("Evidence/key expired or from the future")
        if record.valid_until > self.valid_until:
            raise ContractError("Evidence cannot outlive verifier trust")
        if (
            record.scope not in self.allowed_scopes
            or record.verifier_version not in self.allowed_verifiers
        ):
            raise ContractError("Verifier cannot attest this scope/version")
