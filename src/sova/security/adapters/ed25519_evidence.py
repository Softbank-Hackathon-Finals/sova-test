"""Optional cryptography adapter. Private keys belong outside untrusted workers."""

from dataclasses import replace
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sova.domain.contracts import ContractError
from sova.security.domain.signed_evidence import EvidenceEnvelope, VerifierTrust


class Ed25519EvidenceSigner:
    def __init__(self, private_key, *, issuer_id, key_id):
        if not isinstance(private_key, Ed25519PrivateKey):
            raise ContractError("Ed25519 signer key required")
        self._key = private_key
        self.issuer_id = issuer_id
        self.key_id = key_id

    @property
    def public_key_hex(self):
        return self._key.public_key().public_bytes_raw().hex()

    def sign(self, evidence, *, issued_at):
        unsigned = EvidenceEnvelope(
            self.issuer_id, self.key_id, issued_at, evidence, "0" * 128
        )
        return replace(
            unsigned, signature_hex=self._key.sign(unsigned.signing_bytes).hex()
        )


class Ed25519EvidenceVerifier:
    def __init__(self, resolve_trust):
        self.resolve_trust = resolve_trust

    def verify(self, envelope, *, expected_record, now):
        if (
            not isinstance(envelope, EvidenceEnvelope)
            or envelope.evidence != expected_record
        ):
            raise ContractError("Signed evidence record mismatch")
        trust = self.resolve_trust(envelope.issuer_id, envelope.key_id)
        if not isinstance(trust, VerifierTrust):
            raise ContractError("Registered verifier trust required")
        trust.require_authorized(envelope, now)
        try:
            Ed25519PublicKey.from_public_bytes(
                bytes.fromhex(trust.public_key_hex)
            ).verify(bytes.fromhex(envelope.signature_hex), envelope.signing_bytes)
        except (InvalidSignature, ValueError) as exc:
            raise ContractError("Evidence signature verification failed") from exc
        return envelope.evidence
