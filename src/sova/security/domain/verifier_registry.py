"""Immutable, app-scoped verifier trust changes with independent approval.

Actor names are bindings, not authentication. The administration use case must
authenticate both identities and the exact change, outside this domain model.
"""

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
from sova.domain.contracts import ContractError, canonical_json, identifier, utc
from sova.security.domain.governance import scope_document
from sova.security.domain.signed_evidence import VerifierTrust


def trust_document(trust):
    return {
        "issuer_id": trust.issuer_id,
        "key_id": trust.key_id,
        "public_key_hex": trust.public_key_hex,
        "allowed_scopes": [
            scope_document(s)
            for s in sorted(
                trust.allowed_scopes,
                key=lambda s: (
                    s.tenant_id,
                    s.application_id,
                    s.environment_id,
                    s.resource_id,
                ),
            )
        ],
        "allowed_verifiers": sorted(trust.allowed_verifiers),
        "valid_from": trust.valid_from.isoformat(),
        "valid_until": trust.valid_until.isoformat(),
        "revoked": trust.revoked,
    }


@dataclass(frozen=True, slots=True)
class VerifierTrustChange:
    tenant_id: str
    application_id: str
    revision: int
    trust: VerifierTrust
    requested_by: str
    approved_by: str
    reason: str
    approved_at: datetime
    approval_until: datetime

    def __post_init__(self):
        for key in (
            "tenant_id",
            "application_id",
            "requested_by",
            "approved_by",
            "reason",
        ):
            identifier(getattr(self, key), key, limit=1024 if key == "reason" else 256)
        if (
            type(self.revision) is not int
            or self.revision < 1
            or not isinstance(self.trust, VerifierTrust)
        ):
            raise ContractError(
                "Positive trust revision and typed verifier trust required"
            )
        if self.requested_by == self.approved_by:
            raise ContractError("Independent verifier trust approver required")
        if any(
            (s.tenant_id, s.application_id) != (self.tenant_id, self.application_id)
            for s in self.trust.allowed_scopes
        ):
            raise ContractError("Verifier trust cannot cross tenant/application")
        object.__setattr__(
            self,
            "trust",
            replace(
                self.trust,
                allowed_scopes=tuple(
                    sorted(
                        self.trust.allowed_scopes,
                        key=lambda s: (
                            s.tenant_id,
                            s.application_id,
                            s.environment_id,
                            s.resource_id,
                        ),
                    )
                ),
                allowed_verifiers=tuple(sorted(self.trust.allowed_verifiers)),
            ),
        )
        object.__setattr__(self, "approved_at", utc(self.approved_at))
        object.__setattr__(self, "approval_until", utc(self.approval_until))
        if self.approval_until <= self.approved_at:
            raise ContractError("Bounded verifier trust approval required")
        canonical_json(self.document, limit=131072)

    @property
    def document(self):
        return {
            "schema_version": 1,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "revision": self.revision,
            "trust": trust_document(self.trust),
            "requested_by": self.requested_by,
            "approved_by": self.approved_by,
            "reason": self.reason,
            "approved_at": self.approved_at.isoformat(),
            "approval_until": self.approval_until.isoformat(),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=131072).encode()
        ).hexdigest()

    def require_current(self, now):
        if not self.approved_at <= utc(now) < self.approval_until:
            raise ContractError("Verifier trust approval expired or future")

    def require_successor(self, prior):
        if prior is None:
            if self.revision != 1:
                raise ContractError("Verifier trust must start at revision one")
            return
        if (
            prior.tenant_id,
            prior.application_id,
            prior.trust.issuer_id,
            prior.trust.key_id,
            prior.revision + 1,
        ) != (
            self.tenant_id,
            self.application_id,
            self.trust.issuer_id,
            self.trust.key_id,
            self.revision,
        ):
            raise ContractError("Verifier trust successor scope/revision mismatch")
        if self.trust.public_key_hex != prior.trust.public_key_hex:
            raise ContractError("Key material changes require a new key ID")
        if prior.trust.revoked:
            raise ContractError(
                "A revoked verifier key cannot be reactivated or replaced"
            )
        if self.approved_at < prior.approved_at:
            raise ContractError("Verifier trust approval moved backwards")
