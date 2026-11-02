"""Versioned minimum protection objectives, bound into an approved policy.

Profiles describe which proofs are needed, not which tools are installed.
Provider verifier versions are explicit authority-approved contracts, never AI
labels or an automatic translation between IAM and Kubernetes RBAC.
"""

from dataclasses import dataclass
import hashlib
from sova.domain.contracts import ContractError, canonical_json, identifier
from sova.security.domain.governance import ControlFamily


@dataclass(frozen=True, slots=True)
class ProtectionObjective:
    objective_id: str
    family: ControlFamily
    accepted_verifiers: tuple[str, ...]

    def __post_init__(self):
        identifier(self.objective_id)
        if (
            not isinstance(self.family, ControlFamily)
            or type(self.accepted_verifiers) is not tuple
            or not 1 <= len(self.accepted_verifiers) <= 16
        ):
            raise ContractError(
                "Explicit bounded objective verifier contracts required"
            )
        for version in self.accepted_verifiers:
            identifier(version)
        if len(set(self.accepted_verifiers)) != len(self.accepted_verifiers):
            raise ContractError("Duplicate objective verifiers")
        object.__setattr__(
            self, "accepted_verifiers", tuple(sorted(self.accepted_verifiers))
        )

    @property
    def document(self):
        return {
            "objective_id": self.objective_id,
            "family": str(self.family),
            "accepted_verifiers": list(self.accepted_verifiers),
        }


@dataclass(frozen=True, slots=True)
class ProtectionProfile:
    profile_id: str
    revision: int
    objectives: tuple[ProtectionObjective, ...]

    def __post_init__(self):
        identifier(self.profile_id)
        if (
            type(self.revision) is not int
            or self.revision < 1
            or type(self.objectives) is not tuple
            or not 1 <= len(self.objectives) <= 64
        ):
            raise ContractError("Bounded versioned protection profile required")
        if any(not isinstance(o, ProtectionObjective) for o in self.objectives) or len(
            {o.objective_id for o in self.objectives}
        ) != len(self.objectives):
            raise ContractError("Unique typed protection objectives required")
        object.__setattr__(
            self,
            "objectives",
            tuple(sorted(self.objectives, key=lambda o: o.objective_id)),
        )

    @property
    def document(self):
        return {
            "schema_version": 1,
            "profile_id": self.profile_id,
            "revision": self.revision,
            "objectives": [o.document for o in self.objectives],
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=65536).encode()
        ).hexdigest()

    def require_policy(self, policy):
        if policy.profile_digest != self.fingerprint:
            raise ContractError("Policy is not bound to current protection profile")
        rows = {r.requirement_id: r for r in policy.requirements}
        for objective in self.objectives:
            req = rows.get(objective.objective_id)
            if req is None or not req.required or req.family != objective.family:
                raise ContractError(
                    "Policy omitted or weakened a required protection objective"
                )
            if any(
                ep.verifier_version not in objective.accepted_verifiers
                for ep in (req.source, req.target)
            ):
                raise ContractError(
                    "Configuration or unrelated verifier cannot satisfy this protection objective"
                )


def production_protection_profile():
    """Required proof contracts. Presence here does not claim an implemented probe."""
    specs = (
        (
            "cross-app-access-denial",
            ControlFamily.IDENTITY,
            ("aws-app-denial-probe-v1", "kubernetes-app-denial-probe-v1"),
        ),
        (
            "secret-rotation-and-revocation",
            ControlFamily.SECRETS,
            ("aws-secret-rotation-probe-v1", "onprem-secret-rotation-probe-v1"),
        ),
        (
            "egress-and-management-boundary",
            ControlFamily.NETWORK,
            ("aws-egress-denial-probe-v1", "kubernetes-egress-denial-probe-v1"),
        ),
        (
            "tls-peer-verification",
            ControlFamily.ENCRYPTION,
            ("tls-peer-verification-probe-v1",),
        ),
        (
            "storage-key-access-denial",
            ControlFamily.ENCRYPTION,
            ("aws-storage-key-denial-probe-v1", "onprem-storage-key-denial-probe-v1"),
        ),
        (
            "audit-delivery-and-integrity",
            ControlFamily.AUDIT,
            ("audit-delivery-integrity-probe-v1",),
        ),
        (
            "backup-restore-and-integrity",
            ControlFamily.BACKUP,
            ("backup-restore-integrity-probe-v1",),
        ),
    )
    return ProtectionProfile(
        "sova-production-protection",
        1,
        tuple(ProtectionObjective(*args) for args in specs),
    )
