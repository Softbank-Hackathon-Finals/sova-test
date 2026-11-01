"""Bind sandbox outputs to independent tests and existing revision evidence.

No Harbor runner is started here. An eligible artifact still requires an
authenticated lifecycle plan approval, provider permission and readback.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib

from sova.domain.contracts import ContractError, canonical_json, digest, identifier, utc
from sova.domain.evidence import (
    Gate,
    RevisionSet,
    VerificationObligation,
    evaluate_gate,
)
from sova.domain.sandbox import SandboxRequest


@dataclass(frozen=True, slots=True)
class SandboxArtifact:
    request_id: str
    request_digest: str
    source_digest: str
    patch_digest: str
    image_digest: str
    tests_digest: str
    created_at: datetime
    valid_until: datetime

    def __post_init__(self):
        identifier(self.request_id)
        for value in (
            self.request_digest,
            self.source_digest,
            self.patch_digest,
            self.image_digest,
            self.tests_digest,
        ):
            digest(value)
        object.__setattr__(self, "created_at", utc(self.created_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.created_at:
            raise ContractError("Positive artifact interval required")

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(
                {
                    "request_id": self.request_id,
                    "request_digest": self.request_digest,
                    "source_digest": self.source_digest,
                    "patch_digest": self.patch_digest,
                    "image_digest": self.image_digest,
                    "tests_digest": self.tests_digest,
                    "created_at": self.created_at.isoformat(),
                    "valid_until": self.valid_until.isoformat(),
                }
            ).encode()
        ).hexdigest()


def artifact_obligations(request):
    if not isinstance(request, SandboxRequest):
        raise ContractError("Typed sandbox request required")
    return tuple(
        VerificationObligation(
            f"sandbox-artifact:{request.request_id}:{name}",
            request.scope,
            Gate.CHANGE,
            verifier,
        )
        for name, verifier in (
            ("input-binding", "sandbox-source-tests-binding-v1"),
            ("egress-denial", "sandbox-egress-denial-v1"),
            ("independent-verifier", "sandbox-independent-verifier-v1"),
        )
    )


def assess_sandbox_artifact(
    request, artifact, evidence, *, policy_digest, environment_digest, now
):
    if not isinstance(request, SandboxRequest) or not isinstance(
        artifact, SandboxArtifact
    ):
        raise ContractError("Typed sandbox request and output required")
    now = utc(now)
    request.require_current(now)
    if (request.request_id, request.source_digest, request.tests_digest) != (
        artifact.request_id,
        artifact.source_digest,
        artifact.tests_digest,
    ):
        raise ContractError("Sandbox output does not match original request/tests")
    if artifact.request_digest != request.fingerprint:
        raise ContractError(
            "Sandbox artifact differs from the complete original request"
        )
    if request.agent_image == request.verifier_image:
        raise ContractError("Agent and independent verifier images must differ")
    if not artifact.created_at <= now < artifact.valid_until <= request.valid_until:
        raise ContractError("Artifact expired, future, or outlives request")
    if type(evidence) is not tuple:
        raise ContractError("Immutable independent evidence required")
    revisions = RevisionSet(
        artifact.source_digest, artifact.fingerprint, policy_digest, environment_digest
    )
    decision = evaluate_gate(
        Gate.CHANGE, artifact_obligations(request), evidence, revisions, now=now
    )
    return {
        "eligible_for_approval": decision.accepted,
        "artifact_digest": artifact.fingerprint,
        "image_digest": artifact.image_digest,
        "execution_authorized": False,
        "results": [
            {
                "id": d.obligation.obligation_id,
                "result": str(d.result),
                "evidence_id": d.evidence_id,
                "reason": d.reason,
            }
            for d in decision.decisions
        ],
        "remaining": [
            "authenticate-issuer-and-current-revocation",
            "lifecycle-plan-approval",
            "governance-holds-recheck",
            "deployed-image-digest-readback",
        ],
    }
