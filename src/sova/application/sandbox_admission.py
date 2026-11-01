"""Harbor result admission boundary; runner integration remains separately owned."""

from sova.domain.sandbox_artifacts import assess_sandbox_artifact
from sova.domain.contracts import ContractError
from sova.domain.evidence import EvidenceRecord


class SandboxArtifactAdmission:
    def __init__(
        self,
        *,
        authorize,
        authenticate_request,
        authenticate_artifact,
        authenticate_evidence,
        clock,
    ):
        self.authorize = authorize
        self.authenticate_request = authenticate_request
        self.authenticate_artifact = authenticate_artifact
        self.authenticate_evidence = authenticate_evidence
        self.clock = clock

    def assess(
        self, actor, request, artifact, evidence, *, policy_digest, environment_digest
    ):
        self.authorize(actor, request.scope, "sandbox:review-artifact")
        self.authenticate_request(request)
        self.authenticate_artifact(artifact)
        if (
            type(evidence) is not tuple
            or len(evidence) > 4096
            or any(not isinstance(e, EvidenceRecord) for e in evidence)
        ):
            raise ContractError("Bounded immutable sandbox evidence required")
        for record in evidence:
            self.authenticate_evidence(record)
        return assess_sandbox_artifact(
            request,
            artifact,
            evidence,
            policy_digest=policy_digest,
            environment_digest=environment_digest,
            now=self.clock(),
        )
