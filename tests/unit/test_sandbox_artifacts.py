from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import pytest

from sova.application.sandbox_admission import SandboxArtifactAdmission
from sova.domain.contracts import ContractError
from sova.domain.evidence import EvidenceRecord, RevisionSet, VerificationResult
from sova.domain.sandbox import SandboxRequest
from sova.domain.sandbox_artifacts import (
    SandboxArtifact,
    artifact_obligations,
    assess_sandbox_artifact,
)


@pytest.fixture
def prepared(scope, now):
    request = SandboxRequest(
        scope,
        "task-1",
        "a" * 64,
        "b" * 64,
        "agent@sha256:" + "c" * 64,
        "verifier@sha256:" + "d" * 64,
        120,
        now + timedelta(minutes=5),
    )
    artifact = SandboxArtifact(
        "task-1",
        request.fingerprint,
        "a" * 64,
        "e" * 64,
        "f" * 64,
        "b" * 64,
        now - timedelta(seconds=1),
        now + timedelta(minutes=3),
    )
    revisions = RevisionSet(
        artifact.source_digest, artifact.fingerprint, "1" * 64, "2" * 64
    )
    evidence = tuple(
        EvidenceRecord(
            f"sandbox-proof-{i}",
            o.obligation_id,
            o.scope,
            revisions,
            o.verifier_version,
            now - timedelta(seconds=1),
            now + timedelta(minutes=2),
            VerificationResult.PASS,
            f"sandbox-report-{i}",
            "3" * 64,
        )
        for i, o in enumerate(artifact_obligations(request))
    )
    return request, artifact, evidence


def assess(prepared, now, **changes):
    request, artifact, evidence = prepared
    args = dict(policy_digest="1" * 64, environment_digest="2" * 64, now=now)
    args.update(changes)
    return assess_sandbox_artifact(request, artifact, evidence, **args)


def test_verified_output_only_becomes_eligible_for_human_review(prepared, now):
    result = assess(prepared, now)
    assert result["eligible_for_approval"] and not result["execution_authorized"]
    assert "deployed-image-digest-readback" in result["remaining"]


def test_agent_success_or_missing_independent_verifier_is_not_enough(prepared, now):
    request, artifact, evidence = prepared
    assert not assess((request, artifact, evidence[:-1]), now)["eligible_for_approval"]
    evidence = tuple(replace(e, verifier_version="agent-self-report") for e in evidence)
    assert not assess((request, artifact, evidence), now)["eligible_for_approval"]


@pytest.mark.parametrize("field", ["patch_digest", "image_digest"])
def test_changed_patch_or_image_invalidates_previous_evidence(prepared, now, field):
    request, artifact, evidence = prepared
    artifact = replace(artifact, **{field: "9" * 64})
    assert not assess((request, artifact, evidence), now)["eligible_for_approval"]


def test_agent_cannot_replace_independent_tests_or_verifier_image(prepared, now):
    request, artifact, evidence = prepared
    with pytest.raises(ContractError, match="original request/tests"):
        assess((request, replace(artifact, tests_digest="9" * 64), evidence), now)
    with pytest.raises(ContractError, match="must differ"):
        assess(
            (replace(request, verifier_image=request.agent_image), artifact, evidence),
            now,
        )


def test_expired_or_other_request_output_rejected(prepared, now):
    request, artifact, evidence = prepared
    with pytest.raises(ContractError, match="expired"):
        assess((request, replace(artifact, valid_until=now), evidence), now)
    with pytest.raises(ContractError, match="original"):
        assess((request, replace(artifact, request_id="other-task"), evidence), now)


def test_revoked_issuer_blocks_admission_before_any_success(prepared, now):
    request, artifact, evidence = prepared
    authority = Mock(side_effect=ContractError("revoked"))
    service = SandboxArtifactAdmission(
        authorize=Mock(),
        authenticate_request=Mock(),
        authenticate_artifact=Mock(),
        authenticate_evidence=authority,
        clock=lambda: now,
    )
    with pytest.raises(ContractError, match="revoked"):
        service.assess(
            "reviewer",
            request,
            artifact,
            evidence,
            policy_digest="1" * 64,
            environment_digest="2" * 64,
        )
    assert authority.call_count == 1


def test_image_repository_alias_does_not_hide_identical_agent_and_verifier_bytes(
    prepared,
):
    request, _, _ = prepared
    with pytest.raises(ContractError, match="digests must differ"):
        replace(
            request,
            verifier_image="another-repository@sha256:"
            + request.agent_image.rsplit("@sha256:", 1)[1],
        )


@pytest.mark.parametrize(
    "change",
    [
        {"timeout_seconds": 121},
        {"agent_image": "other@sha256:" + "9" * 64},
        {"verifier_image": "other@sha256:" + "8" * 64},
    ],
)
def test_complete_request_change_invalidates_previously_verified_artifact(
    prepared, now, change
):
    request, artifact, evidence = prepared
    with pytest.raises(ContractError, match="complete original request"):
        assess((replace(request, **change), artifact, evidence), now)
