from dataclasses import replace
from datetime import timedelta
from unittest.mock import Mock

import pytest

from sova.application.migration_readiness import MigrationReadinessService
from sova.domain.contracts import ContractError, ResourceScope
from sova.domain.evidence import EvidenceRecord, Gate, RevisionSet, VerificationResult
from sova.domain.migration_program import MigrationArea, six_area_program


@pytest.fixture
def program(scope, now):
    return six_area_program(
        scope,
        ResourceScope(scope.tenant_id, scope.application_id, "target", "target-unit"),
        RevisionSet(*("a" * 64, "b" * 64, "c" * 64, "d" * 64)),
        issued_at=now - timedelta(minutes=1),
        valid_until=now + timedelta(minutes=10),
    )


def records(program, now):
    return tuple(
        EvidenceRecord(
            f"e-{i}",
            r.obligation.obligation_id,
            r.obligation.scope,
            program.revisions,
            r.obligation.verifier_version,
            now - timedelta(seconds=1),
            now + timedelta(minutes=3),
            VerificationResult.PASS,
            f"artifact-{i}",
            "e" * 64,
        )
        for i, r in enumerate(program.requirements)
    )


def test_empty_evidence_blocks_all_six_areas(program, now):
    report = program.assess((), Gate.PREFLIGHT, now=now)
    assert len(report["areas"]) == 6
    assert sum(len(a["requirements"]) for a in report["areas"]) == 24
    assert not report["gate_accepted"] and not report["all_areas_verified"]
    assert not report["execution_authorized"]
    assert len(report["carry_forward"]) == 2


def test_early_gate_does_not_claim_full_migration(program, now):
    evidence = tuple(
        e for e in records(program, now) if e.obligation_id == "governance:ownership"
    )
    report = program.assess(evidence, Gate.REGISTRATION, now=now)
    assert report["gate_accepted"] and not report["all_areas_verified"]
    assert len(report["carry_forward"]) == 23


def test_complete_evidence_still_never_authorizes_execution(program, now):
    result = program.assess(records(program, now), Gate.POSTFLIGHT, now=now)
    assert result["gate_accepted"] and result["all_areas_verified"]
    assert result["execution_authorized"] is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("verifier_version", "configuration-only"),
        ("revisions", RevisionSet(*("f" * 64,) * 4)),
        ("valid_until", None),
        ("result", VerificationResult.FAIL),
    ],
)
def test_wrong_stale_or_failing_evidence_cannot_satisfy_program(
    program, now, field, value
):
    evidence = list(records(program, now))
    if field == "valid_until":
        value = now
    evidence[0] = replace(evidence[0], **{field: value})
    assert not program.assess(tuple(evidence), Gate.POSTFLIGHT, now=now)[
        "all_areas_verified"
    ]


def test_minimum_catalog_cannot_be_omitted_or_moved_to_later_gate(program):
    with pytest.raises(ContractError, match="minimum"):
        replace(program, requirements=program.requirements[1:])
    altered = replace(
        program.requirements[0],
        obligation=replace(
            program.requirements[0].obligation, due_gate=Gate.POSTFLIGHT
        ),
    )
    with pytest.raises(ContractError, match="minimum"):
        replace(program, requirements=(altered, *program.requirements[1:]))
    assert set(r.area for r in program.requirements) == set(MigrationArea)


def test_expired_program_and_cross_tenant_target_rejected(program, now):
    with pytest.raises(ContractError, match="expired"):
        program.assess((), Gate.REGISTRATION, now=now + timedelta(hours=1))
    with pytest.raises(ContractError, match="same application"):
        replace(program, target_scope=replace(program.target_scope, tenant_id="other"))


def test_authority_rejection_happens_before_readiness_success(program, now):
    authenticate = Mock(side_effect=ContractError("revoked issuer"))
    service = MigrationReadinessService(
        program_provider=lambda _: program,
        evidence_provider=lambda _: records(program, now),
        authorize=Mock(),
        authenticate_program=Mock(),
        authenticate_evidence=authenticate,
        clock=lambda: now,
    )
    with pytest.raises(ContractError, match="revoked"):
        service.assess("operator", program.source_scope, Gate.POSTFLIGHT)
    assert authenticate.call_count == 1


def test_source_access_does_not_authorize_reading_target_evidence(program, now):
    provider = Mock(return_value=())

    def authorize(actor, scope, action):
        if scope == program.target_scope:
            raise PermissionError("target denied")

    service = MigrationReadinessService(
        program_provider=lambda _: program,
        evidence_provider=provider,
        authorize=authorize,
        authenticate_program=Mock(),
        authenticate_evidence=Mock(),
        clock=lambda: now,
    )
    with pytest.raises(PermissionError):
        service.assess("operator", program.source_scope, Gate.PREFLIGHT)
    provider.assert_not_called()
