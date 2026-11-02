from dataclasses import replace
from datetime import timedelta
import pytest
from security_support import security_snapshot
from sova.domain.contracts import ContractError
from sova.domain.evidence import VerificationResult
from sova.domain.posture import FindingBasis
from sova.application.protection_projection import (
    compare_configuration,
    CONFIGURATION_OBJECTIVES,
)
from sova.adapters.kubernetes.posture import RULES


def collected(scope, now):
    snapshot = security_snapshot(scope, now)
    return replace(snapshot, graph=replace(snapshot.graph, origin="kubernetes_api"))


def compare(a, b, now):
    return compare_configuration(
        a, b, source_node="deployment:api", target_node="deployment:api", now=now
    )


def test_only_registered_actual_configuration_is_compared_without_granting_permit(
    scope, now
):
    a = collected(scope, now)
    b = collected(replace(scope, environment_id="target"), now)
    report = compare(a, b, now)
    assert report["accepted"] and len(report["requirements"]) == 12
    assert (
        report["execution_authority"] is False
        and report["basis"] == "configuration_only"
    )
    assert "encryption" in report["unverified"] and "audit" in report["unverified"]
    assert {k: v[0] for k, v in CONFIGURATION_OBJECTIVES.items()} == dict(RULES)
    failed = replace(a.findings[0], result=VerificationResult.FAIL)
    changed = replace(a, findings=(failed,) + a.findings[1:])
    assert any(
        r["comparison"] == "improved" for r in compare(changed, b, now)["requirements"]
    )


def test_missing_finding_is_unverified_not_silently_omitted(scope, now):
    a = collected(scope, now)
    b = collected(replace(scope, environment_id="target"), now)
    report = compare(a, replace(b, findings=b.findings[1:]), now)
    assert not report["accepted"] and len(report["requirements"]) == 12
    assert any(r["comparison"] == "unverified" for r in report["requirements"])


def test_stale_untrusted_or_runtime_mislabelled_snapshot_rejected(scope, now):
    a = collected(scope, now)
    b = collected(replace(scope, environment_id="target"), now)
    with pytest.raises(ContractError):
        compare(a, b, now + timedelta(seconds=16))
    with pytest.raises(ContractError):
        compare(security_snapshot(scope, now), b, now)
    wrong = replace(a.findings[0], basis=FindingBasis.RUNTIME)
    with pytest.raises(ContractError):
        compare(replace(a, findings=(wrong,) + a.findings[1:]), b, now)
