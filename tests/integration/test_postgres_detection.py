"""Real signed detection admission and PG holds; controlled normalized fixtures."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import pytest

from security_patch_support import signed_input_authority
from sova_security.adapters.team_detection import import_detection
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_governance import PostgresSecurityHolds
from sova_security.application.detection import DetectionAdmission
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import RevisionSet
from sova_security.domain.detection import DetectionRegistration

pytestmark = pytest.mark.postgres


@pytest.fixture
def detection(postgres_bundle):
    lifecycle, plan, *_ = postgres_bundle
    scope = plan.steps[0].scope
    now = datetime.now(UTC)
    r = DetectionRegistration(
        scope,
        "falco",
        "onprem",
        "registered-cluster",
        "local",
        "pod-uid-owned",
        "r1",
        300,
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    ms = int(now.timestamp() * 1000)
    document = {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_id": 1,
        "type_uid": 200401,
        "severity_id": 4,
        "status_id": 1,
        "time": ms,
        "finding_info": {
            "uid": "controlled-one",
            "title": "Synthetic integration; not actual attack",
        },
        "metadata": {"version": "1.1.0", "product": {"name": "Falco"}},
        "cloud": {"provider": "onprem"},
        "resources": [{"type": "Pod", "uid": r.resource_uid}],
        "bravo": {
            "source": "falco",
            "environment_id": scope.environment_id,
            "category": "THREAT",
            "control_ids": [],
            "raw_sha256": "sha256:" + "a" * 64,
            "collected_time": ms,
        },
    }

    def parse():
        return import_detection(
            json.dumps(document).encode(),
            registration=r,
            collected_resource_uid=r.resource_uid,
            collected_resource_revision=r.resource_revision,
            now=datetime.now(UTC),
        )

    observation = parse()

    def clock():
        return datetime.now(UTC)

    auth, revoke = signed_input_authority(
        lifecycle.connect,
        scope,
        (r, observation),
        revisions=RevisionSet("a" * 64, "b" * 64, "c" * 64, "d" * 64),
        clock=clock,
    )
    artifacts = PostgresSecurityArtifacts(lifecycle.connect, tenant_id=scope.tenant_id)
    holds = PostgresSecurityHolds(lifecycle.connect, tenant_id=scope.tenant_id)
    service = DetectionAdmission(
        current_registration=lambda *_: r,
        authenticate_registration=lambda value: auth("detector", scope, value),
        authenticate_observation=lambda value: auth("detector", scope, value),
        artifacts=artifacts,
        holds=holds,
        authorize=lambda *_: None,
        clock=clock,
    )
    return service, observation, revoke


def test_signed_detection_creates_durable_deduplicated_hold_and_immutable_artifact(
    detection,
):
    service, observation, _ = detection
    service.admit("detector", observation)
    service.admit("detector", observation)
    assert len(service.holds.active_holds(observation.scope.application_id)) == 1
    assert (
        service.artifacts.get(observation.scope, observation.fingerprint).value
        == observation
    )
    restarted = PostgresSecurityHolds(
        service.artifacts.transactions.connect, tenant_id=observation.scope.tenant_id
    )
    assert restarted.active_holds(
        observation.scope.application_id
    ) == service.holds.active_holds(observation.scope.application_id)


def test_revoked_detector_key_cannot_create_hold(detection):
    service, observation, revoke = detection
    revoke("detection-observation.v1")
    with pytest.raises(ContractError):
        service.admit("detector", observation)
    assert not service.holds.active_holds(observation.scope.application_id)


def test_altered_typed_detection_cannot_reuse_collection_signature(detection):
    service, observation, _ = detection
    with pytest.raises((ContractError, KeyError)):
        service.admit("detector", replace(observation, signal="coverage-observed"))
    assert not service.holds.active_holds(observation.scope.application_id)
