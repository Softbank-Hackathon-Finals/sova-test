"""Real PG + Ed25519 + existing risk/hold engine; observations are fixtures."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_patch_support import patch_bundle
from sova.adapters.postgres_monitoring import PostgresMonitorRepository
from sova.monitoring.contracts import MonitorRegistration, MonitorInputSet
from sova.monitoring.authority import SignedMonitorAuthority, monitoring_record
from sova.monitoring.composition import RegisteredMonitoring
from sova.domain.contracts import ContractError
from sova_security.adapters.assessment_evidence import (
    AssessmentInputAuthority,
    assessment_input_record,
)
from sova_security.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_governance import PostgresSecurityHolds
from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
from sova_security.adapters.modernization_codec import kind_of
from sova_security.application.signed_evidence import SignedEvidenceAuthority
from sova_security.contracts.evidence import RevisionSet
from sova_security.domain.continuous_security import RuntimeSecurityBaseline
from sova_security.domain.remediation import TestedArtifact as Artifact
from sova_security.domain.signed_evidence import VerifierTrust
from sova_security.domain.verifier_registry import VerifierTrustChange

pytestmark = pytest.mark.postgres


@pytest.fixture
def composition(postgres_bundle):
    lifecycle, plan, *_ = postgres_bundle
    scope = plan.steps[0].scope
    now = datetime.now(UTC) - timedelta(seconds=2)

    def clock():
        return datetime.now(UTC)

    inputs, assessment, *_ = patch_bundle(scope, now)
    baseline = RuntimeSecurityBaseline(
        scope,
        "e" * 64,
        Artifact(
            scope,
            inputs[0].image_digest,
            inputs[0].source_digest,
            inputs[0].configuration_digest,
            "f" * 64,
        ),
        inputs[0].resource_revision,
        assessment,
        now + timedelta(seconds=1),
        now + timedelta(hours=1),
    )
    r = MonitorRegistration(
        scope,
        "monitor-api",
        "service-monitor",
        baseline.fingerprint,
        60,
        now + timedelta(seconds=1),
        now + timedelta(hours=1),
    )
    revisions = RevisionSet(
        inputs[0].source_digest,
        inputs[0].configuration_digest,
        inputs[3].fingerprint,
        "f" * 64,
    )
    repository = PostgresMonitorRepository(lifecycle)
    artifacts = PostgresSecurityArtifacts(lifecycle.connect, tenant_id=scope.tenant_id)
    holds = PostgresSecurityHolds(lifecycle.connect, tenant_id=scope.tenant_id)
    registry = PostgresVerifierRegistry(
        lifecycle.connect,
        tenant_id=scope.tenant_id,
        application_id=scope.application_id,
    )
    signed = PostgresSignedEvidence(lifecycle.connect, tenant_id=scope.tenant_id)
    state = {"ids": {}, "kinds": {}, "trust": {}}

    def attest(value, monitor=False):
        record = (
            monitoring_record(value, revisions=revisions)
            if monitor
            else assessment_input_record(
                value, revisions=revisions, evidence_id="input-" + uuid4().hex
            )
        )
        signer = Ed25519EvidenceSigner(
            Ed25519PrivateKey.generate(),
            issuer_id="fixture-" + uuid4().hex,
            key_id="key",
        )
        trust = VerifierTrust(
            signer.issuer_id,
            signer.key_id,
            signer.public_key_hex,
            (scope,),
            (record.verifier_version,),
            now - timedelta(seconds=5),
            now + timedelta(hours=2),
        )
        change = VerifierTrustChange(
            scope.tenant_id,
            scope.application_id,
            1,
            trust,
            "test-requester",
            "test-approver",
            "fixture-only",
            clock(),
            clock() + timedelta(minutes=1),
        )
        registry.publish(change)
        signed.save_envelope(signer.sign(record, issued_at=clock()))
        state["ids"][value.fingerprint] = record.evidence_id
        key = record.verifier_version if monitor else kind_of(value)
        state["kinds"][key] = (*state["kinds"].get(key, ()), signer.issuer_id)
        state["trust"][value.fingerprint] = change

    auth = SignedEvidenceAuthority(
        signed, Ed25519EvidenceVerifier(registry.resolve), clock=clock
    )
    monitor_auth = SignedMonitorAuthority(
        authority=auth,
        current_revisions=lambda _: revisions,
        issuers_for=lambda _, kind: state["kinds"][kind],
        authorize=lambda *_: None,
    )
    input_auth = AssessmentInputAuthority(
        envelope_provider=lambda _, subject, value: signed.get_envelope(
            subject.application_id, state["ids"][value.fingerprint]
        ),
        current_revisions=lambda _: revisions,
        issuers_for=lambda _, kind: state["kinds"][kind],
        resolve_trust=registry.resolve,
        authorize=lambda *_: None,
        clock=clock,
    )
    for value in inputs:
        artifacts.register(scope, value, actor_id="fixture-collector")
        attest(value)
    artifacts.register(scope, baseline, actor_id="fixture-release")
    attest(baseline, True)
    attest(r, True)
    repository.register(r)
    selection = MonitorInputSet(
        scope,
        r.job_id,
        1,
        None,
        *(v.fingerprint for v in inputs),
        now + timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    attest(selection, True)
    service = RegisteredMonitoring(
        repository=repository,
        artifacts=artifacts,
        holds=holds,
        authenticate_monitor_input=monitor_auth.authenticate,
        authenticate_assessment_input=input_auth,
        authorize=lambda *_: None,
        clock=clock,
    )
    service.publish_inputs("fixture-collector", selection)
    return service, r, inputs, selection, attest, state, registry, clock


def test_actual_scheduled_tick_reuses_security_engine_and_durable_review(composition):
    service, r, *_ = composition
    result = service.runner(r).run_due(r, "worker-one")
    assert result.triggers == ()
    assert service.artifacts.get(r.scope, result.fingerprint).value == result
    assert service.runner(r).run_due(r, "worker-two") is None
    assert not service.holds.active_holds(r.scope.application_id)


def test_new_authenticated_input_head_detects_drift_and_opens_hold(composition):
    service, r, inputs, selection, attest, *_ = composition
    inventory = replace(inputs[0], resource_revision="unexpected-runtime-change")
    exposure = replace(
        inputs[2],
        inventory_digest=inventory.fingerprint,
        resource_revision=inventory.resource_revision,
    )
    scan = replace(inputs[1], inventory_digest=inventory.fingerprint)
    changed = (inventory, scan, exposure, inputs[3])
    for value in changed[:3]:
        service.artifacts.register(r.scope, value, actor_id="fixture-collector")
        attest(value)
    next_set = replace(
        selection,
        revision=2,
        predecessor_digest=selection.fingerprint,
        inventory_digest=inventory.fingerprint,
        scan_digest=scan.fingerprint,
        exposure_digest=exposure.fingerprint,
    )
    attest(next_set, True)
    service.publish_inputs("fixture-collector", next_set)
    result = service.runner(r).run_due(r, "worker")
    assert "resource-revision-drift" in result.triggers
    assert service.holds.active_holds(r.scope.application_id)
    assert (
        service.repository.alerts(r.scope.application_id)[0]["category"]
        == "security_attention"
    )
    # Older signed head cannot be replayed over the newer head.
    from sova.ports.plans import RepositoryConflict

    with pytest.raises(RepositoryConflict):
        service.publish_inputs("fixture-collector", selection)


def test_revoked_baseline_key_produces_failure_alert_without_clean_result(composition):
    service, r, _, _, _, state, registry, clock = composition
    change = state["trust"][r.baseline_digest]
    registry.publish(
        replace(
            change,
            revision=2,
            trust=replace(change.trust, revoked=True),
            reason="fixture-revocation",
            approved_at=clock(),
            approval_until=clock() + timedelta(minutes=1),
        )
    )
    with pytest.raises(ContractError):
        service.runner(r).run_due(r, "worker")
    assert (
        service.repository.alerts(r.scope.application_id)[0]["category"]
        == "monitor_failed"
    )


def test_fixed_worker_cli_runs_from_private_configuration_and_records_current_review(
    composition, postgres_database, tmp_path
):
    import json
    import os
    import subprocess
    import sys
    from dataclasses import asdict
    from psycopg.conninfo import make_conninfo

    service, r, _, _, _, state, _, _ = composition
    dsn, _ = postgres_database
    import psycopg
    from psycopg import sql
    from sova.adapters.monitor_permissions import create_monitor_role

    role = "monitor_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        create_monitor_role(admin, role, r)
        admin.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(role)))
    dsn_file = tmp_path / "monitor.dsn"
    dsn_file.write_text(make_conninfo(dsn, user=role))
    dsn_file.chmod(0o600)
    first_input = service.current_inputs(r)[0]
    # The reference policy revision belongs to the fixture's signed input set.
    policy = service.current_inputs(r)[3]
    config = {
        "schema_version": 1,
        "scope": asdict(r.scope),
        "job_id": r.job_id,
        "actor_id": r.actor_id,
        "dsn_file": str(dsn_file),
        "revisions": asdict(
            RevisionSet(
                first_input.source_digest,
                first_input.configuration_digest,
                policy.fingerprint,
                "f" * 64,
            )
        ),
        "issuers": {k: list(v) for k, v in state["kinds"].items()},
    }
    path = tmp_path / "monitor.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    env = {
        **os.environ,
        "PYTHONPATH": str(__import__("pathlib").Path(__file__).parents[2] / "src"),
    }
    for expected in ("observed", "not-due"):
        result = subprocess.run(
            [sys.executable, "-m", "sova.monitoring.worker", "--config", str(path)],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, result.stdout
        assert json.loads(result.stdout)["status"] == expected
        assert dsn not in result.stdout + result.stderr


def test_monitor_database_role_cannot_release_incidents_publish_keys_or_change_other_jobs(
    composition, postgres_database
):
    import psycopg
    from psycopg import sql
    from sova.adapters.monitor_permissions import create_monitor_role
    from sova.adapters.postgres_plans import PostgresLifecycleRepository

    service, r, *_ = composition
    dsn, _ = postgres_database
    role = "monitor_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        create_monitor_role(admin, role, r)
        admin.execute(sql.SQL("ALTER ROLE {} LOGIN").format(sql.Identifier(role)))

    def connect():
        return psycopg.connect(dsn, user=role)

    repo = PostgresMonitorRepository(
        PostgresLifecycleRepository(connect, tenant_id=r.scope.tenant_id)
    )
    assert repo.get_registration(r.scope.application_id, r.job_id) == r
    assert repo.claim(r, "scope-test") is not None
    with connect() as conn:
        conn.execute(
            "SELECT set_config('sova.tenant_id',%s,true)", (r.scope.tenant_id,)
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("UPDATE sova_control.monitor_jobs SET enabled=false")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute("DELETE FROM sova_control.security_hold_events")
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute(
                    "INSERT INTO sova_control.verifier_trust_events SELECT * FROM sova_control.verifier_trust_events LIMIT 1"
                )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with conn.transaction():
                conn.execute(
                    """INSERT INTO sova_control.security_hold_events
                    (tenant_id,application_id,hold_id,revision,event_kind,digest,document)
                    VALUES(%s,%s,'forged-release',2,'released',%s,%s)""",
                    (
                        r.scope.tenant_id,
                        r.scope.application_id,
                        "a" * 64,
                        psycopg.types.json.Jsonb(
                            {
                                "hold": {
                                    "scope": {
                                        "environment_id": r.scope.environment_id,
                                        "resource_id": r.scope.resource_id,
                                    }
                                }
                            }
                        ),
                    ),
                )
        conn.execute("SELECT set_config('sova.tenant_id','another-tenant',true)")
        assert (
            conn.execute("SELECT count(*) FROM sova_control.monitor_jobs").fetchone()[0]
            == 0
        )


def test_signed_lookup_rejects_ambiguous_re_attestation(composition):
    service, r, inputs, _, attest, *_ = composition
    signed = PostgresSignedEvidence(
        service.artifacts.transactions.connect, tenant_id=r.scope.tenant_id
    )
    version = "sova.security.assessment-input.asset-inventory.v1"
    first = signed.find_envelope(
        r.scope, artifact_digest=inputs[0].fingerprint, verifier_version=version
    )
    assert first.evidence.artifact_digest == inputs[0].fingerprint
    attest(inputs[0])
    with pytest.raises(ContractError):
        signed.find_envelope(
            r.scope, artifact_digest=inputs[0].fingerprint, verifier_version=version
        )
