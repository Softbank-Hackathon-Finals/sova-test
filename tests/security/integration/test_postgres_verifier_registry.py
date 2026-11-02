"""Real registry CAS/RLS and separate read-only verifier role; local test keys."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4
import psycopg
from psycopg import sql
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from protection_support import protection_bundle
from sova.adapters.postgres_verifier_registry import PostgresVerifierRegistry
from sova.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova.application.signed_evidence import SignedEvidenceAuthority
from sova.domain.signed_evidence import VerifierTrust
from sova.domain.verifier_registry import VerifierTrustChange
from sova.domain.contracts import ContractError
from sova.ports.plans import RepositoryConflict, RecordNotFound

pytestmark = pytest.mark.postgres


@pytest.fixture
def registry(postgres_bundle, now):
    lifecycle = postgres_bundle[0]
    scope = postgres_bundle[3].scope
    _, records, *_ = protection_bundle(scope, now)
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id="verifier", key_id="k1"
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (records[0].scope,),
        (records[0].verifier_version,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    change = VerifierTrustChange(
        scope.tenant_id,
        scope.application_id,
        1,
        trust,
        "security-requester",
        "security-approver",
        "Register exact app verifier",
        now,
        now + timedelta(minutes=1),
    )
    repo = PostgresVerifierRegistry(
        lifecycle.connect,
        tenant_id=scope.tenant_id,
        application_id=scope.application_id,
    )
    return lifecycle, repo, change, signer, records[0]


def test_trust_survives_restart_and_revocation_invalidates_previously_signed_pass(
    registry,
):
    lifecycle, repo, change, signer, record = registry
    repo.publish(change)
    restarted = PostgresVerifierRegistry(
        lifecycle.connect, tenant_id=repo.tenant_id, application_id=repo.application_id
    )
    signed = SignedEvidenceAuthority(
        PostgresSignedEvidence(lifecycle.connect, tenant_id=repo.tenant_id),
        Ed25519EvidenceVerifier(restarted.resolve),
        clock=lambda: datetime.now(UTC),
    )
    signed.ingest(signer.sign(record, issued_at=record.observed_at))
    assert signed.authenticate(record) == record
    revoke = replace(change, revision=2, trust=replace(change.trust, revoked=True))
    repo.publish(revoke)
    with pytest.raises(ContractError, match="revoked"):
        signed.authenticate(record)
    with pytest.raises(ContractError, match="reactivated"):
        repo.publish(replace(change, revision=3))
    assert restarted.latest(signer.issuer_id, signer.key_id) == revoke


def test_concurrent_changes_cas_and_key_material_cannot_change_in_place(registry):
    _, repo, change, *_ = registry
    repo.publish(change)

    def publish(seconds):
        next_change = replace(
            change,
            revision=2,
            trust=replace(
                change.trust,
                valid_until=change.trust.valid_until + timedelta(seconds=seconds),
            ),
        )
        try:
            repo.publish(next_change)
            return "published"
        except RepositoryConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(publish, [1, 2]))
    assert sorted(results) == ["conflict", "published"]
    current = repo.latest(change.trust.issuer_id, change.trust.key_id)
    with pytest.raises(ContractError, match="new key ID"):
        repo.publish(
            replace(
                current,
                revision=3,
                trust=replace(current.trust, public_key_hex="f" * 64),
            )
        )


def test_unknown_cross_app_and_cross_tenant_are_not_resolved(registry):
    lifecycle, repo, change, *_ = registry
    repo.publish(change)
    for tenant, app in [(repo.tenant_id, "other"), ("other", repo.application_id)]:
        other = PostgresVerifierRegistry(
            lifecycle.connect, tenant_id=tenant, application_id=app
        )
        with pytest.raises(RecordNotFound):
            other.resolve(change.trust.issuer_id, change.trust.key_id)
    with lifecycle.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.verifier_trust_events"
        ).fetchone() == (0,)
        conn.execute("SELECT set_config('sova.tenant_id',%s,true)", (repo.tenant_id,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute("UPDATE sova_control.verifier_trust_events SET document='{}'")


def test_verifier_role_can_read_trust_but_cannot_enroll_its_own_key(
    registry, postgres_database
):
    lifecycle, repo, change, *_ = registry
    repo.publish(change)
    dsn, _ = postgres_database
    role = "sova_verifier_reader_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        admin.execute(
            sql.SQL("GRANT SELECT ON sova_control.verifier_trust_events TO {}").format(
                sql.Identifier(role)
            )
        )
    try:

        def connect():
            return psycopg.connect(dsn, user=role)

        reader = PostgresVerifierRegistry(
            connect, tenant_id=repo.tenant_id, application_id=repo.application_id
        )
        assert (
            reader.resolve(change.trust.issuer_id, change.trust.key_id) == change.trust
        )
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.publish(
                replace(change, revision=2, trust=replace(change.trust, revoked=True))
            )
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
