from dataclasses import replace
from datetime import UTC, datetime, timedelta
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sova.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova.application.signed_evidence import SignedEvidenceAuthority
from sova.domain.signed_evidence import VerifierTrust
from sova.domain.evidence import EvidenceRecord, VerificationResult
from sova.domain.contracts import ContractError
from sova.ports.plans import RepositoryConflict, RecordNotFound

pytestmark = pytest.mark.postgres


@pytest.fixture
def setup(postgres_bundle, now):
    repo, plan, _, inspection, obligation = postgres_bundle
    evidence = EvidenceRecord(
        "signed-record",
        obligation.obligation_id,
        inspection.scope,
        plan.revisions,
        obligation.verifier_version,
        now,
        now + timedelta(minutes=5),
        VerificationResult.PASS,
        "report",
        "a" * 64,
    )
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id="verifier", key_id="key-1"
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (inspection.scope,),
        (obligation.verifier_version,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
    )
    storage = PostgresSignedEvidence(repo.connect, tenant_id=repo.tenant_id)
    current = [trust]
    authority = SignedEvidenceAuthority(
        storage,
        Ed25519EvidenceVerifier(lambda *_: current[0]),
        clock=lambda: datetime.now(UTC),
    )
    return repo, evidence, signer, storage, current, authority


def test_signed_evidence_persists_and_reauthenticates_after_restart(setup, now):
    repo, record, signer, storage, current, authority = setup
    envelope = signer.sign(record, issued_at=now)
    authority.ingest(envelope)
    authority.ingest(envelope)
    restarted = PostgresSignedEvidence(repo.connect, tenant_id=repo.tenant_id)
    assert (
        restarted.get_envelope(record.scope.application_id, record.evidence_id)
        == envelope
    )
    assert authority.authenticate(record) == record
    current[0] = replace(current[0], revoked=True)
    with pytest.raises(ContractError):
        authority.authenticate(record)


def test_bad_signature_never_enters_store_and_record_id_cannot_be_resigned(setup, now):
    _, record, signer, storage, _, authority = setup
    envelope = signer.sign(record, issued_at=now)
    with pytest.raises(ContractError):
        authority.ingest(replace(envelope, signature_hex="0" * 128))
    with pytest.raises(RecordNotFound):
        storage.get_envelope(record.scope.application_id, record.evidence_id)
    authority.ingest(envelope)
    changed = signer.sign(replace(record, artifact_digest="f" * 64), issued_at=now)
    with pytest.raises(RepositoryConflict):
        authority.ingest(changed)
    assert authority.authenticate(record) == record


def test_signed_evidence_cannot_cross_tenant_or_expected_record(setup, now):
    repo, record, signer, storage, _, authority = setup
    authority.ingest(signer.sign(record, issued_at=now))
    other = PostgresSignedEvidence(repo.connect, tenant_id="different-tenant")
    with pytest.raises(RecordNotFound):
        other.get_envelope(record.scope.application_id, record.evidence_id)
    with pytest.raises(ContractError):
        authority.authenticate(replace(record, artifact_digest="0" * 64))
