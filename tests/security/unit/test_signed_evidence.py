from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from governance_support import bundle
from sova.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova.adapters.signed_evidence_codec import decode_envelope
from sova.domain.contracts import ContractError
from sova.domain.signed_evidence import VerifierTrust
from sova.domain.evidence import VerificationResult


@pytest.fixture
def signed(scope, now):
    record = bundle(scope, now)[3]
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(), issuer_id="registered-verifier", key_id="key-1"
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (record.verifier_version,),
        now - timedelta(minutes=1),
        now + timedelta(minutes=10),
    )
    envelope = signer.sign(record, issued_at=now)
    return record, signer, trust, envelope


def test_real_ed25519_roundtrip_and_exact_record_authentication(signed, now):
    record, _, trust, envelope = signed
    assert decode_envelope(envelope.document) == envelope
    assert (
        Ed25519EvidenceVerifier(lambda *_: trust).verify(
            envelope, expected_record=record, now=now
        )
        == record
    )
    assert "private_key" not in str(envelope.document)


@pytest.mark.parametrize(
    "change",
    [
        "result",
        "artifact",
        "scope",
        "revision",
        "signature",
        "issuer",
        "key",
        "verifier",
    ],
)
def test_tampering_scope_escalation_and_reuse_are_refused(signed, now, change):
    record, _, trust, envelope = signed
    if change == "result":
        record = replace(record, result=VerificationResult.FAIL)
    if change == "artifact":
        record = replace(record, artifact_digest="0" * 64)
    if change == "scope":
        record = replace(record, scope=replace(record.scope, application_id="other"))
    if change == "revision":
        record = replace(
            record, revisions=replace(record.revisions, environment="0" * 64)
        )
    if change == "verifier":
        record = replace(record, verifier_version="release-everything-v1")
    envelope = replace(envelope, evidence=record)
    if change == "signature":
        envelope = replace(envelope, signature_hex="0" * 128)
    if change == "issuer":
        envelope = replace(envelope, issuer_id="unregistered")
    if change == "key":
        envelope = replace(envelope, key_id="attacker-key")
    with pytest.raises(ContractError):
        Ed25519EvidenceVerifier(lambda *_: trust).verify(
            envelope, expected_record=record, now=now
        )


def test_trust_revocation_is_reloaded_on_every_verification(signed, now):
    record, _, trust, envelope = signed
    current = [trust]
    verifier = Ed25519EvidenceVerifier(lambda *_: current[0])
    verifier.verify(envelope, expected_record=record, now=now)
    current[0] = replace(trust, revoked=True)
    with pytest.raises(ContractError):
        verifier.verify(envelope, expected_record=record, now=now)


@pytest.mark.parametrize(
    "case",
    ["key-expiry", "record-expiry", "future-issued", "before-trust", "expected-record"],
)
def test_expiry_future_and_record_binding_are_fail_closed(signed, now, case):
    record, _, trust, envelope = signed
    checked = now
    if case == "key-expiry":
        trust = replace(trust, valid_until=now)
    if case == "record-expiry":
        checked = record.valid_until
    if case == "future-issued":
        envelope = replace(envelope, issued_at=now + timedelta(seconds=1))
    if case == "before-trust":
        trust = replace(trust, valid_from=now + timedelta(seconds=1))
    if case == "expected-record":
        record = replace(record, artifact_digest="f" * 64)
    with pytest.raises(ContractError):
        Ed25519EvidenceVerifier(lambda *_: trust).verify(
            envelope, expected_record=record, now=checked
        )


@pytest.mark.parametrize(
    "change",
    [
        {"algorithm": "none"},
        {"public_key": "attacker-provided"},
        {"schema_version": True},
        {"signature": "aa"},
    ],
)
def test_untrusted_algorithm_or_key_fields_not_accepted(signed, change):
    data = deepcopy(signed[3].document)
    data.update(change)
    with pytest.raises(ContractError):
        decode_envelope(data)


def test_record_validity_cannot_extend_beyond_issuer_authorization(signed, now):
    record, _, trust, envelope = signed
    trust = replace(trust, valid_until=now + timedelta(seconds=1))
    with pytest.raises(ContractError):
        Ed25519EvidenceVerifier(lambda *_: trust).verify(
            envelope, expected_record=record, now=now
        )


def test_unregistered_trust_does_not_fall_back_to_envelope_key(signed, now):
    record, _, _, envelope = signed
    with pytest.raises(ContractError):
        Ed25519EvidenceVerifier(lambda *_: None).verify(
            envelope, expected_record=record, now=now
        )
