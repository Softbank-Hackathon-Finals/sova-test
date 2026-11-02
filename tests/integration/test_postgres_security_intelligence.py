"""Real PG/signatures for KEV -> re-attested exposure -> assessment; synthetic facts."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security_patch_support import patch_bundle, signed_input_authority
from sova_security.adapters.cisa_kev import parse_cisa_kev, catalog_evidence
from sova_security.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
from sova_security.application.assessment import AssessmentService
from sova_security.application.exploitation_intelligence import (
    ExploitationIntelligenceService,
)
from sova_security.application.signed_evidence import SignedEvidenceAuthority
from sova_security.contracts.commands import ContractError
from sova_security.contracts.evidence import RevisionSet
from sova_security.contracts.repositories import RecordNotFound
from sova_security.domain.signed_evidence import VerifierTrust
from sova_security.domain.verifier_registry import VerifierTrustChange

pytestmark = pytest.mark.postgres


def test_kev_candidate_requires_new_exposure_attestation_before_host_assessment(
    postgres_bundle,
):
    lifecycle, plan, *_ = postgres_bundle
    scope = plan.steps[0].scope
    now = datetime.now(UTC) - timedelta(seconds=1)
    inputs, *_ = patch_bundle(scope, now)
    # Explicit synthetic CVE association, not real vendor vulnerability evidence.
    scan = replace(
        inputs[1],
        findings=(replace(inputs[1].findings[0], advisory_id="CVE-2099-0001"),),
    )
    inputs = inputs[0], scan, inputs[2], inputs[3]
    revisions = RevisionSet(
        inputs[0].source_digest,
        inputs[0].configuration_digest,
        inputs[3].fingerprint,
        "f" * 64,
    )

    def clock():
        return datetime.now(UTC)

    input_authority, _ = signed_input_authority(
        lifecycle.connect,
        scope,
        inputs,
        revisions=revisions,
        clock=clock,
    )
    catalog = parse_cisa_kev(
        json.dumps(
            {
                "catalogVersion": "2026.10.30",
                "dateReleased": "2026-10-30T17:00:00Z",
                "count": 1,
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2099-0001",
                        "vendorProject": "Synthetic fixture",
                        "product": "Synthetic fixture",
                        "vulnerabilityName": "Not a real vulnerability claim",
                        "dateAdded": "2026-10-30",
                        "shortDescription": "Contract integration only",
                        "requiredAction": "Do not execute",
                        "dueDate": "2026-11-20",
                    }
                ],
            }
        ).encode(),
        source_reference="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        minimum_catalog_version="2026.10.30",
        observed_at=now,
        valid_until=now + timedelta(minutes=5),
    )
    record = catalog_evidence(
        catalog, scope=scope, revisions=revisions, evidence_id="kev-" + uuid4().hex
    )
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id="kev-" + uuid4().hex,
        key_id="test-only-key",
    )
    trust = VerifierTrust(
        signer.issuer_id,
        signer.key_id,
        signer.public_key_hex,
        (scope,),
        (record.verifier_version,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=10),
    )
    registry = PostgresVerifierRegistry(
        lifecycle.connect,
        tenant_id=scope.tenant_id,
        application_id=scope.application_id,
    )
    change = VerifierTrustChange(
        scope.tenant_id,
        scope.application_id,
        1,
        trust,
        "requester",
        "approver",
        "synthetic-collector-registration",
        now,
        now + timedelta(minutes=2),
    )
    registry.publish(change)
    signed = SignedEvidenceAuthority(
        PostgresSignedEvidence(lifecycle.connect, tenant_id=scope.tenant_id),
        Ed25519EvidenceVerifier(registry.resolve),
        clock=clock,
    )
    signed.ingest(signer.sign(record, issued_at=clock()))
    artifacts = PostgresSecurityArtifacts(lifecycle.connect, tenant_id=scope.tenant_id)
    service = ExploitationIntelligenceService(
        current_inputs=lambda _: inputs,
        catalog_provider=lambda _: (catalog, record),
        current_revisions=lambda _: revisions,
        minimum_catalog_version=lambda _: "2026.10.30",
        authenticate_input=input_authority,
        authenticate_catalog=signed.authenticate,
        authorize=lambda *_: None,
        artifacts=artifacts,
        clock=clock,
    )
    matched, candidate = service.propose("operator", scope=scope)
    assert artifacts.get(scope, matched.fingerprint).value == matched
    with pytest.raises(RecordNotFound):
        artifacts.get(scope, candidate.fingerprint)
    enriched = inputs[0], inputs[1], candidate, inputs[3]
    assessment = AssessmentService(
        authorize=lambda *_: None,
        authenticate_input=input_authority,
        current_inputs=lambda _: enriched,
        clock=clock,
    )
    expected = tuple(v.fingerprint for v in enriched)
    # Copying the proposed candidate into current inputs cannot reuse the original signature.
    with pytest.raises((ContractError, KeyError)):
        assessment.assess("operator", scope=scope, expected_inputs=expected)
    new_authority, revoke = signed_input_authority(
        lifecycle.connect,
        scope,
        enriched,
        revisions=revisions,
        clock=clock,
    )
    assessment.authenticate_input = new_authority
    result = assessment.assess("operator", scope=scope, expected_inputs=expected)
    assert result.scope == scope
    assert candidate.known_exploited == ("CVE-2099-0001",)
    revoke("exposure-observation.v1")
    with pytest.raises(ContractError, match="revoked"):
        assessment.assess("operator", scope=scope, expected_inputs=expected)
    registry.publish(replace(change, revision=2, trust=replace(trust, revoked=True)))
    with pytest.raises(ContractError):
        service.propose("operator", scope=scope)
