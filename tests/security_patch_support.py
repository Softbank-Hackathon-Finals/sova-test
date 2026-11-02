"""Rebind synthetic patch contracts to an isolated test tenant and clock."""

from dataclasses import fields, is_dataclass, replace
from datetime import datetime
import json
from pathlib import Path

from sova_security.adapters.modernization_codec import decode
from sova_security.contracts.commands import ResourceScope
from sova_security.domain.assessment import assess_risk
from sova_security.domain.patch_reassessment import reassess_patch


def patch_bundle(scope, now):
    data = json.loads(
        (
            Path(__file__).parent / "fixtures/security/synthetic-patch-v1.json"
        ).read_text()
    )

    def restore(value):
        return decode(json.dumps(value).encode())

    originals = tuple(restore(v) for v in data["inputs"])
    delta = now - originals[0].observed_at

    def shift(value):
        if isinstance(value, datetime):
            return value + delta
        if isinstance(value, ResourceScope):
            return scope
        if type(value) is tuple:
            return tuple(shift(v) for v in value)
        if is_dataclass(value):
            return replace(
                value, **{f.name: shift(getattr(value, f.name)) for f in fields(value)}
            )
        return value

    inventory, scan, exposure, policy = tuple(shift(v) for v in originals)
    scan = replace(scan, inventory_digest=inventory.fingerprint)
    exposure = replace(exposure, inventory_digest=inventory.fingerprint)
    inputs = (inventory, scan, exposure, policy)
    assessment = assess_risk(*inputs, now=now)
    request = shift(restore(data["request"]))
    proposal = replace(
        request.proposal,
        assessment_digest=assessment.fingerprint,
        inventory_digest=inventory.fingerprint,
        policy_digest=policy.fingerprint,
        findings=(assessment.decisions[0].fingerprint,),
    )
    request = replace(
        request,
        proposal=proposal,
        targets=(replace(request.targets[0], snapshot_digest=inventory.fingerprint),),
    )
    receipt = shift(restore(data["receipt"]))
    receipt = replace(
        receipt,
        request_digest=request.fingerprint,
        proposal_digest=proposal.fingerprint,
    )
    return inputs, assessment, request, receipt


def patch_rescan(inputs, baseline, proposal, artifact, at):
    """Synthetic fixed-package observations, not a real scanner invocation."""
    inventory = replace(
        inputs[0],
        source_digest=artifact.source_digest,
        image_digest=artifact.image_digest,
        configuration_digest=artifact.configuration_digest,
        resource_revision="resource-v2",
        observed_at=at,
        components=(replace(inputs[0].components[0], version="1.1"),),
    )
    scan = replace(
        inputs[1],
        inventory_digest=inventory.fingerprint,
        image_digest=inventory.image_digest,
        findings=(),
        observed_at=at,
    )
    exposure = replace(
        inputs[2],
        inventory_digest=inventory.fingerprint,
        resource_revision=inventory.resource_revision,
        observed_at=at,
    )
    after = (inventory, scan, exposure, inputs[3])
    result, assessment = reassess_patch(
        proposal,
        artifact,
        baseline,
        before_inputs=inputs,
        after_inputs=after,
        expected_policy_digest=inputs[3].fingerprint,
        not_before=at,
        now=at,
    )
    return result, assessment, after


def signed_input_authority(connect, scope, values, *, revisions, clock):
    """Real scoped PG keys/envelopes for tests; synthetic source observations."""
    from datetime import timedelta
    from uuid import uuid4
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sova_security.adapters.assessment_evidence import (
        AssessmentInputAuthority,
        assessment_input_record,
    )
    from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
    from sova_security.adapters.modernization_codec import kind_of
    from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
    from sova_security.adapters.postgres_verifier_registry import (
        PostgresVerifierRegistry,
    )
    from sova_security.domain.signed_evidence import VerifierTrust
    from sova_security.domain.verifier_registry import VerifierTrustChange

    signed = PostgresSignedEvidence(connect, tenant_id=scope.tenant_id)
    registry = PostgresVerifierRegistry(
        connect, tenant_id=scope.tenant_id, application_id=scope.application_id
    )
    identifiers, issuers, changes = {}, {}, {}
    for value in values:
        kind = kind_of(value)
        signer = Ed25519EvidenceSigner(
            Ed25519PrivateKey.generate(),
            issuer_id="input-" + uuid4().hex,
            key_id="test-only-key",
        )
        record = assessment_input_record(
            value, revisions=revisions, evidence_id="input-" + uuid4().hex
        )
        now = clock()
        trust = VerifierTrust(
            signer.issuer_id,
            signer.key_id,
            signer.public_key_hex,
            (scope,),
            (record.verifier_version,),
            record.observed_at - timedelta(seconds=1),
            record.valid_until + timedelta(minutes=1),
        )
        change = VerifierTrustChange(
            scope.tenant_id,
            scope.application_id,
            1,
            trust,
            "input-key-requester",
            "input-key-approver",
            "isolated-test-registration",
            now,
            now + timedelta(minutes=1),
        )
        registry.publish(change)
        signed.save_envelope(signer.sign(record, issued_at=clock()))
        identifiers[value.fingerprint] = record.evidence_id
        issuers[kind] = (signer.issuer_id,)
        changes[kind] = change
    authority = AssessmentInputAuthority(
        envelope_provider=lambda actor, subject, value: signed.get_envelope(
            subject.application_id, identifiers[value.fingerprint]
        ),
        current_revisions=lambda _: revisions,
        issuers_for=lambda subject, kind: issuers[kind],
        resolve_trust=registry.resolve,
        authorize=lambda *_: None,
        clock=clock,
    )

    def revoke(kind):
        change = changes[kind]
        now = clock()
        registry.publish(
            replace(
                change,
                revision=2,
                trust=replace(change.trust, revoked=True),
                reason="controlled-test-revocation",
                approved_at=now,
                approval_until=now + timedelta(minutes=1),
            )
        )

    return authority, revoke
