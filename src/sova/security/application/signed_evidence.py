"""Authentication callbacks for governance; trust is resolved on every check."""

from sova.domain.contracts import ContractError


class SignedEvidenceAuthority:
    def __init__(self, repository, verifier, *, clock):
        self.repository = repository
        self.verifier = verifier
        self.clock = clock

    def ingest(self, envelope):
        record = envelope.evidence
        if record.scope.tenant_id != self.repository.tenant_id:
            raise ContractError("Evidence authority tenant mismatch")
        self.verifier.verify(envelope, expected_record=record, now=self.clock())
        self.repository.save_envelope(envelope)
        return record

    def authenticate(self, record):
        if record.scope.tenant_id != self.repository.tenant_id:
            raise ContractError("Evidence authority tenant mismatch")
        envelope = self.repository.get_envelope(
            record.scope.application_id, record.evidence_id
        )
        return self.verifier.verify(envelope, expected_record=record, now=self.clock())
