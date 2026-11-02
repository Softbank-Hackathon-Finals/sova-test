from typing import Protocol
from sova.security.domain.signed_evidence import EvidenceEnvelope


class SignedEvidenceRepository(Protocol):
    tenant_id: str

    def save_envelope(self, envelope: EvidenceEnvelope) -> None: ...
    def get_envelope(
        self, application_id: str, evidence_id: str
    ) -> EvidenceEnvelope: ...
