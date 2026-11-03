"""Concrete signed provenance for schedules and historical runtime baselines.

Reuses security's current Ed25519 trust and immutable evidence repository. These
records attest registered input identity, not that current security is healthy.
"""

from sova.domain.contracts import ContractError, identifier
from sova.monitoring.contracts import MonitorRegistration, MonitorInputSet
from sova_security.application.boundary import require_accept
from sova_security.contracts.evidence import EvidenceRecord, VerificationResult
from sova_security.domain.continuous_security import RuntimeSecurityBaseline


def monitoring_record(value, *, revisions):
    if isinstance(value, MonitorRegistration):
        kind = "schedule"
        start, end = value.registered_at, value.valid_until
    elif isinstance(value, MonitorInputSet):
        kind = "inputs"
        start, end = value.observed_at, value.valid_until
    elif isinstance(value, RuntimeSecurityBaseline):
        kind = "baseline"
        start, end = value.accepted_at, value.monitor_until
    else:
        raise ContractError("Typed monitoring provenance subject required")
    return EvidenceRecord(
        "monitor-" + value.fingerprint,
        "monitor-input:" + kind,
        value.scope,
        revisions,
        "sova.monitor-input." + kind + ".v1",
        start,
        end,
        VerificationResult.PASS,
        "monitor-input:" + value.fingerprint,
        value.fingerprint,
    )


class SignedMonitorAuthority:
    def __init__(self, *, authority, current_revisions, issuers_for, authorize):
        self.authority = authority
        self.current_revisions = current_revisions
        self.issuers_for = issuers_for
        self.authorize = authorize

    def authenticate(self, actor, value):
        scope = value.scope
        require_accept(
            self.authorize, actor, scope, "security:authenticate-monitor-input"
        )
        revisions = self.current_revisions(scope)
        record = monitoring_record(value, revisions=revisions)
        issuers = self.issuers_for(scope, record.verifier_version)
        if (
            type(issuers) is not tuple
            or not 1 <= len(issuers) <= 8
            or len(set(issuers)) != len(issuers)
        ):
            raise ContractError("Explicit bounded monitor input issuers required")
        for issuer in issuers:
            identifier(issuer)
        envelope = self.authority.repository.get_envelope(
            scope.application_id, record.evidence_id
        )
        if envelope.issuer_id not in issuers:
            raise ContractError("Monitor input signer not registered for this purpose")
        self.authority.authenticate(record)
        require_accept(
            self.authorize, actor, scope, "security:authenticate-monitor-input"
        )
        self.authority.authenticate(record)
        if (
            self.current_revisions(scope) != revisions
            or self.issuers_for(scope, record.verifier_version) != issuers
            or self.authority.repository.get_envelope(
                scope.application_id, record.evidence_id
            )
            != envelope
        ):
            raise ContractError("Monitor input authority changed during authentication")
