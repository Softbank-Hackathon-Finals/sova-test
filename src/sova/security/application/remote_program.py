"""Consume fresh service reviews through Sova's existing program guards."""

from dataclasses import replace

from sova_security.adapters.remote_review import RemoteReviewClient
from sova_security.contracts.commands import ContractError
from sova_security.domain.review_service import ReviewRegistration
from sova_security.domain.security_program import ProgramPhase


class RemoteProgramService:
    """Host registrations must come from current authorized plan/operation state.

    The host callback maps preflight/postflight to separately registered contexts;
    postflight must pin the real operation start passed by the existing executor.
    The service does not create approvals, register contexts or apply an effect.
    """

    def __init__(self, client):
        if type(client) is not RemoteReviewClient:
            raise ContractError("Configured authenticated remote client required")
        self.client = client

    def program_for(self, scope, subject_digest):
        value = self.client.current_registration(scope, subject_digest, ProgramPhase.PREFLIGHT)
        if (type(value) is not ReviewRegistration or value.scope != scope
                or value.program.subject_digest != subject_digest or value.phase != ProgramPhase.PREFLIGHT):
            raise ContractError("Current host-bound preflight registration required")
        value.require_current(self.client.clock())
        return value.program

    def review(self, actor, *, scope, subject_digest, phase, not_before=None):
        if actor != self.client.subject_id:
            raise ContractError("Remote service principal differs from execution actor")
        result = self.client.review(scope=scope, subject_digest=subject_digest, phase=phase,
                                    mode="enforce", not_before=not_before)
        # Preserve the narrower transport/identity deadline in the existing guard.
        return replace(result.review, valid_until=min(result.review.valid_until, result.valid_until))
