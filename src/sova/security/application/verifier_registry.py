"""Administrative authorization is separate from issuer signature verification."""

from sova.domain.contracts import ContractError


class VerifierRegistryAdministration:
    def __init__(self, repository, *, authorize, authenticate_approval, clock):
        if any(not callable(c) for c in (authorize, authenticate_approval, clock)):
            raise ContractError("Explicit verifier administration authorities required")
        self.repository = repository
        self.authorize = authorize
        self.authenticate_approval = authenticate_approval
        self.clock = clock

    def publish(self, actor, change):
        if actor != change.requested_by or (
            change.tenant_id,
            change.application_id,
        ) != (self.repository.tenant_id, self.repository.application_id):
            raise ContractError("Verifier administration actor/scope mismatch")
        self.authorize(
            actor, change.tenant_id, change.application_id, "verifier-trust:request"
        )
        self.authenticate_approval(change)
        self.authorize(
            change.approved_by,
            change.tenant_id,
            change.application_id,
            "verifier-trust:approve",
        )
        change.require_current(self.clock())
        return self.repository.publish(change)
