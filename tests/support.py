"""Test-only fake boundary and permit builders; never live authorization."""

from dataclasses import replace
from sova.domain.contracts import (
    EffectObservation,
    EffectStatus,
    ExecutionPermit,
    canonical_json,
)


def permit_for(command, **changes):
    return replace(
        ExecutionPermit(
            command.scope,
            command.operation_id,
            command.plan_digest,
            command.fingerprint,
            command.fencing_epoch,
            command.expires_at,
        ),
        **changes,
    )


class IngressAdapter:
    adapter_id = "test-ingress"

    def __init__(self):
        self.blocked = False
        self.calls = []
        self.reads = 0
        self.before_apply = None
        self.after_apply = None
        self.before_read = None

    def validate(self, command):
        from sova.domain.contracts import ContractError

        if command.action != "set_ingress" or set(command.parameters) != {"blocked"}:
            raise ContractError("Unregistered action or parameters")
        if type(command.parameters["blocked"]) is not bool:
            raise ContractError("Boolean blocked value required")

    def apply(self, command):
        if self.before_apply:
            self.before_apply(command)
        self.calls.append(command.fingerprint)
        self.blocked = command.parameters["blocked"]
        if self.after_apply:
            self.after_apply(command)

    def readback(self, command, now):
        self.reads += 1
        if self.before_read:
            self.before_read(command)
        return EffectObservation(
            command.scope,
            command.fingerprint,
            EffectStatus.APPLIED
            if self.blocked == command.parameters["blocked"]
            else EffectStatus.UNKNOWN,
            now,
            canonical_json({"blocked": self.blocked}),
        )
