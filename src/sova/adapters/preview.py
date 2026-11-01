"""Bind legacy preview boundaries to public, typed effect commands.

These adapters do not import the preview server, AWS SDK, or cloud credentials.
They are qualified only as a single-operator preview bridge.
"""

from datetime import datetime
from typing import Callable, Protocol

from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    EffectObservation,
    EffectStatus,
    ResourceScope,
    canonical_json,
)


class IngressBoundary(Protocol):
    def read(self) -> dict: ...
    def set_blocked(self, blocked: bool) -> dict: ...


class PreviewIngressAdapter:
    adapter_id = "preview.registered-ingress.v1"

    def __init__(self, scope: ResourceScope, boundary: IngressBoundary):
        self.scope, self.boundary = scope, boundary

    def validate(self, command: EffectCommand) -> None:
        if (
            command.scope != self.scope
            or command.adapter_id != self.adapter_id
            or command.action != "set_ingress"
            or set(command.parameters) != {"blocked"}
            or type(command.parameters["blocked"]) is not bool
        ):
            raise ContractError("Unregistered ingress command")

    def apply(self, command: EffectCommand) -> None:
        self.validate(command)
        self.boundary.set_blocked(command.parameters["blocked"])

    def readback(self, command: EffectCommand, now: datetime) -> EffectObservation:
        self.validate(command)
        observed = self.boundary.read()
        # Only allowlisted public facts enter the durable journal.
        if (
            type(observed.get("blocked")) is not bool
            or observed.get("binding_verified") is not True
            or observed.get("task_running") is not True
        ):
            raise ContractError("Ingress readback did not verify its owned resource")
        facts = {
            k: observed[k] for k in ("blocked", "binding_verified", "task_running")
        }
        facts["scope"] = "Sova 전용 AWS 앱 TCP8443 유입만"
        return EffectObservation(
            self.scope,
            command.fingerprint,
            EffectStatus.APPLIED
            if observed["blocked"] == command.parameters["blocked"]
            else EffectStatus.UNKNOWN,
            now,
            canonical_json(facts),
        )


class PreviewRouteAdapter:
    adapter_id = "preview.local-route.v1"

    def __init__(
        self,
        scope: ResourceScope,
        *,
        read: Callable[[], dict],
        apply: Callable[[str, int, str], None],
    ):
        self.scope, self.read, self.set_route = scope, read, apply

    def validate(self, command: EffectCommand) -> None:
        if (
            command.scope != self.scope
            or command.adapter_id != self.adapter_id
            or command.action != "set_route"
            or set(command.parameters) != {"environment"}
            or type(command.parameters["environment"]) is not str
            or command.parameters["environment"] not in {"aws", "vm"}
            or not command.expected_revision.isascii()
            or not command.expected_revision.isdecimal()
            or int(command.expected_revision) < 1
            or str(int(command.expected_revision)) != command.expected_revision
        ):
            raise ContractError("Unregistered route command")

    def apply(self, command: EffectCommand) -> None:
        self.validate(command)
        self.set_route(
            command.parameters["environment"],
            int(command.expected_revision),
            command.fingerprint,
        )

    def readback(self, command: EffectCommand, now: datetime) -> EffectObservation:
        self.validate(command)
        observed = self.read()
        matched = (
            observed.get("environment") == command.parameters["environment"]
            and observed.get("revision") == int(command.expected_revision) + 1
            and observed.get("last_effect_digest") == command.fingerprint
        )
        return EffectObservation(
            self.scope,
            command.fingerprint,
            EffectStatus.APPLIED if matched else EffectStatus.UNKNOWN,
            now,
            canonical_json(
                {
                    "observed_route": observed.get("environment"),
                    "route_revision": observed.get("revision"),
                    "effect_marker_verified": matched,
                    "scope": "로컬 테스트 게이트웨이 · ALB/DNS 변경 아님",
                }
            ),
        )
