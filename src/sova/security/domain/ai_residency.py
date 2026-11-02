"""AI routing admission using authenticated location facts, not model names.

An endpoint's declared locations are not proof by themselves: the application
service authenticates policy, classification and endpoint registration. This
model does not certify provider contracts or detect sensitive text by regex.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    identifier,
    utc,
)


class DataClass(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class DataPhase(StrEnum):
    PROCESSING = "processing"
    STORAGE = "storage"
    LOGGING = "logging"
    REPLICATION = "replication"
    SUPPORT_ACCESS = "support_access"


@dataclass(frozen=True, slots=True)
class LocationRule:
    phase: DataPhase
    locations: tuple[str, ...]

    def __post_init__(self):
        if (
            not isinstance(self.phase, DataPhase)
            or type(self.locations) is not tuple
            or len(self.locations) > 64
        ):
            raise ContractError("Typed bounded location rule required")
        for location in self.locations:
            identifier(location)
        if len(set(self.locations)) != len(self.locations):
            raise ContractError("Duplicate data locations")
        object.__setattr__(self, "locations", tuple(sorted(self.locations)))


def _rules(rules):
    if (
        type(rules) is not tuple
        or any(not isinstance(r, LocationRule) for r in rules)
        or len(rules) != len(DataPhase)
        or {r.phase for r in rules} != set(DataPhase)
    ):
        raise ContractError("Every data phase must be explicitly described")
    return tuple(sorted(rules, key=lambda r: str(r.phase)))


@dataclass(frozen=True, slots=True)
class AIResidencyPolicy:
    scope: ResourceScope
    policy_id: str
    revision: int
    data_class: DataClass
    purposes: tuple[str, ...]
    allowed_endpoints: tuple[str, ...]
    rules: tuple[LocationRule, ...]
    issued_at: datetime
    valid_until: datetime
    max_input_bytes: int = 65536

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.data_class, DataClass
        ):
            raise ContractError("Typed AI policy scope/class required")
        identifier(self.policy_id)
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive AI policy revision required")
        for values in (self.purposes, self.allowed_endpoints):
            if (
                type(values) is not tuple
                or not 1 <= len(values) <= 64
                or len(set(values)) != len(values)
            ):
                raise ContractError("Explicit bounded AI purposes/endpoints required")
            for value in values:
                identifier(value)
        object.__setattr__(self, "rules", _rules(self.rules))
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if (
            self.valid_until <= self.issued_at
            or type(self.max_input_bytes) is not int
            or not 1 <= self.max_input_bytes <= 262144
        ):
            raise ContractError("Bounded policy interval/input required")

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(
                {
                    "scope": {
                        k: getattr(self.scope, k)
                        for k in (
                            "tenant_id",
                            "application_id",
                            "environment_id",
                            "resource_id",
                        )
                    },
                    "policy_id": self.policy_id,
                    "revision": self.revision,
                    "data_class": str(self.data_class),
                    "purposes": sorted(self.purposes),
                    "allowed_endpoints": sorted(self.allowed_endpoints),
                    "rules": [
                        {"phase": str(r.phase), "locations": list(r.locations)}
                        for r in self.rules
                    ],
                    "issued_at": self.issued_at.isoformat(),
                    "valid_until": self.valid_until.isoformat(),
                    "max_input_bytes": self.max_input_bytes,
                },
                limit=32768,
            ).encode()
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class AIEndpointFacts:
    scope: ResourceScope
    endpoint_id: str
    deployment_revision: str
    provider: str
    capabilities: tuple[str, ...]
    rules: tuple[LocationRule, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed model deployment scope required")
        for value in (self.endpoint_id, self.deployment_revision, self.provider):
            identifier(value)
        if (
            type(self.capabilities) is not tuple
            or not 1 <= len(self.capabilities) <= 32
            or len(set(self.capabilities)) != len(self.capabilities)
        ):
            raise ContractError("Explicit endpoint capabilities required")
        for value in self.capabilities:
            identifier(value)
        object.__setattr__(self, "rules", _rules(self.rules))
        if not next(r.locations for r in self.rules if r.phase == DataPhase.PROCESSING):
            raise ContractError("Processing location cannot be absent")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Positive endpoint evidence interval required")


def assess_ai_route(
    policy, endpoint, *, scope, data_class, purpose, capability, input_bytes, now
):
    if (
        not isinstance(policy, AIResidencyPolicy)
        or not isinstance(endpoint, AIEndpointFacts)
        or not isinstance(data_class, DataClass)
    ):
        raise ContractError(
            "Typed policy, facts and server-side classification required"
        )
    if scope != policy.scope or (
        endpoint.scope.tenant_id,
        endpoint.scope.application_id,
        endpoint.scope.environment_id,
    ) != (scope.tenant_id, scope.application_id, scope.environment_id):
        raise ContractError(
            "AI route crosses authenticated application/environment scope"
        )
    now = utc(now)
    reasons = []
    if not policy.issued_at <= now < policy.valid_until:
        reasons.append("policy-not-current")
    if not endpoint.observed_at <= now < endpoint.valid_until:
        reasons.append("endpoint-facts-not-current")
    if data_class != policy.data_class:
        reasons.append("classification-policy-mismatch")
    if purpose not in policy.purposes:
        reasons.append("purpose-not-authorized")
    if endpoint.endpoint_id not in policy.allowed_endpoints:
        reasons.append("endpoint-not-authorized")
    if capability not in endpoint.capabilities:
        reasons.append("capability-unverified")
    if type(input_bytes) is not int or not 0 <= input_bytes <= policy.max_input_bytes:
        reasons.append("input-outside-limit")
    allowed = {r.phase: set(r.locations) for r in policy.rules}
    for rule in endpoint.rules:
        if not set(rule.locations) <= allowed[rule.phase]:
            reasons.append(f"forbidden-{rule.phase}-location")
    return {
        "allowed": not reasons,
        "reasons": reasons,
        "policy_digest": policy.fingerprint,
        "endpoint_id": endpoint.endpoint_id,
        "deployment_revision": endpoint.deployment_revision,
        "data_class": str(data_class),
        "automatic_fallback": False,
    }
