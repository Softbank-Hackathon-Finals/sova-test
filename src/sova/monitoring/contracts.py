"""Immutable, authenticated monitor registrations and opaque fenced claims."""

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import hashlib

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)


@dataclass(frozen=True, slots=True)
class MonitorRegistration:
    scope: ResourceScope
    job_id: str
    actor_id: str
    baseline_digest: str
    interval_seconds: int
    registered_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed monitor scope required")
        identifier(self.job_id)
        identifier(self.actor_id)
        digest(self.baseline_digest)
        if (
            type(self.interval_seconds) is not int
            or not 60 <= self.interval_seconds <= 86400
        ):
            raise ContractError("Monitor interval must be 60 seconds to one day")
        object.__setattr__(self, "registered_at", utc(self.registered_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if (
            not self.registered_at
            < self.valid_until
            <= self.registered_at + timedelta(days=30)
        ):
            raise ContractError("Bounded monitor registration required")

    @property
    def document(self):
        return {
            "schema_version": 1,
            "scope": asdict(self.scope),
            "job_id": self.job_id,
            "actor_id": self.actor_id,
            "baseline_digest": self.baseline_digest,
            "interval_seconds": self.interval_seconds,
            "registered_at": self.registered_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()

    def require_current(self, now):
        if not self.registered_at <= utc(now) < self.valid_until:
            raise ContractError("Monitor registration expired/future")


@dataclass(frozen=True, slots=True)
class MonitorClaim:
    registration_digest: str
    job_id: str
    application_id: str
    run_id: str
    owner_id: str
    lease_token: str
    lease_until: datetime

    def __post_init__(self):
        digest(self.registration_digest)
        for value in (
            self.job_id,
            self.application_id,
            self.run_id,
            self.owner_id,
            self.lease_token,
        ):
            identifier(value)
        object.__setattr__(self, "lease_until", utc(self.lease_until))


@dataclass(frozen=True, slots=True)
class AlertDelivery:
    tenant_id: str
    application_id: str
    alert_id: str
    job_id: str
    run_id: str
    category: str
    owner_id: str
    lease_token: str
    lease_until: datetime

    def __post_init__(self):
        for name in (
            "tenant_id",
            "application_id",
            "alert_id",
            "job_id",
            "run_id",
            "owner_id",
            "lease_token",
        ):
            identifier(getattr(self, name))
        if self.category not in {
            "monitor_failed",
            "security_attention",
            "monitor_abandoned",
        }:
            raise ContractError("Known monitoring alert category required")
        object.__setattr__(self, "lease_until", utc(self.lease_until))

    @property
    def event(self):
        # Lease tokens, worker identity and arbitrary collector text never leave
        # the relay. Sink must deduplicate by tenant + alert_id (at-least-once).
        return {
            "schema_version": 1,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "alert_id": self.alert_id,
            "job_id": self.job_id,
            "run_id": self.run_id,
            "category": self.category,
        }


@dataclass(frozen=True, slots=True)
class AlertReceipt:
    alert_id: str
    sink_id: str
    receipt_id: str

    def __post_init__(self):
        for value in (self.alert_id, self.sink_id, self.receipt_id):
            identifier(value)


@dataclass(frozen=True, slots=True)
class MonitorInputSet:
    scope: ResourceScope
    job_id: str
    revision: int
    predecessor_digest: str | None
    inventory_digest: str
    scan_digest: str
    exposure_digest: str
    policy_digest: str
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed monitoring input set scope required")
        identifier(self.job_id)
        if (
            type(self.revision) is not int
            or not 1 <= self.revision <= 9223372036854775807
        ):
            raise ContractError("Positive input set revision required")
        if (self.revision == 1) != (self.predecessor_digest is None):
            raise ContractError("Explicit monitor input predecessor required")
        for value in (
            self.inventory_digest,
            self.scan_digest,
            self.exposure_digest,
            self.policy_digest,
        ):
            digest(value)
        if self.predecessor_digest is not None:
            digest(self.predecessor_digest)
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if (
            not self.observed_at
            < self.valid_until
            <= self.observed_at + timedelta(minutes=15)
        ):
            raise ContractError("Fresh bounded monitor input set required")

    @property
    def document(self):
        result = asdict(self)
        result["schema_version"] = 1
        result["observed_at"] = self.observed_at.isoformat()
        result["valid_until"] = self.valid_until.isoformat()
        return result

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()

    @property
    def input_digests(self):
        return (
            self.inventory_digest,
            self.scan_digest,
            self.exposure_digest,
            self.policy_digest,
        )
