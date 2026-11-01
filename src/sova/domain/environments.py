"""Provider identity, backend identity and implementation facts are distinct."""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from sova.domain.contracts import ContractError, digest, identifier, utc


class Provider(StrEnum):
    AWS = "aws"
    GCP = "gcp"
    ON_PREM = "on_prem"
    LOCAL = "local"


@dataclass(frozen=True, slots=True)
class EnvironmentRegistration:
    tenant_id: str
    environment_id: str
    provider: Provider
    backend: str
    location: str
    resource_identity: str
    revision_digest: str
    registered_at: datetime

    def __post_init__(self):
        for field in (
            "tenant_id",
            "environment_id",
            "backend",
            "location",
            "resource_identity",
        ):
            identifier(getattr(self, field), field, limit=2048)
        if not isinstance(self.provider, Provider):
            raise ContractError("Typed provider required")
        digest(self.revision_digest)
        object.__setattr__(self, "registered_at", utc(self.registered_at))


@dataclass(frozen=True, slots=True)
class ApplicationRevision:
    tenant_id: str
    application_id: str
    source_digest: str
    requirements_digest: str

    def __post_init__(self):
        identifier(self.tenant_id, "tenant_id")
        identifier(self.application_id, "application_id")
        digest(self.source_digest)
        digest(self.requirements_digest)


class FeatureSupport(StrEnum):
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class BackendCapability:
    provider: Provider
    backend: str
    feature: str
    provider_support: FeatureSupport
    implemented_by_sova: bool
    qualified_profile_digest: str | None
    qualification_valid_until: datetime | None

    def __post_init__(self):
        if not isinstance(self.provider, Provider) or not isinstance(
            self.provider_support, FeatureSupport
        ):
            raise ContractError("Typed provider and support facts required")
        identifier(self.backend, "backend")
        identifier(self.feature, "feature")
        if type(self.implemented_by_sova) is not bool:
            raise ContractError("Implementation status must be a boolean")
        if (self.qualified_profile_digest is None) != (
            self.qualification_valid_until is None
        ):
            raise ContractError("Qualification requires both a profile and expiry")
        if self.qualified_profile_digest is not None:
            digest(self.qualified_profile_digest)
            object.__setattr__(
                self, "qualification_valid_until", utc(self.qualification_valid_until)
            )

    def can_execute(
        self, *, profile_digest: str, now: datetime, live_ready: bool
    ) -> bool:
        now = utc(now)
        digest(profile_digest)
        if type(live_ready) is not bool:
            raise ContractError("Live readiness must be a boolean")
        return bool(
            self.provider_support == FeatureSupport.SUPPORTED
            and self.implemented_by_sova
            and live_ready
            and self.qualified_profile_digest == profile_digest
            and self.qualification_valid_until is not None
            and now < self.qualification_valid_until
        )
