"""Explicit registration and sanitized RDS configuration facts, not DB access."""

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
import hashlib
import re
from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    identifier,
    utc,
)


class RdsManagementRelation(StrEnum):
    SOVA_MANAGED = "sova_managed"
    REGISTERED_READ_ONLY = "registered_read_only"


@dataclass(frozen=True, slots=True)
class RdsReadRegistration:
    scope: ResourceScope
    account_id: str
    region: str
    immutable_resource_id: str
    minimum_backup_days: int
    revision: int
    issued_at: datetime
    valid_until: datetime
    management_relation: RdsManagementRelation = RdsManagementRelation.SOVA_MANAGED

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed RDS resource scope required")
        if not isinstance(self.management_relation, RdsManagementRelation):
            raise ContractError("Explicit RDS management relation required")
        if type(self.account_id) is not str or not re.fullmatch(
            r"[0-9]{12}", self.account_id
        ):
            raise ContractError("Exact AWS account required")
        if type(self.region) is not str or not re.fullmatch(
            r"(?:us|eu|ap|sa|ca|me|af|il|mx)-(?:[a-z]+-)+[0-9]", self.region
        ):
            raise ContractError("Supported standard-partition AWS region required")
        prefix = "arn:aws:rds:" + self.region + ":" + self.account_id + ":db:"
        if not self.scope.resource_id.startswith(prefix) or not re.fullmatch(
            r"[a-z][a-z0-9-]{0,62}", self.scope.resource_id[len(prefix) :]
        ):
            raise ContractError("RDS ARN must match registered account and region")
        identifier(self.immutable_resource_id)
        if (
            type(self.minimum_backup_days) is not int
            or not 1 <= self.minimum_backup_days <= 35
        ):
            raise ContractError("Explicit RDS backup retention budget required")
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive RDS registration revision required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if not self.issued_at < self.valid_until <= self.issued_at + timedelta(days=1):
            raise ContractError("Bounded RDS registration required")

    @property
    def identifier(self):
        return self.scope.resource_id.rsplit(":", 1)[1]

    @property
    def document(self):
        from sova.security.domain.governance import scope_document

        return {
            "schema_version": 2,
            "scope": scope_document(self.scope),
            "account_id": self.account_id,
            "region": self.region,
            "immutable_resource_id": self.immutable_resource_id,
            "minimum_backup_days": self.minimum_backup_days,
            "revision": self.revision,
            "issued_at": self.issued_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "management_relation": str(self.management_relation),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()

    def require_current(self, now):
        if not self.issued_at <= utc(now) < self.valid_until:
            raise ContractError("RDS registration expired or future")
