"""Fixed AWS metadata reads; no SQL, Secrets, IAM simulation or modifications.

These checks establish configuration facts only. Successful backup restore,
actual network reachability, TLS enforcement and IAM denial need separate probes.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
from sova.security.domain.aws_security import RdsReadRegistration, RdsManagementRelation
from sova.domain.contracts import (
    ContractError,
    canonical_json,
    public_json,
    digest,
    utc,
)
from sova.domain.evidence import EvidenceRecord, VerificationResult
from sova.security.domain.protection_parity import Availability


VERIFIER = "sova-aws-rds-configuration-v1"
CONTROLS = (
    "storage-encryption",
    "backup-retention",
    "private-endpoint",
    "deletion-protection",
    "postgres-log-export",
    "multi-az-configuration",
)


def fixed_clients(session, registration):
    """Trusted SDK factory: exact HTTPS endpoints, no proxy or endpoint override."""
    from botocore.config import Config

    config = Config(
        connect_timeout=2,
        read_timeout=3,
        retries={"total_max_attempts": 1},
        proxies={},
        ignore_configured_endpoint_urls=True,
    )
    return {
        service: session.client(
            service,
            region_name=registration.region,
            endpoint_url="https://"
            + service
            + "."
            + registration.region
            + ".amazonaws.com",
            verify=True,
            config=config,
        )
        for service in ("sts", "rds")
    }


def _boolean(value, *, expected=True):
    if type(value) is not bool:
        return "unknown"
    return "pass" if value == expected else "fail"


def configuration_checks(facts, registration):
    retention = facts["backup_retention_days"]
    checks = {
        "storage-encryption": _boolean(facts["storage_encrypted"]),
        "backup-retention": "unknown"
        if retention is None
        else "pass"
        if retention >= registration.minimum_backup_days
        else "fail",
        "private-endpoint": _boolean(facts["publicly_accessible"], expected=False),
        "deletion-protection": _boolean(facts["deletion_protection"]),
        "postgres-log-export": _boolean(facts["postgres_log_export"]),
        "multi-az-configuration": _boolean(facts["multi_az"]),
    }
    return (
        {k: "unknown" for k in checks}
        if facts["available"] is not True or facts["pending_changes"] is not False
        else checks
    )


@dataclass(frozen=True, slots=True)
class RdsConfigurationSnapshot:
    registration: RdsReadRegistration
    observed_at: datetime
    valid_until: datetime
    facts_json: str
    checks_json: str

    def __post_init__(self):
        if not isinstance(self.registration, RdsReadRegistration):
            raise ContractError("Typed RDS snapshot registration required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        self.registration.require_current(self.observed_at)
        if (
            not self.observed_at
            < self.valid_until
            <= min(
                self.registration.valid_until, self.observed_at + timedelta(minutes=2)
            )
        ):
            raise ContractError("Bounded RDS observation required")
        facts = public_json(self.facts_json)
        checks = public_json(self.checks_json)
        fields = {
            "storage_encrypted",
            "backup_retention_days",
            "publicly_accessible",
            "deletion_protection",
            "postgres_log_export",
            "multi_az",
            "available",
            "pending_changes",
            "resource_binding",
        }
        if (
            not isinstance(facts, dict)
            or set(facts) != fields
            or not isinstance(checks, dict)
            or set(checks) != set(CONTROLS)
        ):
            raise ContractError("Allowlisted RDS security projection required")
        if any(
            type(facts[k]) is not bool and facts[k] is not None
            for k in fields - {"backup_retention_days", "resource_binding"}
        ):
            raise ContractError("Typed RDS configuration flags required")
        retention = facts["backup_retention_days"]
        if retention is not None and (
            type(retention) is not int or not 0 <= retention <= 35
        ):
            raise ContractError("Bounded RDS retention fact required")
        digest(facts["resource_binding"])
        if any(v not in ("pass", "fail", "unknown") for v in checks.values()):
            raise ContractError("Typed RDS configuration outcomes required")
        binding = hashlib.sha256(
            (
                self.registration.scope.resource_id
                + "\0"
                + self.registration.immutable_resource_id
            ).encode()
        ).hexdigest()
        if facts["resource_binding"] != binding or checks != configuration_checks(
            facts, self.registration
        ):
            raise ContractError("RDS configuration facts and conclusions differ")
        object.__setattr__(self, "facts_json", canonical_json(facts))
        object.__setattr__(self, "checks_json", canonical_json(checks))

    @property
    def facts(self):
        import json

        return json.loads(self.facts_json)

    @property
    def checks(self):
        import json

        return json.loads(self.checks_json)

    @property
    def configuration_digest(self):
        return hashlib.sha256(self.facts_json.encode()).hexdigest()

    @property
    def document(self):
        from sova.security.domain.governance import scope_document

        return {
            "schema_version": 1,
            "scope": scope_document(self.registration.scope),
            "registration_digest": self.registration.fingerprint,
            "configuration_digest": self.configuration_digest,
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "basis": "configuration_only",
            "management_relation": str(self.registration.management_relation),
            "ownership_tags_verified": self.registration.management_relation
            == RdsManagementRelation.SOVA_MANAGED,
            "grants_modification_authority": False,
            "verifier_version": VERIFIER,
            "facts": self.facts,
            "checks": self.checks,
            "unverified": [
                "tls-enforcement",
                "certificate-verification",
                "cross-app-access-denial",
                "restore-test",
                "availability-slo",
                "effective-network-access",
                "audit-log-delivery",
            ],
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()

    def evidence(self, policy, requirement_id, *, side):
        if side not in ("source", "target"):
            raise ContractError("Exact RDS protection side required")
        req = next(
            (r for r in policy.requirements if r.requirement_id == requirement_id), None
        )
        if req is None:
            raise ContractError("RDS objective not registered")
        ep = getattr(req, side)
        prefix = "rds-postgresql:"
        if ep.provider != "aws" or not ep.implementation.startswith(prefix):
            raise ContractError("Registered RDS implementation required")
        control = ep.implementation[len(prefix) :]
        if (
            control not in CONTROLS
            or ep.scope != self.registration.scope
            or ep.verifier_version != VERIFIER
        ):
            raise ContractError("RDS evidence objective/scope/verifier mismatch")
        if (
            ep.configuration_digest != self.configuration_digest
            or ep.environment_digest != self.registration.fingerprint
        ):
            raise ContractError("RDS evidence configuration/registration changed")
        if (
            ep.provider_capability != Availability.AVAILABLE
            or ep.adapter_implementation != Availability.AVAILABLE
        ):
            raise ContractError("RDS protection path unavailable")
        return EvidenceRecord(
            "rds:" + side + ":" + requirement_id + ":" + self.fingerprint,
            req.obligation(side).obligation_id,
            ep.scope,
            ep.revisions(policy.fingerprint),
            VERIFIER,
            self.observed_at,
            min(self.valid_until, policy.valid_until),
            VerificationResult(self.checks[control]),
            "rds-config:" + self.fingerprint,
            self.fingerprint,
        )


class RdsSecurityCollector:
    def __init__(self, registration, *, clients, authorize, clock, monotonic):
        if not isinstance(registration, RdsReadRegistration) or any(
            not callable(c) for c in (clients, authorize, clock, monotonic)
        ):
            raise ContractError(
                "Explicit RDS registration and read authorities required"
            )
        self.registration = registration
        self.clients = clients
        self.authorize = authorize
        self.clock = clock
        self.monotonic = monotonic

    def collect(self, *, actor):
        reg = self.registration
        started_at = utc(self.clock())
        reg.require_current(started_at)
        self.authorize(actor, reg, "security:rds-metadata-read")
        end = self.monotonic() + 12
        clients = self.clients(reg)

        def call(service, method, **parameters):
            self.authorize(actor, reg, "security:rds-metadata-read")
            reg.require_current(self.clock())
            if self.monotonic() >= end:
                raise ContractError("RDS read deadline exceeded")
            try:
                value = getattr(clients[service], method)(**parameters)
            except Exception as exc:
                raise ContractError(
                    "Registered AWS security metadata unavailable"
                ) from exc
            if self.monotonic() >= end:
                raise ContractError("RDS read deadline exceeded")
            return value

        identity = call("sts", "get_caller_identity")
        if identity.get("Account") != reg.account_id:
            raise ContractError("AWS reader account does not match registration")
        response = call(
            "rds", "describe_db_instances", DBInstanceIdentifier=reg.scope.resource_id
        )
        instances = response.get("DBInstances")
        if type(instances) is not list or len(instances) != 1 or response.get("Marker"):
            raise ContractError("Single registered RDS instance required")
        db = instances[0]
        if not isinstance(db, dict) or (
            db.get("DBInstanceArn"),
            db.get("DBInstanceIdentifier"),
            db.get("DbiResourceId"),
            db.get("Engine"),
        ) != (
            reg.scope.resource_id,
            reg.identifier,
            reg.immutable_resource_id,
            "postgres",
        ):
            raise ContractError("RDS identity was replaced or is unsupported")
        if reg.management_relation == RdsManagementRelation.SOVA_MANAGED:
            tags = call(
                "rds", "list_tags_for_resource", ResourceName=reg.scope.resource_id
            ).get("TagList")
            if (
                type(tags) is not list
                or len(tags) > 50
                or any(
                    not isinstance(t, dict)
                    or type(t.get("Key")) is not str
                    or type(t.get("Value")) is not str
                    for t in tags
                )
            ):
                raise ContractError("Bounded RDS ownership tags required")
            tagmap = {t["Key"]: t["Value"] for t in tags}
            if len(tagmap) != len(tags) or any(
                tagmap.get(k) != v
                for k, v in {
                    "sova:managed-by": "sova",
                    "sova:tenant-id": reg.scope.tenant_id,
                    "sova:application-id": reg.scope.application_id,
                }.items()
            ):
                raise ContractError("RDS registered ownership mismatch")
        retention = db.get("BackupRetentionPeriod")
        exports = db.get("EnabledCloudwatchLogsExports")
        pending = db.get("PendingModifiedValues")
        facts = {
            "storage_encrypted": db.get("StorageEncrypted")
            if type(db.get("StorageEncrypted")) is bool
            else None,
            "backup_retention_days": retention
            if type(retention) is int and 0 <= retention <= 35
            else None,
            "publicly_accessible": db.get("PubliclyAccessible")
            if type(db.get("PubliclyAccessible")) is bool
            else None,
            "deletion_protection": db.get("DeletionProtection")
            if type(db.get("DeletionProtection")) is bool
            else None,
            "postgres_log_export": ("postgresql" in exports)
            if type(exports) is list and all(type(x) is str for x in exports)
            else None,
            "multi_az": db.get("MultiAZ") if type(db.get("MultiAZ")) is bool else None,
            "available": db.get("DBInstanceStatus") == "available",
            "pending_changes": bool(pending) if type(pending) is dict else None,
            "resource_binding": hashlib.sha256(
                (reg.scope.resource_id + "\0" + reg.immutable_resource_id).encode()
            ).hexdigest(),
        }
        checks = configuration_checks(facts, reg)
        self.authorize(actor, reg, "security:rds-metadata-read")
        if self.monotonic() >= end:
            raise ContractError("RDS read deadline exceeded")
        observed = utc(self.clock())
        reg.require_current(observed)
        if observed < started_at:
            raise ContractError("RDS observation clock moved backwards")
        return RdsConfigurationSnapshot(
            reg,
            observed,
            min(reg.valid_until, observed + timedelta(minutes=2)),
            canonical_json(facts),
            canonical_json(checks),
        )
