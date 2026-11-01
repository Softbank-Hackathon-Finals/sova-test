"""Immutable, bounded public commands; credentials never belong in these values.

Adapter validation must restrict parameters to its own non-secret command schema.
This module validates structure, not whether an arbitrary string contains a secret.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Mapping


class ContractError(ValueError):
    pass


def identifier(value: str, field: str = "identifier", *, limit: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= limit
        or value != value.strip()
        or any(ord(c) < 32 or ord(c) == 127 for c in value)
    ):
        raise ContractError(f"Invalid {field}")
    return value


def digest(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ContractError("Expected a lowercase SHA-256 digest")
    return value


def utc(value: datetime) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ContractError("An aware timestamp is required")
    if value.utcoffset() is None:
        raise ContractError("An aware timestamp is required")
    return value.astimezone(UTC)


def canonical_json(value: Mapping[str, Any], *, limit: int = 8192) -> str:
    def validate(item, depth=0):
        if depth > 12:
            raise ContractError("Command structure is too deep")
        if isinstance(item, dict):
            if any(not isinstance(k, str) for k in item):
                raise ContractError("JSON object keys must be strings")
            for child in item.values():
                validate(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                validate(child, depth + 1)
        elif item is not None and type(item) not in (str, bool, int, float):
            raise ContractError("Only JSON values are accepted")

    if not isinstance(value, dict):
        raise ContractError("A JSON object is required")
    validate(value)
    try:
        result = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (ValueError, TypeError, OverflowError) as error:
        raise ContractError("Invalid JSON value") from error
    try:
        encoded = result.encode()
    except UnicodeError as error:
        raise ContractError("Invalid Unicode in public command") from error
    if len(encoded) > limit:
        raise ContractError("Public command exceeds size limit")
    return result


def public_json(value: str) -> dict:
    if not isinstance(value, str):
        raise ContractError("Public JSON text is required")
    try:
        if len(value.encode()) > 8192:
            raise ContractError("Public command exceeds size limit")
    except UnicodeError as error:
        raise ContractError("Invalid Unicode in public command") from error

    def unique_pairs(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ContractError("Duplicate JSON object key")
            result[key] = item
        return result

    try:
        result = json.loads(value, object_pairs_hook=unique_pairs)
    except (ValueError, RecursionError) as error:
        raise ContractError("Invalid public command JSON") from error
    canonical_json(result)
    return result


@dataclass(frozen=True, slots=True)
class ResourceScope:
    tenant_id: str
    application_id: str
    environment_id: str
    resource_id: str

    def __post_init__(self):
        for field, value in asdict(self).items():
            identifier(value, field, limit=2048 if field == "resource_id" else 256)


@dataclass(frozen=True, slots=True)
class EffectCommand:
    scope: ResourceScope
    operation_id: str
    step_id: str
    adapter_id: str
    action: str
    idempotency_key: str
    plan_digest: str
    expected_revision: str
    fencing_epoch: int
    expires_at: datetime
    parameters_json: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("A resource scope is required")
        for name in (
            "operation_id",
            "step_id",
            "adapter_id",
            "action",
            "idempotency_key",
            "expected_revision",
        ):
            identifier(getattr(self, name), name)
        digest(self.plan_digest)
        if type(self.fencing_epoch) is not int or self.fencing_epoch < 1:
            raise ContractError("A positive fencing epoch is required")
        object.__setattr__(self, "expires_at", utc(self.expires_at))
        parsed = public_json(self.parameters_json)
        object.__setattr__(self, "parameters_json", canonical_json(parsed))

    @property
    def parameters(self) -> dict:
        # A fresh object prevents callers from mutating the approved command.
        return json.loads(self.parameters_json)

    @property
    def document(self) -> dict:
        return {
            **asdict(self),
            "expires_at": self.expires_at.isoformat(),
            "parameters_json": self.parameters_json,
        }

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(
            canonical_json(self.document, limit=16384).encode()
        ).hexdigest()

    @property
    def intent_fingerprint(self) -> str:
        """Stable intent across newer execution epochs, not across plan changes.

        Only confirmed historical receipts may be reused with a newer epoch.
        Unknown/in-flight commands still require their exact original digest.
        """
        document = self.document
        del document["fencing_epoch"]
        return hashlib.sha256(
            canonical_json(document, limit=16384).encode()
        ).hexdigest()

    @classmethod
    def from_document(cls, value: dict) -> EffectCommand:
        data = dict(value)
        data["scope"] = ResourceScope(**data["scope"])
        data["expires_at"] = datetime.fromisoformat(data["expires_at"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ExecutionPermit:
    """Server-issued scope grant, not a JWT or proof of live user authorization.

    The caller must obtain/recheck membership, approval, and security holds at the
    execution boundary. A matching data structure alone does not authorize a user.
    """

    scope: ResourceScope
    operation_id: str
    plan_digest: str
    command_digest: str
    fencing_epoch: int
    expires_at: datetime
    security_hold: bool = False

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("A resource scope is required")
        identifier(self.operation_id, "operation_id")
        digest(self.plan_digest)
        digest(self.command_digest)
        if type(self.fencing_epoch) is not int or self.fencing_epoch < 1:
            raise ContractError("A positive fencing epoch is required")
        if type(self.security_hold) is not bool:
            raise ContractError("security_hold must be a boolean")
        object.__setattr__(self, "expires_at", utc(self.expires_at))


def validate_permit(
    command: EffectCommand,
    permit: ExecutionPermit,
    now: datetime,
    *,
    mutation: bool = True,
) -> None:
    now = utc(now)
    if permit.security_hold and mutation:
        raise ContractError("Security hold blocks execution")
    if (
        permit.scope != command.scope
        or permit.operation_id != command.operation_id
        or permit.plan_digest != command.plan_digest
        or permit.command_digest != command.fingerprint
        or permit.fencing_epoch != command.fencing_epoch
    ):
        raise ContractError("Execution permit does not match the command")
    if now >= permit.expires_at or (mutation and now >= command.expires_at):
        raise ContractError("Execution permit or command expired")


class EffectStatus(StrEnum):
    PREPARED = "prepared"
    IN_FLIGHT = "in_flight"
    APPLIED = "confirmed_applied"
    NOT_APPLIED = "confirmed_not_applied"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class EffectObservation:
    scope: ResourceScope
    command_digest: str
    status: EffectStatus
    observed_at: datetime
    evidence_json: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("A resource scope is required")
        digest(self.command_digest)
        if not isinstance(self.status, EffectStatus) or self.status not in (
            EffectStatus.APPLIED,
            EffectStatus.UNKNOWN,
        ):
            # Current state alone cannot prove that a request never took effect.
            raise ContractError("Readback must confirm applied state or remain unknown")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(
            self, "evidence_json", canonical_json(public_json(self.evidence_json))
        )

    @property
    def evidence(self) -> dict:
        return json.loads(self.evidence_json)


@dataclass(frozen=True, slots=True)
class EffectRecord:
    command: EffectCommand
    status: EffectStatus
    revision: int
    observation: EffectObservation | None = None

    def __post_init__(self):
        if not isinstance(self.command, EffectCommand) or not isinstance(
            self.status, EffectStatus
        ):
            raise ContractError("Typed command and effect status are required")
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive effect record revision required")
        if self.status == EffectStatus.APPLIED and self.observation is None:
            raise ContractError("Applied records require evidence")
        if self.observation is not None and not isinstance(
            self.observation, EffectObservation
        ):
            raise ContractError("Typed effect observation required")
        if self.observation and (
            self.observation.scope != self.command.scope
            or self.observation.command_digest != self.command.fingerprint
            or self.observation.status != self.status
        ):
            raise ContractError("Effect record evidence binding mismatch")
