"""Immutable lifecycle plans. Recovery and cleanup create new approved plans.

Approvals and evidence must come from authenticated server-side authorities.
These value objects do not authenticate an approver or sign an artifact.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
import hashlib

from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    public_json,
    utc,
)
from sova.domain.evidence import RevisionSet, VerificationObligation


class PlanPurpose(StrEnum):
    CHANGE = "change"
    MIGRATION_PHASE = "migration_phase"
    SECURITY_RESPONSE = "security_response"
    RECOVERY = "recovery"
    FINALIZATION = "finalization"


@dataclass(frozen=True, slots=True)
class Inspection:
    scope: ResourceScope
    revisions: RevisionSet
    observed_at: datetime
    valid_until: datetime
    facts_json: str
    artifact_digest: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed inspection scope and revisions required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Invalid inspection validity")
        object.__setattr__(
            self, "facts_json", canonical_json(public_json(self.facts_json))
        )
        digest(self.artifact_digest)

    def require_current(self, now: datetime) -> None:
        if not self.observed_at <= utc(now) < self.valid_until:
            raise ContractError("Inspection is expired or from the future")


@dataclass(frozen=True, slots=True)
class PlanStep:
    step_id: str
    scope: ResourceScope
    adapter_id: str
    action: str
    parameters_json: str
    expected_revision: str
    depends_on: tuple[str, ...] = ()

    def __post_init__(self):
        for field in ("step_id", "adapter_id", "action", "expected_revision"):
            identifier(getattr(self, field), field)
        if (
            not isinstance(self.scope, ResourceScope)
            or type(self.depends_on) is not tuple
        ):
            raise ContractError("Typed scope and immutable dependencies required")
        for dependency in self.depends_on:
            identifier(dependency, "dependency")
        if len(self.depends_on) != len(set(self.depends_on)):
            raise ContractError("Duplicate step dependencies")
        object.__setattr__(
            self, "parameters_json", canonical_json(public_json(self.parameters_json))
        )

    @property
    def document(self):
        return {
            "step_id": self.step_id,
            "scope": {
                name: getattr(self.scope, name)
                for name in (
                    "tenant_id",
                    "application_id",
                    "environment_id",
                    "resource_id",
                )
            },
            "adapter_id": self.adapter_id,
            "action": self.action,
            "parameters_json": self.parameters_json,
            "expected_revision": self.expected_revision,
            "depends_on": list(self.depends_on),
        }


@dataclass(frozen=True, slots=True)
class LifecyclePlan:
    plan_id: str
    tenant_id: str
    application_id: str
    created_by: str
    purpose: PlanPurpose
    revisions: RevisionSet
    valid_until: datetime
    steps: tuple[PlanStep, ...]
    obligations: tuple[VerificationObligation, ...]
    origin_plan_digest: str | None = None
    reason: str | None = None

    def __post_init__(self):
        for field in ("plan_id", "tenant_id", "application_id", "created_by"):
            identifier(getattr(self, field), field)
        if not isinstance(self.purpose, PlanPurpose) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed plan purpose and revisions required")
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.reason is not None:
            identifier(self.reason, "plan reason", limit=2048)
        if type(self.steps) is not tuple or not 1 <= len(self.steps) <= 128:
            raise ContractError("A bounded immutable step list is required")
        if type(self.obligations) is not tuple or not 1 <= len(self.obligations) <= 256:
            raise ContractError("A bounded immutable obligation list is required")
        seen = set()
        for step in self.steps:
            if not isinstance(step, PlanStep):
                raise ContractError("Typed plan steps required")
            if step.step_id in seen or not set(step.depends_on) <= seen:
                raise ContractError(
                    "Steps must have unique IDs and earlier dependencies"
                )
            self.require_scope(step.scope)
            seen.add(step.step_id)
        ids = set()
        for obligation in self.obligations:
            if (
                not isinstance(obligation, VerificationObligation)
                or obligation.obligation_id in ids
            ):
                raise ContractError("Unique typed obligations required")
            self.require_scope(obligation.scope)
            ids.add(obligation.obligation_id)
        if self.purpose == PlanPurpose.SECURITY_RESPONSE:
            identifier(self.reason, "security response reason", limit=2048)
            if self.origin_plan_digest is not None:
                digest(self.origin_plan_digest)
        elif self.purpose == PlanPurpose.MIGRATION_PHASE:
            identifier(self.reason, "migration phase reason", limit=2048)
            if self.origin_plan_digest is not None:
                digest(self.origin_plan_digest)
        elif self.purpose != PlanPurpose.CHANGE:
            digest(self.origin_plan_digest)
            identifier(self.reason, "recovery/finalization reason", limit=2048)
        elif self.origin_plan_digest is not None:
            digest(self.origin_plan_digest)

    def require_scope(self, scope: ResourceScope):
        if (scope.tenant_id, scope.application_id) != (
            self.tenant_id,
            self.application_id,
        ):
            raise ContractError("Plan scope crosses tenant or application")

    @property
    def document(self):
        # Runtime operation/epoch/permit fields are excluded, avoiding a circular
        # plan_digest -> command_digest -> plan_digest dependency.
        data = {
            "plan_id": self.plan_id,
            "tenant_id": self.tenant_id,
            "application_id": self.application_id,
            "created_by": self.created_by,
            "purpose": str(self.purpose),
            "revisions": {
                key: getattr(self.revisions, key)
                for key in ("source", "configuration", "policy", "environment")
            },
            "valid_until": self.valid_until.isoformat(),
            "steps": [step.document for step in self.steps],
            "obligations": [
                {
                    "id": o.obligation_id,
                    "scope": {
                        key: getattr(o.scope, key)
                        for key in (
                            "tenant_id",
                            "application_id",
                            "environment_id",
                            "resource_id",
                        )
                    },
                    "due_gate": int(o.due_gate),
                    "verifier": o.verifier_version,
                    "required": o.required,
                }
                for o in self.obligations
            ],
            "origin_plan_digest": self.origin_plan_digest,
            "reason": self.reason,
        }
        return data

    @property
    def fingerprint(self):
        return hashlib.sha256(
            canonical_json(self.document, limit=262144).encode()
        ).hexdigest()

    def command(self, step_id: str, *, operation_id: str, epoch: int) -> EffectCommand:
        step = next((item for item in self.steps if item.step_id == step_id), None)
        if step is None:
            raise ContractError("Step is not in this plan")
        return EffectCommand(
            step.scope,
            operation_id,
            step.step_id,
            step.adapter_id,
            step.action,
            operation_id + ":" + step.step_id,
            self.fingerprint,
            step.expected_revision,
            epoch,
            self.valid_until,
            step.parameters_json,
        )


@dataclass(frozen=True, slots=True)
class PlanApproval:
    plan_digest: str
    approved_by: str
    purpose: PlanPurpose
    valid_until: datetime

    def __post_init__(self):
        digest(self.plan_digest)
        identifier(self.approved_by, "approver")
        if not isinstance(self.purpose, PlanPurpose):
            raise ContractError("Typed approval purpose required")
        object.__setattr__(self, "valid_until", utc(self.valid_until))

    def require_valid(self, plan: LifecyclePlan, now: datetime):
        if self.plan_digest != plan.fingerprint or self.purpose != plan.purpose:
            raise ContractError("Approval does not match plan")
        if self.approved_by == plan.created_by:
            raise ContractError("Plan author cannot approve the same plan")
        if utc(now) >= min(self.valid_until, plan.valid_until):
            raise ContractError("Approval or plan expired")
