"""Migration and preview-step state machines, independent of presentation."""

from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum

from sova.domain.contracts import ContractError, ResourceScope, digest, identifier, utc


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    NEEDS_ATTENTION = "needs_attention"


def validate_step_transition(current: str, target: str) -> None:
    allowed = {
        StepStatus.PENDING: {StepStatus.RUNNING, StepStatus.BLOCKED},
        StepStatus.RUNNING: {
            StepStatus.SUCCEEDED,
            StepStatus.FAILED,
            StepStatus.NEEDS_ATTENTION,
        },
    }
    if target not in allowed.get(current, set()):
        raise ContractError(f"Invalid step transition: {current} -> {target}")


class OperationStatus(StrEnum):
    PHASE_RUNNING = "phase_running"
    PHASE_VERIFIED = "phase_verified"
    CONTAINING = "containing"
    PREPARING_REPLACEMENT = "preparing_replacement"
    VERIFYING_REPLACEMENT = "verifying_replacement"
    RESPONSE_VERIFIED = "response_verified"
    REGISTERED = "registered"
    ASSESSING = "assessing"
    REHEARSING = "rehearsing"
    AWAITING_APPROVAL = "awaiting_approval"
    PREPARING = "preparing"
    SYNCING = "syncing"
    CUTOVER_READY = "cutover_ready"
    FENCING = "fencing"
    SWITCHING = "switching"
    VERIFYING = "verifying"
    STABILIZING = "stabilizing"
    SERVICE_MOVED = "service_moved"
    FINALIZING = "finalizing"
    FINALIZED = "finalized"
    BLOCKED = "blocked"
    FAILED = "failed"
    CANCELLED = "cancelled"
    RECOVERY_REQUIRED = "recovery_required"
    RECOVERING = "recovering"
    RECOVERED = "recovered"


_FORWARD = (
    OperationStatus.REGISTERED,
    OperationStatus.ASSESSING,
    OperationStatus.REHEARSING,
    OperationStatus.AWAITING_APPROVAL,
    OperationStatus.PREPARING,
    OperationStatus.SYNCING,
    OperationStatus.CUTOVER_READY,
    OperationStatus.FENCING,
    OperationStatus.SWITCHING,
    OperationStatus.VERIFYING,
    OperationStatus.STABILIZING,
    OperationStatus.SERVICE_MOVED,
    OperationStatus.FINALIZING,
    OperationStatus.FINALIZED,
)
_TRANSITIONS = {current: {target} for current, target in zip(_FORWARD, _FORWARD[1:])}
for _state in _FORWARD[:7]:
    _TRANSITIONS[_state].update(
        {
            OperationStatus.BLOCKED,
            OperationStatus.FAILED,
            OperationStatus.CANCELLED,
        }
    )
for _state in _FORWARD[7:-1]:
    _TRANSITIONS[_state].add(OperationStatus.RECOVERY_REQUIRED)
_TRANSITIONS[OperationStatus.RECOVERY_REQUIRED] = {OperationStatus.RECOVERING}
_TRANSITIONS[OperationStatus.RECOVERING] = {
    OperationStatus.RECOVERED,
    OperationStatus.RECOVERY_REQUIRED,
}


class OperationProfile(StrEnum):
    MIGRATION = "migration"
    MIGRATION_PHASE = "migration_phase"
    SECURITY_RESPONSE = "security_response"


_RESPONSE_TRANSITIONS = {
    OperationStatus.REGISTERED: {
        OperationStatus.CONTAINING,
        OperationStatus.CANCELLED,
        OperationStatus.BLOCKED,
        OperationStatus.FAILED,
    },
    OperationStatus.CONTAINING: {
        OperationStatus.PREPARING_REPLACEMENT,
        OperationStatus.RECOVERY_REQUIRED,
    },
    OperationStatus.PREPARING_REPLACEMENT: {
        OperationStatus.VERIFYING_REPLACEMENT,
        OperationStatus.RECOVERY_REQUIRED,
    },
    OperationStatus.VERIFYING_REPLACEMENT: {
        OperationStatus.SWITCHING,
        OperationStatus.RECOVERY_REQUIRED,
    },
    OperationStatus.SWITCHING: {
        OperationStatus.VERIFYING,
        OperationStatus.RECOVERY_REQUIRED,
    },
    OperationStatus.VERIFYING: {
        OperationStatus.RESPONSE_VERIFIED,
        OperationStatus.RECOVERY_REQUIRED,
    },
    OperationStatus.RECOVERY_REQUIRED: {OperationStatus.RECOVERING},
    OperationStatus.RECOVERING: {
        OperationStatus.RECOVERED,
        OperationStatus.RECOVERY_REQUIRED,
    },
}

_PHASE_TRANSITIONS = {
    OperationStatus.REGISTERED: {
        OperationStatus.PHASE_RUNNING,
        OperationStatus.CANCELLED,
        OperationStatus.BLOCKED,
        OperationStatus.FAILED,
    },
    OperationStatus.PHASE_RUNNING: {
        OperationStatus.VERIFYING,
        OperationStatus.RECOVERY_REQUIRED,
    },
    OperationStatus.VERIFYING: {
        OperationStatus.PHASE_VERIFIED,
        OperationStatus.RECOVERY_REQUIRED,
    },
    OperationStatus.RECOVERY_REQUIRED: {OperationStatus.RECOVERING},
    OperationStatus.RECOVERING: {
        OperationStatus.RECOVERED,
        OperationStatus.RECOVERY_REQUIRED,
    },
}


@dataclass(frozen=True, slots=True)
class OperationState:
    scope: ResourceScope
    operation_id: str
    plan_digest: str
    status: OperationStatus
    revision: int
    updated_at: datetime
    security_hold: bool = False
    profile: OperationProfile = OperationProfile.MIGRATION

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.status, OperationStatus
        ):
            raise ContractError("Typed scope and operation status are required")
        if not isinstance(self.profile, OperationProfile):
            raise ContractError("Typed operation profile required")
        identifier(self.operation_id, "operation_id")
        digest(self.plan_digest)
        if type(self.revision) is not int or self.revision < 1:
            raise ContractError("Positive operation revision required")
        if type(self.security_hold) is not bool:
            raise ContractError("security_hold must be a boolean")
        object.__setattr__(self, "updated_at", utc(self.updated_at))

    def advance(
        self, target: OperationStatus, *, expected_revision: int, now: datetime
    ) -> "OperationState":
        now = utc(now)
        if type(expected_revision) is not int or expected_revision != self.revision:
            raise ContractError("Operation revision conflict")
        transitions = (
            _RESPONSE_TRANSITIONS
            if self.profile == OperationProfile.SECURITY_RESPONSE
            else _PHASE_TRANSITIONS
            if self.profile == OperationProfile.MIGRATION_PHASE
            else _TRANSITIONS
        )
        if not isinstance(target, OperationStatus) or target not in transitions.get(
            self.status, set()
        ):
            raise ContractError("Invalid operation transition")
        if now < self.updated_at:
            raise ContractError("Operation timestamp moved backwards")
        if self.security_hold and target not in {
            OperationStatus.BLOCKED,
            OperationStatus.RECOVERY_REQUIRED,
        }:
            raise ContractError("Security hold blocks operation progress")
        return replace(self, status=target, revision=self.revision + 1, updated_at=now)
