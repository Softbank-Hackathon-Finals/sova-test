from dataclasses import dataclass
from typing import Protocol

from sova.domain.plans import Inspection, LifecyclePlan, PlanApproval


class RepositoryConflict(RuntimeError):
    pass


class RecordNotFound(LookupError):
    """Missing or outside the caller's tenant/application scope."""


@dataclass(frozen=True, slots=True)
class StoredApproval:
    approval_id: str
    plan_id: str
    approval: PlanApproval
    revision: int
    revoked: bool


class LifecycleRepository(Protocol):
    tenant_id: str

    def save_plan(self, plan: LifecyclePlan) -> None: ...
    def get_plan(self, application_id: str, plan_id: str) -> LifecyclePlan: ...
    def save_inspection(self, inspection_id: str, inspection: Inspection) -> None: ...
    def get_inspection(self, application_id: str, inspection_id: str) -> Inspection: ...
    def save_approval(
        self,
        application_id: str,
        plan_id: str,
        approval_id: str,
        approval: PlanApproval,
    ) -> StoredApproval: ...
    def get_approval(self, application_id: str, approval_id: str) -> StoredApproval: ...
    def revoke_approval(
        self,
        application_id: str,
        approval_id: str,
        *,
        expected_revision: int,
        actor_id: str,
    ) -> StoredApproval: ...
