"""Planning/inspection ports cannot mutate resources.

Recovery and finalization return new plans. All resource changes are executed
through EffectExecutor and the existing bounded EffectAdapter.apply boundary.
"""

from datetime import datetime
from typing import Protocol

from sova.domain.contracts import ResourceScope
from sova.domain.environments import ApplicationRevision
from sova.domain.evidence import EvidenceRecord
from sova.domain.plans import Inspection, LifecyclePlan


class LifecycleAdapter(Protocol):
    def inspect(self, scope: ResourceScope, now: datetime) -> Inspection: ...

    def plan(
        self,
        application: ApplicationRevision,
        source: Inspection,
        target: Inspection,
        now: datetime,
    ) -> LifecyclePlan: ...

    def verify(
        self, plan: LifecyclePlan, now: datetime
    ) -> tuple[EvidenceRecord, ...]: ...

    def plan_recovery(
        self, original: LifecyclePlan, current: tuple[Inspection, ...], now: datetime
    ) -> LifecyclePlan: ...

    def plan_finalization(
        self, original: LifecyclePlan, current: tuple[Inspection, ...], now: datetime
    ) -> LifecyclePlan: ...
