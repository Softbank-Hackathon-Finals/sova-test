"""Source-backed comparable estimates; never a bill, budget cap or auto-move.

All coverage categories must be explicitly priced (including explicit zero).
FX conversion and comparison of different workloads/SLOs are intentionally not
inferred. Provider adapters authenticate quote sources outside this pure model.
"""

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
import re

from sova.domain.contracts import ContractError, ResourceScope, digest, identifier, utc


COST_CATEGORIES = ("compute", "storage", "network", "backup", "operations", "shared")
TRANSITION_CATEGORIES = ("migration", "overlap", "egress")


def amount(value, field):
    if (
        type(value) is not Decimal
        or not value.is_finite()
        or value < 0
        or value > Decimal("1e18")
    ):
        raise ContractError(f"Finite nonnegative Decimal {field} required")
    return value


@dataclass(frozen=True, slots=True)
class CostItem:
    category: str
    amount: Decimal
    currency: str
    source_ref: str
    source_digest: str

    def __post_init__(self):
        identifier(self.category)
        amount(self.amount, "cost")
        if type(self.currency) is not str or not re.fullmatch(
            "[A-Z]{3}", self.currency
        ):
            raise ContractError("Explicit cost item currency required")
        identifier(self.source_ref, limit=1024)
        digest(self.source_digest)


@dataclass(frozen=True, slots=True)
class CostEstimate:
    scope: ResourceScope
    currency: str
    period_hours: Decimal
    workload_digest: str
    slo_digest: str
    items: tuple[CostItem, ...]
    observed_at: datetime
    valid_until: datetime
    allocation_ref: str

    def __post_init__(self):
        if (
            not isinstance(self.scope, ResourceScope)
            or type(self.currency) is not str
            or not re.fullmatch("[A-Z]{3}", self.currency)
        ):
            raise ContractError("Typed estimate scope and currency required")
        amount(self.period_hours, "period")
        if not Decimal("0") < self.period_hours <= Decimal("8784"):
            raise ContractError("Estimate period must be positive and at most one year")
        digest(self.workload_digest)
        digest(self.slo_digest)
        if (
            type(self.items) is not tuple
            or any(not isinstance(i, CostItem) for i in self.items)
            or len(self.items) != len(COST_CATEGORIES)
            or {i.category for i in self.items} != set(COST_CATEGORIES)
        ):
            raise ContractError("Every cost category must be explicitly estimated once")
        identifier(self.allocation_ref, limit=1024)
        if any(i.currency != self.currency for i in self.items):
            raise ContractError("Cost item currency differs from estimate")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Positive cost-source validity required")

    @property
    def total(self):
        return sum((item.amount for item in self.items), Decimal("0"))


@dataclass(frozen=True, slots=True)
class TransitionEstimate:
    source_scope: ResourceScope
    target_scope: ResourceScope
    currency: str
    workload_digest: str
    slo_digest: str
    items: tuple[CostItem, ...]
    observed_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.source_scope, ResourceScope) or not isinstance(
            self.target_scope, ResourceScope
        ):
            raise ContractError("Typed transition scopes required")
        a, b = self.source_scope, self.target_scope
        if (a.tenant_id, a.application_id) != (
            b.tenant_id,
            b.application_id,
        ) or a.environment_id == b.environment_id:
            raise ContractError("Distinct same-application transition scopes required")
        if type(self.currency) is not str or not re.fullmatch(
            "[A-Z]{3}", self.currency
        ):
            raise ContractError("Explicit transition currency required")
        digest(self.workload_digest)
        digest(self.slo_digest)
        if (
            type(self.items) is not tuple
            or len(self.items) != len(TRANSITION_CATEGORIES)
            or any(not isinstance(i, CostItem) for i in self.items)
            or {i.category for i in self.items} != set(TRANSITION_CATEGORIES)
        ):
            raise ContractError(
                "Each migration, overlap and egress category must be explicit, including zero"
            )
        if any(item.currency != self.currency for item in self.items):
            raise ContractError("Transition cost currency mismatch")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Positive transition estimate validity required")


def compare_estimates(source, target, *, one_time_costs, horizon_hours, now):
    if not isinstance(source, CostEstimate) or not isinstance(target, CostEstimate):
        raise ContractError("Typed source and target estimates required")
    a, b = source.scope, target.scope
    if (a.tenant_id, a.application_id) != (
        b.tenant_id,
        b.application_id,
    ) or a.environment_id == b.environment_id:
        raise ContractError("Distinct same-application cost scopes required")
    if (
        source.currency,
        source.period_hours,
        source.workload_digest,
        source.slo_digest,
    ) != (
        target.currency,
        target.period_hours,
        target.workload_digest,
        target.slo_digest,
    ):
        raise ContractError("Cost currency, period, workload and SLO must match")
    now = utc(now)
    if any(not q.observed_at <= now < q.valid_until for q in (source, target)):
        raise ContractError("Cost evidence expired or from future")
    if not isinstance(one_time_costs, TransitionEstimate):
        raise ContractError(
            "Scoped, current migration/overlap/egress estimate required"
        )
    transition = one_time_costs
    if (
        transition.source_scope,
        transition.target_scope,
        transition.currency,
        transition.workload_digest,
        transition.slo_digest,
    ) != (
        source.scope,
        target.scope,
        source.currency,
        source.workload_digest,
        source.slo_digest,
    ):
        raise ContractError("Transition scope/currency/workload/SLO mismatch")
    if not transition.observed_at <= now < transition.valid_until:
        raise ContractError("Transition estimate expired or from future")
    one_time_costs = transition.items
    amount(horizon_hours, "horizon")
    if not Decimal("0") < horizon_hours <= Decimal("8784"):
        raise ContractError("Bounded positive comparison horizon required")
    migration_total = sum((c.amount for c in one_time_costs), Decimal("0"))
    hourly_saving = (source.total - target.total) / source.period_hours
    net_saving = hourly_saving * horizon_hours - migration_total
    return {
        "kind": "estimated",
        "compared_at": now.isoformat(),
        "valid_until": min(
            source.valid_until, target.valid_until, transition.valid_until
        ).isoformat(),
        "currency": source.currency,
        "source_period_total": str(source.total),
        "target_period_total": str(target.total),
        "period_hours": str(source.period_hours),
        "horizon_hours": str(horizon_hours),
        "one_time_cost": str(migration_total),
        "net_saving": str(net_saving),
        "payback_hours": str(migration_total / hourly_saving)
        if hourly_saving > 0
        else None,
        "economically_beneficial": net_saving > 0,
        "execution_authorized": False,
        "required_before_proposal": [
            "authenticate-price-and-usage-sources",
            "residency",
            "security",
            "availability",
            "capacity",
            "human-or-policy-approval",
        ],
        "sources": [
            {
                "category": i.category,
                "reference": i.source_ref,
                "digest": i.source_digest,
            }
            for i in (*source.items, *target.items, *one_time_costs)
        ],
        "limitations": [
            "not-billed-cost",
            "not-a-spending-cap",
            "no-fx-inference",
            "no-free-onprem-assumption",
        ],
    }
