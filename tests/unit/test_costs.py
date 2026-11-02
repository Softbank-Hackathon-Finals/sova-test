from dataclasses import replace
from datetime import timedelta
from decimal import Decimal

import pytest

from sova.domain.contracts import ContractError
from sova.domain.costs import (
    COST_CATEGORIES,
    TRANSITION_CATEGORIES,
    CostEstimate,
    CostItem,
    TransitionEstimate,
    compare_estimates,
)


@pytest.fixture
def estimates(scope, now):
    def make(total="100", **changes):
        items = tuple(
            CostItem(
                name,
                Decimal(total) if i == 0 else Decimal("0"),
                "USD",
                f"synthetic-price-fixture:{name}",
                "a" * 64,
            )
            for i, name in enumerate(COST_CATEGORIES)
        )
        quote = CostEstimate(
            scope,
            "USD",
            Decimal("100"),
            "b" * 64,
            "c" * 64,
            items,
            now - timedelta(minutes=1),
            now + timedelta(minutes=10),
            "explicit-app-only-allocation",
        )
        return replace(quote, **changes)

    return make


def compare(a, b, now, **changes):
    args = dict(
        one_time_costs=TransitionEstimate(
            a.scope,
            b.scope,
            a.currency,
            a.workload_digest,
            a.slo_digest,
            tuple(
                CostItem(
                    name,
                    Decimal("10") if i == 0 else Decimal("0"),
                    a.currency,
                    "synthetic-migration-fixture:" + name,
                    "e" * 64,
                )
                for i, name in enumerate(TRANSITION_CATEGORIES)
            ),
            now - timedelta(minutes=1),
            now + timedelta(minutes=5),
        ),
        horizon_hours=Decimal("100"),
        now=now,
    )
    args.update(changes)
    return compare_estimates(a, b, **args)


def test_same_period_workload_slo_and_explicit_one_time_cost(estimates, scope, now):
    a = estimates("100")
    b = estimates("50", scope=replace(scope, environment_id="target"))
    result = compare(a, b, now)
    assert Decimal(result["net_saving"]) == Decimal("40")
    assert Decimal(result["payback_hours"]) == Decimal("20")
    assert result["economically_beneficial"] and not result["execution_authorized"]
    assert (
        result["kind"] == "estimated" and "not-a-spending-cap" in result["limitations"]
    )


def test_cheaper_running_cost_can_still_lose_money(estimates, scope, now):
    a = estimates("100")
    b = estimates("95", scope=replace(scope, environment_id="target"))
    result = compare(a, b, now)
    assert Decimal(result["net_saving"]) == Decimal("-5")
    assert not result["economically_beneficial"]


def test_more_expensive_target_has_no_payback(estimates, scope, now):
    result = compare(
        estimates("100"),
        estimates("120", scope=replace(scope, environment_id="target")),
        now,
    )
    assert result["payback_hours"] is None and not result["economically_beneficial"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("workload_digest", "d" * 64),
        ("slo_digest", "d" * 64),
        ("period_hours", Decimal("200")),
    ],
)
def test_incomparable_workloads_periods_and_slos_fail_closed(
    estimates, scope, now, field, value
):
    with pytest.raises(ContractError, match="must match"):
        compare(
            estimates(),
            estimates(scope=replace(scope, environment_id="target"), **{field: value}),
            now,
        )


def test_mixed_currency_and_incomplete_tco_are_not_guessed(estimates, scope, now):
    a = estimates()
    with pytest.raises(ContractError, match="category"):
        replace(a, items=a.items[:-1])
    b = estimates(scope=replace(scope, environment_id="target"))
    with pytest.raises(ContractError, match="currency"):
        compare(
            a,
            b,
            now,
            one_time_costs=TransitionEstimate(
                a.scope,
                b.scope,
                "JPY",
                a.workload_digest,
                a.slo_digest,
                tuple(
                    CostItem(name, Decimal("0"), "JPY", "fixture", "e" * 64)
                    for name in TRANSITION_CATEGORIES
                ),
                now - timedelta(minutes=1),
                now + timedelta(minutes=5),
            ),
        )
    with pytest.raises(ContractError):
        compare(a, b, now, one_time_costs=())


@pytest.mark.parametrize(
    "value", [1.5, True, Decimal("NaN"), Decimal("Infinity"), Decimal("-1")]
)
def test_invalid_amounts_rejected(value):
    with pytest.raises(ContractError):
        CostItem("compute", value, "USD", "fixture", "a" * 64)


def test_expired_price_and_cross_tenant_quote_cannot_be_used(estimates, scope, now):
    a = estimates()
    b = estimates(scope=replace(scope, environment_id="target"), valid_until=now)
    with pytest.raises(ContractError, match="expired"):
        compare(a, b, now)
    with pytest.raises(ContractError, match="same-application"):
        compare(
            a,
            estimates(scope=replace(scope, tenant_id="other", environment_id="target")),
            now,
        )


def test_transition_quote_cannot_omit_zero_categories_or_use_stale_evidence(
    estimates, scope, now
):
    a, b = estimates(), estimates(scope=replace(scope, environment_id="target"))
    items = tuple(
        CostItem(name, Decimal("0"), "USD", "fixture", "e" * 64)
        for name in TRANSITION_CATEGORIES
    )
    quote = TransitionEstimate(
        a.scope,
        b.scope,
        "USD",
        a.workload_digest,
        a.slo_digest,
        items,
        now - timedelta(minutes=1),
        now + timedelta(minutes=1),
    )
    with pytest.raises(ContractError, match="category"):
        replace(quote, items=items[:-1])
    with pytest.raises(ContractError, match="expired"):
        compare(a, b, now, one_time_costs=replace(quote, valid_until=now))
    with pytest.raises(ContractError, match="mismatch"):
        compare(a, b, now, one_time_costs=replace(quote, workload_digest="f" * 64))
