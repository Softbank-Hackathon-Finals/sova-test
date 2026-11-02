from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
from unittest.mock import Mock

import pytest

from sova.application.cost_advisor import CostAdvisor, quote_digest
from sova.domain.contracts import ContractError
from sova.domain.costs import (
    COST_CATEGORIES,
    TRANSITION_CATEGORIES,
    CostItem,
    CostEstimate,
    TransitionEstimate,
)


@pytest.fixture
def advisor(scope, now):
    target = replace(scope, environment_id="target")

    def items(names, price):
        return tuple(
            CostItem(
                name,
                Decimal(price) if i == 0 else Decimal("0"),
                "USD",
                "synthetic-fixture:" + name,
                "a" * 64,
            )
            for i, name in enumerate(names)
        )

    common = ("USD", Decimal("100"), "b" * 64, "c" * 64)
    source_quote = CostEstimate(
        scope,
        *common,
        items(COST_CATEGORIES, "100"),
        now - timedelta(minutes=1),
        now + timedelta(minutes=10),
        "app-only-allocation",
    )
    target_quote = replace(
        source_quote, scope=target, items=items(COST_CATEGORIES, "50")
    )
    transition = TransitionEstimate(
        scope,
        target,
        "USD",
        "b" * 64,
        "c" * 64,
        items(TRANSITION_CATEGORIES, "10"),
        now - timedelta(minutes=1),
        now + timedelta(minutes=5),
    )
    service = CostAdvisor(
        quote_provider=Mock(side_effect=[source_quote, target_quote]),
        transition_provider=Mock(return_value=transition),
        authorize=Mock(),
        authenticate_quote=Mock(),
        clock=lambda: now,
    )
    args = dict(
        source_scope=scope,
        target_scope=target,
        workload_digest="b" * 64,
        slo_digest="c" * 64,
        horizon_hours=Decimal("100"),
    )
    return service, args, source_quote, target_quote, transition


def test_authorized_comparison_binds_all_authenticated_quotes_and_remains_nonexecutable(
    advisor,
):
    service, args, *quotes = advisor
    result = service.compare("operator", **args)
    assert (
        result["net_saving"] == "40.0"
        and result["analysis_only"]
        and not result["execution_authorized"]
    )
    assert (
        service.authenticate_quote.call_count == 3 and service.authorize.call_count == 4
    )
    assert result["quote_digests"]["transition"] == quote_digest(quotes[2])
    assert quote_digest(
        replace(quotes[0], allocation_ref="different-allocation")
    ) != quote_digest(quotes[0])


def test_authorization_precedes_any_quote_lookup(advisor):
    service, args, *_ = advisor
    service.authorize.side_effect = PermissionError("denied")
    with pytest.raises(PermissionError):
        service.compare("unknown", **args)
    service.quote_provider.assert_not_called()
    service.transition_provider.assert_not_called()


def test_source_authentication_and_scope_drift_fail_closed(advisor):
    service, args, source, target, _ = advisor
    service.quote_provider.side_effect = [replace(source, scope=target.scope), target]
    with pytest.raises(ContractError, match="different"):
        service.compare("operator", **args)


def test_revoked_or_expired_transition_is_not_treated_as_zero(advisor, now):
    service, args, _, _, transition = advisor
    service.transition_provider.return_value = replace(transition, valid_until=now)
    with pytest.raises(ContractError, match="expired"):
        service.compare("operator", **args)


def test_untrusted_quote_never_produces_a_comparison(advisor):
    service, args, *_ = advisor
    service.authenticate_quote.side_effect = PermissionError("source not registered")
    with pytest.raises(PermissionError):
        service.compare("operator", **args)
