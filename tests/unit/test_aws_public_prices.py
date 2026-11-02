"""Pricing protocol contract tests; SDK Stubber does not contact AWS."""

from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
from decimal import Decimal
import json

import boto3
from botocore.config import Config
from botocore.stub import Stubber
import pytest

from sova.adapters.aws_public_prices import AWSPublicPriceCollector, RDSRateRequest
from sova.domain.contracts import ContractError
from sova.domain.costs import CostEstimate


@pytest.fixture
def case(now, scope):
    request = RDSRateRequest(
        scope,
        "a" * 64,
        "ap-northeast-2",
        "db.t4g.micro",
        now,
        now + timedelta(hours=12),
    )
    client = boto3.client(
        "pricing",
        region_name="us-east-1",
        aws_access_key_id="fixture",
        aws_secret_access_key="fixture",
        config=Config(
            connect_timeout=3, read_timeout=5, retries={"total_max_attempts": 1}
        ),
    )
    sku, offer, rate = "SKU1", "OFFER1", "SKU1.OFFER1.RATE1"
    record = {
        "serviceCode": "AmazonRDS",
        "version": "20261029000000",
        "publicationDate": (now - timedelta(days=1)).isoformat(),
        "product": {
            "sku": sku,
            "productFamily": "Database Instance",
            "attributes": {
                **request.filters,
                "usagetype": "APN2-InstanceUsage:db.t4g.micro",
            },
        },
        "terms": {
            "OnDemand": {
                sku + "." + offer: {
                    "sku": sku,
                    "offerTermCode": offer,
                    "termAttributes": {},
                    "effectiveDate": (now - timedelta(days=2)).isoformat(),
                    "priceDimensions": {
                        rate: {
                            "unit": "Hrs",
                            "beginRange": "0",
                            "endRange": "Inf",
                            "appliesTo": [],
                            "rateCode": rate,
                            "pricePerUnit": {"USD": "0.0250000000"},
                        }
                    },
                }
            }
        },
    }
    stub = Stubber(client)
    collector = AWSPublicPriceCollector(
        client,
        authorize=lambda *a: None,
        authenticate_request=lambda r: None,
        clock=lambda: now,
    )
    yield request, record, collector, stub
    stub.deactivate()


def response(stub, request, records, *, token=None, incoming=None):
    args = {
        "ServiceCode": "AmazonRDS",
        "Filters": [
            {"Type": "TERM_MATCH", "Field": k, "Value": v}
            for k, v in request.filters.items()
        ],
        "MaxResults": 20,
    }
    if incoming:
        args["NextToken"] = incoming
    result = {"FormatVersion": "aws_v1", "PriceList": [json.dumps(r) for r in records]}
    if token:
        result["NextToken"] = token
    stub.add_response("get_products", result, args)


def collect(case, records=None):
    request, record, collector, stub = case
    response(stub, request, records if records is not None else [record])
    stub.activate()
    return collector.rds_hourly("registered-operator", request)


def test_partial_unit_rate_has_exact_source_and_never_becomes_full_estimate(case, now):
    request, _, _, _ = case
    rate = collect(case)
    assert rate.unit_price_usd == Decimal("0.025")
    assert rate.valid_until == now + timedelta(hours=6)
    item = rate.compute_item(whole_hours=730, now=now)
    assert item.amount == Decimal("18.25")
    assert item.source_digest == rate.document_digest
    assert rate.report()["complete_cost_estimate"] is False
    assert rate.report()["execution_authorized"] is False
    with pytest.raises(ContractError, match="Every cost category"):
        CostEstimate(
            request.scope,
            "USD",
            Decimal(730),
            "a" * 64,
            "b" * 64,
            (item,),
            now,
            rate.valid_until,
            "allocation",
        )


@pytest.mark.parametrize(
    "path,value",
    [
        (("product", "attributes", "regionCode"), "us-west-2"),
        (("product", "attributes", "deploymentOption"), "Multi-AZ"),
        (("product", "attributes", "databaseEngine"), "MySQL"),
        (("product", "attributes", "currentGeneration"), "No"),
        (("product", "productFamily"), "Storage"),
        (("serviceCode",), "AmazonEC2"),
        (("product", "attributes", "usagetype"), []),
        (("terms",), []),
        (("terms", "OnDemand"), {}),
    ],
)
def test_response_profile_mismatch_never_produces_rate(case, path, value):
    record = deepcopy(case[1])
    node = record
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    with pytest.raises(ContractError):
        collect(case, [record])


@pytest.mark.parametrize(
    "field,value",
    [
        ("unit", "GB-Mo"),
        ("beginRange", "10"),
        ("endRange", "100"),
        ("appliesTo", ["conditional"]),
        ("pricePerUnit", {"JPY": "1"}),
        ("pricePerUnit", {"USD": "NaN"}),
        ("pricePerUnit", {"USD": "-1"}),
        ("pricePerUnit", {"USD": "Infinity"}),
        ("pricePerUnit", {"USD": "1e-100"}),
        ("rateCode", "OTHER.OFFER.RATE"),
    ],
)
def test_conditional_tiered_or_invalid_amount_refused(case, field, value):
    record = deepcopy(case[1])
    dimension = record["terms"]["OnDemand"]["SKU1.OFFER1"]["priceDimensions"][
        "SKU1.OFFER1.RATE1"
    ]
    dimension[field] = value
    with pytest.raises(ContractError):
        collect(case, [record])


def test_cheaper_ambiguous_sku_is_not_selected_even_with_newer_effective_date(
    case, now
):
    record = deepcopy(case[1])
    other = json.loads(json.dumps(record).replace("SKU1", "SKU2"))
    other["terms"]["OnDemand"]["SKU2.OFFER1"]["effectiveDate"] = (
        now - timedelta(hours=1)
    ).isoformat()
    with pytest.raises(ContractError, match="multiple matching SKUs"):
        collect(case, [record, other])


def test_identical_paginated_sku_is_deduplicated_but_incomplete_pages_fail(case):
    request, record, collector, stub = case
    response(stub, request, [record], token="page2")
    response(stub, request, [record], incoming="page2")
    stub.activate()
    assert collector.rds_hourly("operator", request).sku == "SKU1"
    stub.assert_no_pending_responses()


def test_conflicting_pages_and_pagination_budget_refused(case):
    request, record, collector, stub = case
    response(stub, request, [record], token="page2")
    other = deepcopy(record)
    other["version"] = "different-version"
    response(stub, request, [other], incoming="page2")
    stub.activate()
    with pytest.raises(ContractError, match="conflicting"):
        collector.rds_hourly("operator", request)


def test_future_publication_not_used(case, now):
    record = deepcopy(case[1])
    record["publicationDate"] = (now + timedelta(seconds=1)).isoformat()
    with pytest.raises(ContractError, match="Future"):
        collect(case, [record])


def test_unused_reservation_capacity_is_not_active_instance_compute(case):
    record = deepcopy(case[1])
    record["product"]["attributes"]["usagetype"] = "APN2-UnusedBox:db.t4g.micro"
    with pytest.raises(ContractError, match="No qualified"):
        collect(case, [record])


def test_incomplete_pagination_never_returns_first_page_rate(case):
    request, record, collector, stub = case
    for index in range(3):
        response(
            stub,
            request,
            [record],
            token="page" + str(index + 1),
            incoming="page" + str(index) if index else None,
        )
    stub.activate()
    with pytest.raises(ContractError, match="incomplete"):
        collector.rds_hourly("operator", request)


@pytest.mark.parametrize("bad", [[], None, "flat", {"USD": []}])
def test_malformed_price_object_returns_contract_error(case, bad):
    record = deepcopy(case[1])
    record["terms"]["OnDemand"]["SKU1.OFFER1"]["priceDimensions"]["SKU1.OFFER1.RATE1"][
        "pricePerUnit"
    ] = bad
    with pytest.raises(ContractError):
        collect(case, [record])


def test_authorization_denied_before_network(case):
    request, _, collector, _ = case

    def deny(*args):
        raise ContractError("Denied")

    collector.authorize = deny
    with pytest.raises(ContractError, match="Denied"):
        collector.rds_hourly("other-tenant", request)


@pytest.mark.parametrize("hours", [True, 0, -1, 8785, Decimal(2)])
def test_quantity_and_expired_rate_refused(case, now, hours):
    rate = collect(case)
    with pytest.raises(ContractError):
        rate.compute_item(whole_hours=hours, now=now)
    with pytest.raises(ContractError, match="current"):
        rate.compute_item(whole_hours=1, now=rate.valid_until)


def test_expired_request_and_unbounded_client_refused_without_call(case, now):
    request, _, collector, _ = case
    with pytest.raises(ContractError, match="current"):
        collector.rds_hourly(
            "operator",
            replace(request, issued_at=now - timedelta(hours=1), valid_until=now),
        )
    collector.client.meta.config.read_timeout = 60
    with pytest.raises(ContractError, match="endpoint"):
        collector.rds_hourly("operator", request)
