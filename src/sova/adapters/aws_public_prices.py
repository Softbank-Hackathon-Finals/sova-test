"""Read official unit prices without treating a partial rate as an app quote.

First qualified profile: current-generation Single-AZ PostgreSQL RDS instance
hours, standard AWS partition, public USD On-Demand rates. CPU credits, storage,
backup, network, discounts/taxes and shared allocation remain separate sources.
"""

from dataclasses import dataclass, asdict
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation, localcontext
import hashlib
import re

from sova.adapters.registration.graph_codec import json_document
from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova.domain.costs import CostItem


@dataclass(frozen=True, slots=True)
class RDSRateRequest:
    scope: ResourceScope
    configuration_digest: str
    region: str
    instance_type: str
    issued_at: datetime
    valid_until: datetime

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Typed price request scope required")
        digest(self.configuration_digest)
        if type(self.region) is not str or not re.fullmatch(
            r"[a-z]{2}(?:-[a-z]+)+-[1-9][0-9]?", self.region
        ):
            raise ContractError("Explicit price region required")
        if type(self.instance_type) is not str or not re.fullmatch(
            r"db\.[a-z0-9]+\.(?:micro|small|medium|large|xlarge|[1-9][0-9]*xlarge)",
            self.instance_type,
        ):
            raise ContractError("Explicit RDS instance class required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Positive price request lifetime required")

    @property
    def filters(self):
        return {
            "regionCode": self.region,
            "databaseEngine": "PostgreSQL",
            "instanceType": self.instance_type,
            "deploymentOption": "Single-AZ",
            "currentGeneration": "Yes",
        }


@dataclass(frozen=True, slots=True)
class RDSPublicHourlyRate:
    request: RDSRateRequest
    sku: str
    offer_term: str
    rate_code: str
    price_version: str
    unit_price_usd: Decimal
    effective_at: datetime
    observed_at: datetime
    valid_until: datetime
    document_digest: str

    def __post_init__(self):
        if not isinstance(self.request, RDSRateRequest):
            raise ContractError("Typed price profile required")
        for value in (self.sku, self.offer_term, self.rate_code, self.price_version):
            identifier(value)
        value = self.unit_price_usd
        if (
            type(value) is not Decimal
            or not value.is_finite()
            or not Decimal(0) <= value <= Decimal("1e18")
            or not -18 <= value.as_tuple().exponent <= 18
        ):
            raise ContractError("Bounded finite public unit price required")
        for field in ("effective_at", "observed_at", "valid_until"):
            object.__setattr__(self, field, utc(getattr(self, field)))
        if (
            not self.effective_at
            <= self.observed_at
            < self.valid_until
            <= self.request.valid_until
        ):
            raise ContractError("Current bounded public rate validity required")
        digest(self.document_digest)

    @property
    def source_ref(self):
        return (
            f"aws-price-list:AmazonRDS:{self.sku}:{self.rate_code}:{self.price_version}"
        )

    def compute_item(self, *, whole_hours, now):
        if type(whole_hours) is not int or not 1 <= whole_hours <= 8784:
            raise ContractError("Bounded whole-hour forecast quantity required")
        if not self.observed_at <= utc(now) < self.valid_until:
            raise ContractError("Public unit price is not current")
        with localcontext() as context:
            context.prec = 96
            cost = self.unit_price_usd * Decimal(whole_hours)
        return CostItem("compute", cost, "USD", self.source_ref, self.document_digest)

    def report(self):
        return {
            "kind": "public-unit-rate",
            "scope": asdict(self.request.scope),
            "configuration_digest": self.request.configuration_digest,
            "region": self.request.region,
            "instance_type": self.request.instance_type,
            "sku": self.sku,
            "rate_code": self.rate_code,
            "price_version": self.price_version,
            "unit": "Hrs",
            "currency": "USD",
            "unit_price": str(self.unit_price_usd),
            "effective_at": self.effective_at.isoformat(),
            "observed_at": self.observed_at.isoformat(),
            "valid_until": self.valid_until.isoformat(),
            "source_ref": self.source_ref,
            "source_digest": self.document_digest,
            "complete_cost_estimate": False,
            "bill_verified": False,
            "execution_authorized": False,
            "not_included": [
                "cpu-credits",
                "storage",
                "network",
                "backup",
                "operations",
                "shared-allocation",
                "discounts-and-taxes",
            ],
        }


class AWSPublicPriceCollector:
    def __init__(
        self,
        client,
        *,
        authorize,
        authenticate_request,
        clock=lambda: datetime.now(UTC),
    ):
        self.client, self.authorize, self.authenticate_request, self.clock = (
            client,
            authorize,
            authenticate_request,
            clock,
        )

    def _check(self, actor, request):
        if not isinstance(request, RDSRateRequest):
            raise ContractError("Typed price request required")
        self.authorize(actor, request.scope, "cost:read-public-prices")
        self.authenticate_request(request)
        if not request.issued_at <= utc(self.clock()) < request.valid_until:
            raise ContractError("Price request is not current")
        client = self.client
        if (
            client.meta.service_model.service_name != "pricing"
            or client.meta.region_name != "us-east-1"
            or client.meta.endpoint_url.rstrip("/")
            != "https://api.pricing.us-east-1.amazonaws.com"
            or client._endpoint.http_session._verify is not True
            or not 0 < client.meta.config.connect_timeout <= 5
            or not 0 < client.meta.config.read_timeout <= 10
            or not 1 <= client.meta.config.retries.get("total_max_attempts", 0) <= 2
        ):
            raise ContractError(
                "Registered certificate-verified AWS public pricing endpoint required"
            )

    def rds_hourly(self, actor, request):
        self._check(actor, request)
        started = utc(self.clock())
        records = {}
        token = None
        for page in range(3):
            self._check(actor, request)
            args = {
                "ServiceCode": "AmazonRDS",
                "Filters": [
                    {"Type": "TERM_MATCH", "Field": k, "Value": v}
                    for k, v in request.filters.items()
                ],
                "MaxResults": 20,
            }
            if token is not None:
                args["NextToken"] = token
            response = self.client.get_products(**args)
            if response.get("FormatVersion") != "aws_v1":
                raise ContractError("Unsupported public pricing format")
            values = response.get("PriceList")
            if type(values) is not list or len(values) > 20:
                raise ContractError("Bounded public pricing page required")
            for raw in values:
                record = json_document(raw, limit=262144)
                if type(record) is not dict or type(record.get("product")) is not dict:
                    raise ContractError("Explicit pricing product object required")
                product = record.get("product", {})
                sku = product.get("sku")
                identifier(sku, "SKU")
                fingerprint = hashlib.sha256(
                    canonical_json(record, limit=262144).encode()
                ).hexdigest()
                if sku in records and records[sku][1] != fingerprint:
                    raise ContractError("Public price SKU has conflicting records")
                records[sku] = (record, fingerprint)
            token = response.get("NextToken")
            if token is None:
                break
            identifier(token, "price pagination token", limit=4096)
        if token is not None:
            raise ContractError("Public pricing response was incomplete")
        self._check(actor, request)
        now = utc(self.clock())
        if now < started:
            raise ContractError("Price observation clock moved backwards")
        candidates = []
        for record, fingerprint in records.values():
            product = record["product"]
            attributes = product.get("attributes", {})
            if (
                type(attributes) is not dict
                or record.get("serviceCode") != "AmazonRDS"
                or product.get("productFamily") != "Database Instance"
                or any(attributes.get(k) != v for k, v in request.filters.items())
            ):
                raise ContractError("Pricing response differs from exact RDS profile")
            usage = attributes.get("usagetype", "")
            if type(usage) is not str:
                raise ContractError("Explicit pricing usage type required")
            if not usage.endswith("InstanceUsage:" + request.instance_type):
                continue  # e.g. UnusedBox is not an active database instance hour.
            try:
                publication = utc(datetime.fromisoformat(record["publicationDate"]))
            except (ValueError, TypeError, KeyError) as exc:
                raise ContractError(
                    "Explicit public price publication date required"
                ) from exc
            if publication > now:
                raise ContractError("Future public price publication cannot be used")
            all_terms = record.get("terms", {})
            if type(all_terms) is not dict:
                raise ContractError("Explicit pricing terms object required")
            terms = all_terms.get("OnDemand", {})
            if type(terms) is not dict or not 1 <= len(terms) <= 16:
                raise ContractError("Bounded public On-Demand terms required")
            for term_key, term in terms.items():
                if (
                    type(term) is not dict
                    or term.get("sku") != product["sku"]
                    or term.get("termAttributes") != {}
                    or term_key != product["sku"] + "." + str(term.get("offerTermCode"))
                ):
                    raise ContractError("Conditional or mismatched public price term")
                try:
                    effective = utc(datetime.fromisoformat(term["effectiveDate"]))
                except (ValueError, TypeError, KeyError) as exc:
                    raise ContractError(
                        "Explicit public price effective date required"
                    ) from exc
                if effective > now:
                    continue
                dimensions = term.get("priceDimensions", {})
                if type(dimensions) is not dict or len(dimensions) != 1:
                    raise ContractError(
                        "Only one flat instance-hour price is supported"
                    )
                dimension = next(iter(dimensions.values()))
                if (
                    type(dimension) is not dict
                    or dimension.get("unit") != "Hrs"
                    or dimension.get("beginRange") != "0"
                    or dimension.get("endRange") != "Inf"
                    or dimension.get("appliesTo") != []
                    or type(dimension.get("pricePerUnit")) is not dict
                    or set(dimension["pricePerUnit"]) != {"USD"}
                    or next(iter(dimensions)) != dimension.get("rateCode")
                    or not str(dimension.get("rateCode")).startswith(term_key + ".")
                ):
                    raise ContractError(
                        "Tiered/non-hourly/currency-dependent price is unsupported"
                    )
                raw = dimension["pricePerUnit"]["USD"]
                if type(raw) is not str or len(raw) > 64:
                    raise ContractError("Bounded explicit public price required")
                try:
                    value = Decimal(raw)
                except InvalidOperation as exc:
                    raise ContractError("Invalid public price amount") from exc
                candidates.append(
                    RDSPublicHourlyRate(
                        request,
                        product["sku"],
                        term["offerTermCode"],
                        dimension["rateCode"],
                        record["version"],
                        value,
                        effective,
                        now,
                        min(request.valid_until, now + timedelta(hours=6)),
                        fingerprint,
                    )
                )
        if not candidates:
            raise ContractError("No qualified current RDS instance-hour rate found")
        if len({c.sku for c in candidates}) != 1:
            raise ContractError(
                "Ambiguous current public rates; multiple matching SKUs"
            )
        newest = max(c.effective_at for c in candidates)
        matches = [c for c in candidates if c.effective_at == newest]
        if len(matches) != 1:
            raise ContractError(
                "Ambiguous current public rates; cannot choose a cheaper SKU"
            )
        return matches[0]
