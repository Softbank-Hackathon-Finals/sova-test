"""Bounded OTel-compatible span normalization, not an OTLP collector or audit log.

The ingress supplies authenticated resource identity. Raw prompts, SQL, URLs,
headers, user IDs and arbitrary attributes are never copied into output. Route
templates must belong to an operator-selected allowlist; trace IDs are not metric
labels. A sampled observation window is never treated as total traffic or billing.
"""

from dataclasses import dataclass
import math
import re

from sova.domain.contracts import ContractError, ResourceScope, digest, identifier, utc


@dataclass(frozen=True, slots=True)
class SpanObservation:
    scope: ResourceScope
    deployment_digest: str
    trace_id: str
    span_id: str
    start_ns: int
    end_ns: int
    http_status: int
    route_template: str

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope):
            raise ContractError("Authenticated observation scope required")
        digest(self.deployment_digest)
        for value, size in ((self.trace_id, 32), (self.span_id, 16)):
            if (
                type(value) is not str
                or not re.fullmatch(f"[0-9a-f]{{{size}}}", value)
                or set(value) == {"0"}
            ):
                raise ContractError("Nonzero OTel trace/span identifiers required")
        if (
            type(self.start_ns) is not int
            or type(self.end_ns) is not int
            or not 0 < self.start_ns <= self.end_ns
            or self.end_ns - self.start_ns > 3600 * 10**9
        ):
            raise ContractError("Bounded nonnegative span duration required")
        if type(self.http_status) is not int or not 100 <= self.http_status <= 599:
            raise ContractError("HTTP response code required")
        identifier(self.route_template, limit=128)

    @property
    def duration_ms(self):
        return (self.end_ns - self.start_ns) / 1000000


def normalize_http_span(raw, *, scope, deployment_digest, allowed_routes):
    if (
        type(raw) is not dict
        or set(raw) != {"trace_id", "span_id", "start_ns", "end_ns", "attributes"}
        or type(raw["attributes"]) is not dict
        or len(raw["attributes"]) > 64
    ):
        raise ContractError("Bounded HTTP span input required")
    if type(allowed_routes) is not tuple or not 1 <= len(allowed_routes) <= 64:
        raise ContractError("Operator-selected route templates required")
    attrs = raw["attributes"]
    route = attrs.get("http.route")
    if route not in allowed_routes:
        raise ContractError("Unknown HTTP route template")
    # scope/deployment are never accepted from untrusted span attributes.
    return SpanObservation(
        scope,
        deployment_digest,
        raw["trace_id"],
        raw["span_id"],
        raw["start_ns"],
        raw["end_ns"],
        attrs.get("http.response.status_code"),
        route,
    )


def observation_window(
    spans,
    *,
    scope,
    deployment_digest,
    start,
    end,
    observed_at,
    valid_until,
    now,
    dropped_count=None,
):
    if not isinstance(scope, ResourceScope):
        raise ContractError("Typed observation scope required")
    digest(deployment_digest)
    start, end, observed_at, valid_until = map(
        utc, (start, end, observed_at, valid_until)
    )
    now = utc(now)
    if (
        not start < end <= observed_at <= now < valid_until
        or (end - start).total_seconds() > 3600
        or type(spans) is not tuple
        or len(spans) > 100000
        or (
            dropped_count is not None
            and (type(dropped_count) is not int or dropped_count < 0)
        )
    ):
        raise ContractError("Bounded observation window and loss count required")
    unique = {}
    start_ns, end_ns = int(start.timestamp() * 10**9), int(end.timestamp() * 10**9)
    for span in spans:
        if (
            not isinstance(span, SpanObservation)
            or span.scope != scope
            or span.deployment_digest != deployment_digest
        ):
            raise ContractError("Cross-scope or stale-deployment span rejected")
        if not start_ns <= span.end_ns < end_ns:
            raise ContractError("Span outside declared observation window")
        key = span.trace_id, span.span_id
        if key in unique and unique[key] != span:
            raise ContractError("Conflicting duplicate span")
        unique[key] = span
    values = list(unique.values())
    times = sorted(s.duration_ms for s in values)
    failures = sum(s.http_status >= 500 for s in values)
    return {
        "scope": {
            k: getattr(scope, k)
            for k in ("tenant_id", "application_id", "environment_id", "resource_id")
        },
        "deployment_digest": deployment_digest,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "observed_at": observed_at.isoformat(),
        "valid_until": valid_until.isoformat(),
        "observed_requests": len(values),
        "observed_failures": failures,
        "observed_error_ratio": failures / len(values) if values else None,
        "observed_p95_ms": times[max(0, math.ceil(len(times) * 0.95) - 1)]
        if times
        else None,
        "dropped_count": dropped_count,
        "loss_observation_available": dropped_count is not None,
        "no_reported_loss": dropped_count == 0,
        "sample_usable": bool(values) and dropped_count == 0,
        "execution_authorized": False,
        "scope_note": "sampled HTTP observations; not total traffic, billing, or immutable audit",
    }
