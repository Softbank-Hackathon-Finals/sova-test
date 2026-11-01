"""Normalize a bounded protobuf batch from an authenticated, registered Collector.

Not a general OTLP server. The transport must authenticate the collector first;
resource labels alone never authenticate a producer. Unknown fields, schema URLs,
events, links, names and raw attributes are not retained in the projection.
"""

from sova.domain.contracts import ContractError, utc
from sova.domain.telemetry import normalize_http_span
from sova.adapters.otel_collector import TelemetryProducer


def _attributes(items):
    if len(items) > 64:
        raise ContractError("Too many telemetry attributes")
    result = {}
    for item in items:
        if item.key in result:
            raise ContractError("Duplicate telemetry attribute")
        kind = item.value.WhichOneof("value")
        if kind in {"string_value", "int_value", "bool_value", "double_value"}:
            result[item.key] = getattr(item.value, kind)
        else:
            result[item.key] = None
    return result


def project_otlp(raw, producers, *, authenticate_collector, now):
    authenticate_collector()
    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= 1048576
        or type(producers) is not tuple
        or not 1 <= len(producers) <= 16
        or any(not isinstance(p, TelemetryProducer) for p in producers)
    ):
        raise ContractError("Bounded OTLP protobuf and registered producers required")
    try:
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTraceServiceRequest,
        )
        from google.protobuf.message import DecodeError
    except ImportError as exc:
        raise ContractError(
            "OTLP projection requires the observability/demo extra"
        ) from exc
    message = ExportTraceServiceRequest()
    try:
        message.ParseFromString(raw)
    except DecodeError as exc:
        raise ContractError("Invalid OTLP protobuf") from exc
    total = sum(
        len(group.spans)
        for resource in message.resource_spans
        for group in resource.scope_spans
    )
    if total > 4096:
        raise ContractError("OTLP span capacity exceeded")
    output = []
    for resource in message.resource_spans:
        labels = _attributes(resource.resource.attributes)
        matches = [
            p for p in producers if labels == p.labels and utc(now) < p.valid_until
        ]
        if len(matches) != 1:
            raise ContractError(
                "Collector resource identity is unregistered or expired"
            )
        p = matches[0]
        for group in resource.scope_spans:
            for span in group.spans:
                if span.kind != 2:
                    raise ContractError("Only registered HTTP server spans qualify")
                attrs = _attributes(span.attributes)
                projected = normalize_http_span(
                    {
                        "trace_id": span.trace_id.hex(),
                        "span_id": span.span_id.hex(),
                        "start_ns": span.start_time_unix_nano,
                        "end_ns": span.end_time_unix_nano,
                        "attributes": attrs,
                    },
                    scope=p.scope,
                    deployment_digest=p.deployment_digest,
                    allowed_routes=p.routes,
                )
                if projected.end_ns > int(utc(now).timestamp() * 10**9) + 5 * 10**9:
                    raise ContractError("Future telemetry observation rejected")
                output.append(projected)
    return tuple(output)
