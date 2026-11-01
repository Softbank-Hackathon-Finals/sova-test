from dataclasses import asdict, replace
from datetime import timedelta

import pytest

from sova.adapters.otel_collector import TelemetryProducer, collector_configuration
from sova.adapters.otlp_projection import project_otlp
from sova.domain.contracts import ContractError


@pytest.fixture
def producer(scope, now):
    return TelemetryProducer(
        "source",
        scope,
        "a" * 64,
        4318,
        "/secrets/source.token",
        ("/health", "/rooms/{room_id}/messages"),
        now + timedelta(minutes=5),
    )


def test_configuration_separates_credentials_and_overwrites_identity(producer, now):
    target = replace(
        producer,
        producer_id="target",
        port=4319,
        token_file="/secrets/target.token",
        scope=replace(producer.scope, environment_id="target"),
    )
    config = collector_configuration(
        (producer, target), backend_endpoint="https://backend:8443", now=now
    )
    assert len(config["receivers"]) == len(config["service"]["pipelines"]) == 2
    assert (
        config["extensions"]["bearertokenauth/source"]["filename"]
        != config["extensions"]["bearertokenauth/target"]["filename"]
    )
    assert (
        "keep_keys(resource.attributes, [])"
        in config["processors"]["transform/source"]["trace_statements"][0]["statements"]
    )
    assert "file" not in config["exporters"]
    assert all("tls" in value for value in config["exporters"].values())


@pytest.mark.parametrize(
    "endpoint",
    ["http://backend", "https://user:secret@backend", "https://backend?token=secret"],
)
def test_backend_must_be_fixed_https_without_embedded_secret(producer, now, endpoint):
    with pytest.raises(ContractError):
        collector_configuration((producer,), backend_endpoint=endpoint, now=now)


def test_expired_or_duplicate_producer_blocked(producer, now):
    for producers in ((producer, producer), (replace(producer, valid_until=now),)):
        with pytest.raises(ContractError):
            collector_configuration(
                producers, backend_endpoint="https://backend", now=now
            )


def frame(producer, now):
    module = pytest.importorskip(
        "opentelemetry.proto.collector.trace.v1.trace_service_pb2"
    )
    msg = module.ExportTraceServiceRequest()
    resource = msg.resource_spans.add()
    for key, value in producer.labels.items():
        attr = resource.resource.attributes.add(key=key)
        attr.value.string_value = value
    span = resource.scope_spans.add().spans.add()
    span.trace_id = bytes.fromhex("1" * 32)
    span.span_id = bytes.fromhex("2" * 16)
    span.name = "private-customer-name"
    span.kind = 2
    span.end_time_unix_nano = int((now - timedelta(seconds=1)).timestamp() * 10**9)
    span.start_time_unix_nano = span.end_time_unix_nano - 100000000
    span.attributes.add(key="http.route").value.string_value = "/health"
    span.attributes.add(key="http.response.status_code").value.int_value = 200
    span.attributes.add(key="db.statement").value.string_value = "private sql"
    return msg


def test_projection_authenticates_before_parse_and_keeps_only_safe_fields(
    producer, now
):
    calls = []
    message = frame(producer, now)
    result = project_otlp(
        message.SerializeToString(),
        (producer,),
        authenticate_collector=lambda: calls.append("auth"),
        now=now,
    )
    assert calls == ["auth"] and len(result) == 1
    assert result[0].scope == producer.scope
    assert "private" not in repr(asdict(result[0]))


def test_projection_rejects_forged_resource_and_future_or_unknown_route(producer, now):
    for mutate in ("resource", "future", "route", "duplicate"):
        msg = frame(producer, now)
        resource = msg.resource_spans[0]
        span = resource.scope_spans[0].spans[0]
        if mutate == "resource":
            resource.resource.attributes[0].value.string_value = "attacker"
        if mutate == "future":
            span.end_time_unix_nano = int(
                (now + timedelta(minutes=1)).timestamp() * 10**9
            )
        if mutate == "route":
            span.attributes[0].value.string_value = "/private-user-id"
        if mutate == "duplicate":
            span.attributes.add(key="http.route").value.string_value = "/health"
        with pytest.raises(ContractError):
            project_otlp(
                msg.SerializeToString(),
                (producer,),
                authenticate_collector=lambda: None,
                now=now,
            )


def test_projection_transport_denial_precedes_any_parsing(producer, now):
    def deny():
        raise PermissionError("untrusted collector")

    with pytest.raises(PermissionError):
        project_otlp(b"invalid", (producer,), authenticate_collector=deny, now=now)


def test_client_or_internal_span_cannot_inflate_server_request_counts(producer, now):
    for kind in (0, 1, 3, 4, 5):
        message = frame(producer, now)
        message.resource_spans[0].scope_spans[0].spans[0].kind = kind
        with pytest.raises(ContractError, match="server spans"):
            project_otlp(
                message.SerializeToString(),
                (producer,),
                authenticate_collector=lambda: None,
                now=now,
            )
