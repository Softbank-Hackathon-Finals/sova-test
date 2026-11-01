"""Generate a bounded standard Collector configuration, not a custom collector.

Receiver authentication is separate per registered producer. Client-supplied
resource labels are replaced, not trusted. Deployers still owe CNI/egress,
secret delivery/rotation, host isolation and HA qualification. This configuration
exports to an authenticated HTTPS backend; it never writes raw OTLP to disk.
"""

from dataclasses import dataclass
from datetime import datetime
import json
import re
from urllib.parse import urlsplit

from sova.domain.contracts import ContractError, ResourceScope, digest, utc


COLLECTOR_IMAGE = "otel/opentelemetry-collector-contrib@sha256:340c9ca6a36617084c6661bdc4f0fe92b7cda5a805d61673ec8db375fddc522b"


@dataclass(frozen=True, slots=True)
class TelemetryProducer:
    producer_id: str
    scope: ResourceScope
    deployment_digest: str
    port: int
    token_file: str
    routes: tuple[str, ...]
    valid_until: datetime

    def __post_init__(self):
        if (
            type(self.producer_id) is not str
            or not re.fullmatch("[a-z][a-z0-9_-]{0,31}", self.producer_id)
            or not isinstance(self.scope, ResourceScope)
        ):
            raise ContractError("Registered telemetry producer identity required")
        digest(self.deployment_digest)
        if type(self.port) is not int or not 1024 <= self.port <= 65535:
            raise ContractError("Bounded producer listener port required")
        if type(self.token_file) is not str or not re.fullmatch(
            r"/secrets/[a-z0-9_-]{1,64}\.token", self.token_file
        ):
            raise ContractError("Fixed mounted telemetry token filename required")
        if (
            type(self.routes) is not tuple
            or not 1 <= len(self.routes) <= 64
            or len(set(self.routes)) != len(self.routes)
        ):
            raise ContractError("Explicit unique route templates required")
        for route in self.routes:
            if type(route) is not str or not re.fullmatch(
                r"/[A-Za-z0-9_/{}/.-]{0,127}", route
            ):
                raise ContractError("Bounded route template required")
        object.__setattr__(self, "valid_until", utc(self.valid_until))

    @property
    def labels(self):
        return {
            "sova.tenant.id": self.scope.tenant_id,
            "sova.application.id": self.scope.application_id,
            "sova.environment.id": self.scope.environment_id,
            "sova.resource.id": self.scope.resource_id,
            "sova.deployment.digest": self.deployment_digest,
            "service.name": "consultation",
        }


def collector_configuration(producers, *, backend_endpoint, now):
    if (
        type(producers) is not tuple
        or not 1 <= len(producers) <= 16
        or any(not isinstance(p, TelemetryProducer) for p in producers)
    ):
        raise ContractError("Bounded immutable producer registrations required")
    if any(
        len({getattr(p, key) for p in producers}) != len(producers)
        for key in ("producer_id", "port", "token_file", "scope")
    ):
        raise ContractError(
            "Producer IDs, scopes, listeners and credentials must be distinct"
        )
    if any(utc(now) >= p.valid_until for p in producers):
        raise ContractError("Expired telemetry producer registration")
    parsed = urlsplit(backend_endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ContractError("Registered HTTPS telemetry backend required")
    config = {
        "extensions": {
            "bearertokenauth/backend": {"filename": "/secrets/backend.token"}
        },
        "receivers": {},
        "processors": {
            "memory_limiter": {
                "check_interval": "1s",
                "limit_mib": 64,
                "spike_limit_mib": 16,
            },
            "batch": {
                "timeout": "200ms",
                "send_batch_size": 64,
                "send_batch_max_size": 128,
            },
        },
        "exporters": {
            "otlp_http/backend": {
                "endpoint": backend_endpoint,
                "compression": "none",
                "auth": {"authenticator": "bearertokenauth/backend"},
                "tls": {
                    "ca_file": "/tls/ca.pem",
                    "cert_file": "/tls/collector.pem",
                    "key_file": "/tls/collector.key",
                },
                "timeout": "3s",
                "sending_queue": {
                    "enabled": True,
                    "queue_size": 64,
                    "num_consumers": 1,
                },
                "retry_on_failure": {
                    "enabled": True,
                    "initial_interval": "1s",
                    "max_interval": "2s",
                    "max_elapsed_time": "5s",
                },
            }
        },
        "service": {
            "extensions": ["bearertokenauth/backend"],
            "pipelines": {},
            "telemetry": {"logs": {"level": "warn"}},
        },
    }
    for p in producers:
        suffix = p.producer_id
        auth = "bearertokenauth/" + suffix
        receiver = "otlp/" + suffix
        reject = "filter/" + suffix
        clean = "transform/" + suffix
        config["extensions"][auth] = {"filename": p.token_file}
        config["service"]["extensions"].append(auth)
        config["receivers"][receiver] = {
            "protocols": {
                "http": {
                    "endpoint": f"0.0.0.0:{p.port}",
                    "auth": {"authenticator": auth},
                    "tls": {
                        "cert_file": "/tls/collector.pem",
                        "key_file": "/tls/collector.key",
                        "client_ca_file": "/tls/ca.pem",
                    },
                }
            }
        }
        route_allow = " or ".join(
            f'span.attributes["http.route"] == {json.dumps(route)}'
            for route in p.routes
        )
        method_allow = " or ".join(
            f'span.attributes["http.request.method"] == {json.dumps(method)}'
            for method in ("GET", "POST", "PUT", "DELETE", "HEAD")
        )
        config["processors"][reject] = {
            "error_mode": "propagate",
            "trace_conditions": [
                "span.kind != SPAN_KIND_SERVER",
                "Len(span.events) > 0",
                "Len(span.links) > 0",
                f"not ({route_allow})",
                f"not ({method_allow})",
                'not IsInt(span.attributes["http.response.status_code"])',
                'span.attributes["http.response.status_code"] < 100 or span.attributes["http.response.status_code"] > 599',
            ],
        }
        statements = [
            'set(name, "HTTP")',
            'set(trace_state, "")',
            'set(status.message, "")',
            'keep_keys(attributes, ["http.route", "http.request.method", "http.response.status_code"])',
            "keep_keys(resource.attributes, [])",
            'set(instrumentation_scope.name, "sova.registered-workload")',
            'set(instrumentation_scope.version, "1")',
            "keep_keys(instrumentation_scope.attributes, [])",
        ]
        statements.extend(
            f"set(resource.attributes[{json.dumps(key)}], {json.dumps(value)})"
            for key, value in p.labels.items()
        )
        config["processors"][clean] = {
            "error_mode": "propagate",
            "trace_statements": [{"context": "span", "statements": statements}],
        }
        config["service"]["pipelines"]["traces/" + suffix] = {
            "receivers": [receiver],
            "processors": ["memory_limiter", reject, clean, "batch"],
            "exporters": ["otlp_http/backend"],
        }
    return config
