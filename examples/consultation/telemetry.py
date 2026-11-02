"""Actual OTel SDK instrumentation with explicit resource identity and bounded output.

No automatic HTTP headers, URLs, SQL, exception messages, prompts, customer IDs,
or message bodies are recorded. Collector loss is reported, not hidden.
"""

from collections import deque
from threading import Lock

from opentelemetry.trace import SpanKind
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SpanExporter,
    SpanExportResult,
    SimpleSpanProcessor,
)


class BoundedSpans(SpanExporter):
    def __init__(self, capacity=2048):
        self.rows = deque(maxlen=capacity)
        self.dropped = 0
        self.lock = Lock()

    def export(self, spans):
        with self.lock:
            for span in spans:
                if span.kind != SpanKind.SERVER:
                    continue
                if len(self.rows) == self.rows.maxlen:
                    self.dropped += 1
                self.rows.append(
                    {
                        "trace_id": f"{span.context.trace_id:032x}",
                        "span_id": f"{span.context.span_id:016x}",
                        "start_ns": span.start_time,
                        "end_ns": span.end_time,
                        "attributes": {
                            key: value
                            for key, value in span.attributes.items()
                            if key
                            in {
                                "http.route",
                                "http.request.method",
                                "http.response.status_code",
                            }
                        },
                    }
                )
        return SpanExportResult.SUCCESS

    def snapshot(self):
        with self.lock:
            return {
                "spans": list(self.rows),
                "dropped_count": self.dropped,
                "sampled": True,
            }

    def shutdown(self):
        pass


class WorkloadTelemetry:
    def __init__(
        self, *, application_id, environment, deployment_revision, exporter=None
    ):
        self.buffer = BoundedSpans()
        self.provider = TracerProvider(
            resource=Resource(
                {
                    "service.name": "consultation",
                    "sova.application.id": application_id,
                    "deployment.environment.name": environment,
                    "service.version": deployment_revision,
                }
            )
        )
        self.provider.add_span_processor(SimpleSpanProcessor(self.buffer))
        if exporter is not None:
            self.provider.add_span_processor(
                BatchSpanProcessor(
                    exporter,
                    max_queue_size=256,
                    max_export_batch_size=64,
                    schedule_delay_millis=1000,
                    export_timeout_millis=2000,
                )
            )
        self.tracer = self.provider.get_tracer("consultation.http", "1")

    def span(self, method, route):
        return self.tracer.start_as_current_span(
            method + " " + route,
            kind=SpanKind.SERVER,
            record_exception=False,
            set_status_on_exception=False,
            attributes={"http.request.method": method, "http.route": route},
        )

    def close(self):
        self.provider.shutdown()
