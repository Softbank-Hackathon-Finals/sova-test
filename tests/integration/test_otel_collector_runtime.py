"""Opt-in qualification against a pinned, real OTel Collector container.

Only synthetic telemetry, ephemeral certificates and loopback listeners. No cloud
credentials, production apps or external telemetry backends are used.
"""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import ipaddress
import json
import os
import secrets
import ssl
import subprocess
from threading import Thread, Lock
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("SOVA_TEST_COLLECTOR") != "1",
    reason="explicit real Collector qualification required",
)


def certificates(root):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "sova-private-collector-test")]
    )
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    root.mkdir(mode=0o700)
    (root / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name in ("collector", "backend", "producer"):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
                ),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.DNSName("localhost"),
                        x509.DNSName("host.docker.internal"),
                        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                    ]
                ),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        (root / (name + ".pem")).write_bytes(
            cert.public_bytes(serialization.Encoding.PEM)
        )
        path = root / (name + ".key")
        path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        path.chmod(0o600)


def test_real_collector_tls_auth_scope_and_minimal_projection(tmp_path):
    requests = pytest.importorskip("requests")
    pytest.importorskip("opentelemetry.proto")
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )
    from sova.adapters.otel_collector import (
        TelemetryProducer,
        COLLECTOR_IMAGE,
        collector_configuration,
    )
    from sova.adapters.otlp_projection import project_otlp
    from sova.domain.contracts import ResourceScope

    certificates(tmp_path / "tls")
    tokens = tmp_path / "secrets"
    tokens.mkdir(mode=0o700)
    values = {name: secrets.token_hex(32) for name in ("source", "target", "backend")}
    for name, value in values.items():
        path = tokens / (name + ".token")
        path.write_text(value)
        path.chmod(0o600)
    now = datetime.now(UTC)
    source = TelemetryProducer(
        "source",
        ResourceScope("tenant-test", "consultation", "source", "app"),
        "a" * 64,
        4318,
        "/secrets/source.token",
        ("/health",),
        now + timedelta(minutes=5),
    )
    target = replace(
        source,
        producer_id="target",
        scope=replace(source.scope, environment_id="target"),
        port=4319,
        token_file="/secrets/target.token",
    )
    observations = []
    raw_safe = []
    errors = []
    lock = Lock()

    class Sink(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            cert = self.connection.getpeercert()
            cn = dict(pair for group in cert.get("subject", ()) for pair in group).get(
                "commonName"
            )
            if (
                self.path != "/v1/traces"
                or cn != "collector"
                or self.headers.get("Authorization") != "Bearer " + values["backend"]
            ):
                self.send_response(403)
                self.end_headers()
                return
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 1048576:
                self.send_response(413)
                self.end_headers()
                return
            payload = self.rfile.read(size)
            try:
                rows = project_otlp(
                    payload,
                    (source, target),
                    authenticate_collector=lambda: None,
                    now=datetime.now(UTC),
                )
                # Memory-only privacy assertion; raw telemetry is never persisted.
                assert (
                    b"private-content" not in payload
                    and b"attacker-tenant" not in payload
                )
                with lock:
                    observations.extend(rows)
                    raw_safe.append(True)
            except Exception as exc:
                with lock:
                    errors.append(type(exc).__name__ + ": " + str(exc))
                self.send_response(400)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-protobuf")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Sink)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tmp_path / "tls/backend.pem", tmp_path / "tls/backend.key")
    context.load_verify_locations(tmp_path / "tls/ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = collector_configuration(
        (source, target),
        backend_endpoint=f"https://host.docker.internal:{server.server_port}",
        now=now,
    )
    configpath = tmp_path / "collector.json"
    configpath.write_text(json.dumps(config))
    name = "sova-otel-test-" + uuid4().hex[:12]
    common = [
        "--user",
        str(os.getuid()),
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--memory",
        "256m",
        "--cpus",
        "0.5",
        "--mount",
        f"type=bind,src={tmp_path}/tls,dst=/tls,readonly",
        "--mount",
        f"type=bind,src={tokens},dst=/secrets,readonly",
        "--mount",
        f"type=bind,src={configpath},dst=/config.json,readonly",
    ]

    def docker(*args, check=True):
        return subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=40, check=check
        )

    session = requests.Session()
    session.trust_env = False
    try:
        validation = docker(
            "run",
            "--rm",
            *common,
            COLLECTOR_IMAGE,
            "validate",
            "--config=/config.json",
            check=False,
        )
        assert validation.returncode == 0, validation.stderr[-8000:]
        docker(
            "run",
            "-d",
            "--name",
            name,
            "--label",
            "io.sova.fixture=collector-qualification",
            "--publish",
            "127.0.0.1::4318",
            "--publish",
            "127.0.0.1::4319",
            *common,
            COLLECTOR_IMAGE,
            "--config=/config.json",
        )
        ports = json.loads(docker("inspect", name).stdout)[0]["NetworkSettings"][
            "Ports"
        ]
        endpoints = {
            key: f"https://127.0.0.1:{ports[str(port) + '/tcp'][0]['HostPort']}/v1/traces"
            for key, port in (("source", 4318), ("target", 4319))
        }
        msg = ExportTraceServiceRequest()
        resource = msg.resource_spans.add()
        resource.resource.attributes.add(
            key="sova.tenant.id"
        ).value.string_value = "attacker-tenant"
        group = resource.scope_spans.add()
        group.scope.name = "private-content"
        span = group.spans.add(
            name="private-content",
            kind=2,
            trace_id=bytes.fromhex("1" * 32),
            span_id=bytes.fromhex("2" * 16),
            start_time_unix_nano=time.time_ns() - 1000000,
            end_time_unix_nano=time.time_ns(),
        )
        span.attributes.add(key="http.route").value.string_value = "/health"
        span.attributes.add(key="http.request.method").value.string_value = "GET"
        span.attributes.add(key="http.response.status_code").value.int_value = 200
        span.attributes.add(key="authorization").value.string_value = "private-content"
        data = msg.SerializeToString()

        def send(name, token, certificate=True, payload=data):
            class VerifiedTLS(requests.adapters.HTTPAdapter):
                def init_poolmanager(self, *args, **kwargs):
                    ctx = ssl.create_default_context(
                        cafile=str(tmp_path / "tls/ca.pem")
                    )
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    kwargs["ssl_context"] = ctx
                    return super().init_poolmanager(*args, **kwargs)

            # A new pool prevents a previously authenticated mTLS connection
            # from invalidating the missing-certificate negative test.
            local = requests.Session()
            local.trust_env = False
            local.mount("https://", VerifiedTLS())
            try:
                return local.post(
                    endpoints[name],
                    data=payload,
                    headers={
                        "Content-Type": "application/x-protobuf",
                        "Authorization": "Bearer " + token,
                    },
                    verify=str(tmp_path / "tls/ca.pem"),
                    cert=(
                        str(tmp_path / "tls/producer.pem"),
                        str(tmp_path / "tls/producer.key"),
                    )
                    if certificate
                    else None,
                    timeout=4,
                )
            finally:
                local.close()

        for attempt in range(30):
            try:
                response = send("source", values["target"])
                break
            except requests.exceptions.SSLError:
                if attempt > 3:
                    raise
                time.sleep(0.2)
            except requests.ConnectionError:
                time.sleep(0.2)
        else:
            pytest.fail(
                "Own Collector did not start: "
                + docker("logs", name, check=False).stderr[-8000:]
            )
        assert response.status_code in (401, 403)
        with pytest.raises(requests.exceptions.SSLError):
            send("source", values["source"], False)
        for producer in ("source", "target"):
            assert send(producer, values[producer]).status_code == 200
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and len(observations) < 2 and not errors:
            time.sleep(0.1)
        assert not errors, errors
        assert len(observations) == 2, docker("logs", name).stderr[-8000:]
        assert {s.scope.environment_id for s in observations} == {"source", "target"}
        assert (
            all(s.scope.tenant_id == "tenant-test" for s in observations)
            and len(raw_safe) >= 1
        )
        # The actual reference workload SDK exports through the same mTLS path.
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from examples.consultation.telemetry import WorkloadTelemetry

        exporter_session = requests.Session()
        exporter_session.trust_env = False
        exporter = OTLPSpanExporter(
            endpoint=endpoints["source"],
            certificate_file=str(tmp_path / "tls/ca.pem"),
            client_certificate_file=str(tmp_path / "tls/producer.pem"),
            client_key_file=str(tmp_path / "tls/producer.key"),
            headers={"Authorization": "Bearer " + values["source"]},
            session=exporter_session,
            timeout=3,
        )
        telemetry = WorkloadTelemetry(
            application_id="consultation",
            environment="source",
            deployment_revision="a" * 64,
            exporter=exporter,
        )
        try:
            with telemetry.span("GET", "/health") as actual:
                actual.set_attribute("http.response.status_code", 200)
                actual.set_attribute("gen_ai.input.messages", "private-content")
            assert telemetry.provider.force_flush(timeout_millis=5000)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and len(observations) < 3 and not errors:
                time.sleep(0.1)
            assert not errors and len(observations) == 3
        finally:
            telemetry.close()
        # Unapproved raw path and event payload must be dropped, not merely hidden in UI.
        span.attributes[0].value.string_value = "/private-content"
        assert (
            send(
                "source", values["source"], payload=msg.SerializeToString()
            ).status_code
            == 200
        )
        span.attributes[0].value.string_value = "/health"
        span.events.add(name="private-content")
        assert (
            send(
                "source", values["source"], payload=msg.SerializeToString()
            ).status_code
            == 200
        )
        time.sleep(0.7)
        assert len(observations) == 3
    finally:
        docker("rm", "-f", name, check=False)
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        session.close()
