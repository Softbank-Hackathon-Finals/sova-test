"""Real loopback TLS protocol tests; this is not a real Kubernetes cluster."""

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import ssl
import subprocess
import time
from threading import Thread

import pytest

from sova.adapters.kubernetes.https import (
    KubernetesHTTPS,
    KubernetesRequestRefused,
    private_text,
)
from sova.application.kubernetes_discovery import KubernetesDiscovery, COLLECTIONS
from sova.domain.contracts import ContractError
from sova.domain.discovery import KubernetesReadRegistration


@pytest.fixture
def api(tmp_path):
    key = tmp_path / "key.pem"
    cert = tmp_path / "cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
        ],
        capture_output=True,
        check=True,
        timeout=15,
    )
    state = {"requests": [], "mode": "ok"}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_PATCH(self):
            state["requests"].append(self.path)
            state["patch_headers"] = dict(self.headers)
            state["patch_body"] = self.rfile.read(int(self.headers["Content-Length"]))
            if state["mode"] in {"deny", "redirect", "conflict"}:
                self.send_response(
                    {"deny": 403, "redirect": 302, "conflict": 422}[state["mode"]]
                )
                self.send_header("Location", "https://unregistered.invalid/")
                self.end_headers()
                return
            if state["mode"] == "lost":
                self.close_connection = True
                return
            body = b'{"kind":"Deployment"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            state["requests"].append(self.path)
            if self.headers.get("Authorization") != "Bearer test-token":
                self.send_response(401)
                self.end_headers()
                return
            if state["mode"] == "redirect":
                self.send_response(302)
                self.send_header("Location", "https://unregistered.invalid/")
                self.end_headers()
                return
            if state["mode"] == "deny":
                self.send_response(403)
                self.end_headers()
                return
            if self.path == "/api/v1/namespaces/orders":
                result = {
                    "kind": "Namespace",
                    "metadata": {"name": "orders", "uid": "ns-one"},
                }
            else:
                plural = self.path.split("?")[0].split("/")[-1]
                kind = next(k for k, _, p in COLLECTIONS if p == plural)
                item = {
                    "kind": "Deployment",
                    "metadata": {
                        "name": "api",
                        "namespace": "orders",
                        "uid": "api-one",
                        "resourceVersion": "2",
                        "labels": {"app.kubernetes.io/part-of": "orders"},
                    },
                    "spec": {
                        "template": {
                            "metadata": {"labels": {"app": "api"}},
                            "spec": {"containers": []},
                        }
                    },
                }
                result = {
                    "kind": kind + "List",
                    "metadata": {"resourceVersion": "5"},
                    "items": [item] if kind == "Deployment" else [],
                }
            if state["mode"] == "drip":
                self.send_response(200)
                self.send_header("Content-Length", "20")
                self.end_headers()
                try:
                    for _ in range(20):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(0.08)
                except (OSError, ssl.SSLError):
                    pass
                return
            body = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    now = datetime.now(UTC)
    ca = cert.read_bytes()
    reg = KubernetesReadRegistration(
        "tenant",
        "orders",
        "test",
        "local-test",
        "https://localhost:" + str(server.server_port),
        ("127.0.0.1",),
        hashlib.sha256(ca).hexdigest(),
        "orders",
        "ns-one",
        1,
        now,
        now + timedelta(minutes=5),
    )
    try:
        yield reg, ca, state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_complete_collection_over_verified_tls_and_pinned_ip(api, monkeypatch):
    reg, ca, state = api
    monkeypatch.setenv("HTTPS_PROXY", "http://unregistered.invalid:80")
    transport = KubernetesHTTPS(reg, ca_pem=ca, token_provider=lambda: "test-token")
    result = KubernetesDiscovery(
        reg, transport, authorize=lambda *args: None, clock=lambda: datetime.now(UTC)
    ).inspect(actor="test-auth-boundary")
    assert len(state["requests"]) == 6
    assert result["graph"]["origin"] == "kubernetes_api"
    assert result["graph"]["resources"][0]["scope"]["environment_id"] == "test"
    assert result["executable"] is False


@pytest.mark.parametrize("mode", ["redirect", "deny"])
def test_refusals_do_not_follow_redirect_or_return_partial_inventory(api, mode):
    reg, ca, state = api
    state["mode"] = mode
    transport = KubernetesHTTPS(reg, ca_pem=ca, token_provider=lambda: "test-token")
    with pytest.raises(ContractError):
        transport.get("/api/v1/namespaces/orders", {}, timeout=2)
    assert len(state["requests"]) == 1


def test_hostname_verification_and_ca_binding(api):
    reg, ca, state = api
    with pytest.raises(ContractError):
        KubernetesHTTPS(
            replace(reg, ca_digest="0" * 64),
            ca_pem=ca,
            token_provider=lambda: "test-token",
        )
    reg = replace(reg, endpoint=reg.endpoint.replace("localhost", "wrong-name.invalid"))
    transport = KubernetesHTTPS(reg, ca_pem=ca, token_provider=lambda: "test-token")
    with pytest.raises(ContractError):
        transport.get("/api/v1/namespaces/orders", {}, timeout=2)
    assert state["requests"] == []


def test_unregistered_paths_and_query_refused_before_credentials(api):
    reg, ca, state = api

    def forbidden():
        raise AssertionError("Credential read before scope check")

    transport = KubernetesHTTPS(reg, ca_pem=ca, token_provider=forbidden)
    with pytest.raises(ContractError):
        transport.get("/api/v1/secrets", {}, timeout=2)
    with pytest.raises(ContractError):
        transport.get(
            "/api/v1/namespaces/orders/services",
            {"labelSelector": "other", "limit": "32"},
            timeout=2,
        )
    assert state["requests"] == []


def test_private_operator_files(tmp_path):
    path = tmp_path / "token"
    path.write_text("test-token")
    path.chmod(0o600)
    assert private_text(path) == "test-token"
    path.chmod(0o644)
    with pytest.raises(ContractError):
        private_text(path)
    path.chmod(0o600)
    link = Path(tmp_path / "link")
    link.symlink_to(path)
    with pytest.raises(ContractError):
        private_text(link)


def test_absolute_deadline_stops_trickling_response(api):
    reg, ca, state = api
    state["mode"] = "drip"
    transport = KubernetesHTTPS(reg, ca_pem=ca, token_provider=lambda: "test-token")
    started = time.monotonic()
    with pytest.raises(ContractError):
        transport.get("/api/v1/namespaces/orders", {}, timeout=0.15)
    assert time.monotonic() - started < 1


def test_image_patch_uses_pinned_tls_json_patch_and_exact_registered_path(api):
    from kubernetes_patch_support import image_patch_bundle
    from sova.adapters.kubernetes.image_patch import KubernetesImagePatchHTTPS

    reg, ca, state = api
    image_reg, command, adapter, fixture = image_patch_bundle(reg.registered_at)
    image_reg = replace(
        image_reg,
        reader=replace(
            image_reg.reader,
            endpoint=reg.endpoint,
            ca_digest=reg.ca_digest,
            namespace="owned",
            valid_until=image_reg.reader.valid_until,
        ),
    )
    transport = KubernetesImagePatchHTTPS(
        image_reg, ca_pem=ca, token_provider=lambda: "test-token"
    )
    adapter.transport = transport
    adapter.registration = image_reg
    fixture["registration"] = image_reg
    # Only exercise the wire mutation boundary; namespace/deployment reads have
    # their own real-cluster qualification and require the registered identity.
    operations = [
        {"op": "test", "path": "/metadata/uid", "value": image_reg.deployment_uid},
        {
            "op": "test",
            "path": "/metadata/resourceVersion",
            "value": image_reg.resource_version,
        },
        {
            "op": "test",
            "path": "/spec/template",
            "value": fixture["workload"]["spec"]["template"],
        },
        {
            "op": "add",
            "path": "/metadata/annotations",
            "value": {"sova.security/patch-command": command.fingerprint},
        },
        {
            "op": "replace",
            "path": "/spec/template/spec/containers/0/image",
            "value": image_reg.image,
        },
    ]
    assert transport.patch_image(operations)["kind"] == "Deployment"
    assert json.loads(state["patch_body"]) == operations
    assert state["patch_headers"]["Content-Type"] == "application/json-patch+json"
    assert state["requests"] == ["/apis/apps/v1/namespaces/owned/deployments/api"]
    for mode, status in (("deny", 403), ("redirect", 302), ("conflict", 422)):
        state["mode"] = mode
        with pytest.raises(KubernetesRequestRefused) as error:
            transport.patch_image(operations)
        assert error.value.status == status
    assert len(state["requests"]) == 4
    state["mode"] = "lost"
    with pytest.raises(ContractError):
        transport.patch_image(operations)
    assert len(state["requests"]) == 5  # No retry after an uncertain write.
    operations[-1]["value"] = "registry.example/not-owned:latest"
    with pytest.raises(ContractError):
        transport.patch_image(operations)
    assert len(state["requests"]) == 5
