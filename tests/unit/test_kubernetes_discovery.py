from copy import deepcopy
from dataclasses import replace
from datetime import timedelta
import json

import pytest

from sova.adapters.kubernetes.registration import decode_registration
from sova.application.kubernetes_discovery import KubernetesDiscovery, COLLECTIONS
from sova.domain.contracts import ContractError
from sova.domain.discovery import KubernetesReadRegistration
from sova.adapters.registration.graph_codec import decode_graph


def registration(now):
    return KubernetesReadRegistration(
        "tenant",
        "orders",
        "cluster",
        "test",
        "https://cluster.example",
        ("127.0.0.1",),
        "a" * 64,
        "orders",
        "namespace-1",
        1,
        now,
        now + timedelta(hours=1),
    )


def resource(kind, name):
    spec = (
        {"selector": {"app": "api"}}
        if kind == "Service"
        else {
            "template": {
                "metadata": {"labels": {"app": "api"}},
                "spec": {
                    "containers": [
                        {
                            "name": "app",
                            "env": [{"name": "TOKEN", "value": "do-not-return"}],
                        }
                    ]
                },
            }
        }
    )
    return {
        "kind": kind,
        "metadata": {
            "name": name,
            "namespace": "orders",
            "uid": "uid-" + name,
            "resourceVersion": "1",
            "labels": {"app.kubernetes.io/part-of": "orders"},
        },
        "spec": spec,
    }


class Transport:
    def __init__(self, reg, change=lambda path, data: data):
        self.registration_digest = reg.fingerprint
        self.calls = []
        self.change = change

    def get(self, path, query, *, timeout):
        self.calls.append((path, query, timeout))
        if path == "/api/v1/namespaces/orders":
            data = {
                "kind": "Namespace",
                "metadata": {"name": "orders", "uid": "namespace-1"},
            }
        else:
            kind = next(
                k for k, _, plural in COLLECTIONS if path.endswith("/" + plural)
            )
            data = {
                "kind": kind + "List",
                "metadata": {"resourceVersion": "10"},
                "items": [resource(kind, "api" if kind == "Deployment" else "entry")]
                if kind in {"Service", "Deployment"}
                else [],
            }
        return self.change(path, deepcopy(data))


def service(
    now, change=lambda path, data: data, authorize=lambda *args: None, clock=None
):
    reg = registration(now)
    transport = Transport(reg, change)
    return KubernetesDiscovery(
        reg, transport, authorize=authorize, clock=clock or (lambda: now)
    ), transport


def test_scoped_read_binding_and_non_atomic_proof(now):
    auth = []
    reader, transport = service(now, authorize=lambda *args: auth.append(args))
    result = reader.inspect(actor="trusted-caller")
    assert result["executable"] is False
    graph = decode_graph(result["graph"])
    assert graph.origin == "kubernetes_api"
    assert result["collection"]["graph_digest"] == graph.fingerprint
    assert len(result["collection"]["collection_versions"]) == 4
    assert len(transport.calls) == 6 and len(auth) == 7
    assert "do-not-return" not in json.dumps(result)
    for path, query, timeout in transport.calls:
        assert "/namespaces/orders" in path and 0 < timeout <= 5
        if query:
            assert query["labelSelector"] == "app.kubernetes.io/part-of=orders"


def test_permission_denied_before_network(now):
    def deny(*args):
        raise ContractError("Denied")

    reader, transport = service(now, authorize=deny)
    with pytest.raises(ContractError):
        reader.inspect(actor="untrusted")
    assert transport.calls == []


def test_revocation_mid_read_aborts_no_partial_result(now):
    calls = []

    def auth(*args):
        calls.append(args)
        if len(calls) > 2:
            raise ContractError("Revoked")

    reader, transport = service(now, authorize=auth)
    with pytest.raises(ContractError):
        reader.inspect(actor="caller")
    assert len(transport.calls) == 2


@pytest.mark.parametrize(
    "case",
    [
        "wrong-uid",
        "cross-namespace",
        "cross-app",
        "missing-version",
        "repeated-token",
        "wrong-list",
        "wrong-item",
        "denied-last-kind",
        "malformed-namespace",
        "empty",
        "oversize",
    ],
)
def test_incomplete_or_out_of_scope_reads_never_return_success(case, now):
    def change(path, data):
        if case == "wrong-uid" and data["kind"] == "Namespace":
            data["metadata"]["uid"] = "recreated"
        if case == "malformed-namespace" and data["kind"] == "Namespace":
            data["metadata"] = []
        if data["kind"] == "DeploymentList":
            if case == "cross-namespace":
                data["items"][0]["metadata"]["namespace"] = "other"
            if case == "cross-app":
                data["items"][0]["metadata"]["labels"] = {}
            if case == "missing-version":
                data["metadata"].pop("resourceVersion")
            if case == "repeated-token":
                data["metadata"]["continue"] = "same-token"
            if case == "wrong-list":
                data["kind"] = "SecretList"
            if case == "wrong-item":
                data["items"][0]["kind"] = "Secret"
            if case == "oversize":
                data["items"] = [resource("Deployment", "api")] * 129
        if case == "empty":
            data["items"] = [] if "items" in data else None
        if case == "denied-last-kind" and path.endswith("/persistentvolumeclaims"):
            raise ContractError("403")
        return data

    reader, _ = service(now, change)
    with pytest.raises(ContractError):
        reader.inspect(actor="caller")


def test_paginated_collection_same_version_required(now):
    pages = []

    def change(path, data):
        if data["kind"] == "DeploymentList":
            pages.append(path)
            if len(pages) == 1:
                data["metadata"]["continue"] = "next"
            else:
                data["metadata"]["resourceVersion"] = "11"
                data["items"] = []
        return data

    reader, _ = service(now, change)
    with pytest.raises(ContractError):
        reader.inspect(actor="caller")


def test_namespace_recreation_after_collection_detected(now):
    calls = []

    def change(path, data):
        if data["kind"] == "Namespace":
            calls.append(path)
            if len(calls) > 1:
                data["metadata"]["uid"] = "new-uid"
        return data

    reader, _ = service(now, change)
    with pytest.raises(ContractError):
        reader.inspect(actor="caller")


def test_expired_registration_or_mismatched_transport(now):
    reg = registration(now)
    transport = Transport(reg)
    reader = KubernetesDiscovery(
        reg,
        transport,
        authorize=lambda *args: None,
        clock=lambda: now + timedelta(hours=1),
    )
    with pytest.raises(ContractError):
        reader.inspect(actor="caller")
    assert transport.calls == []
    transport.registration_digest = "b" * 64
    with pytest.raises(ContractError):
        KubernetesDiscovery(
            reg, transport, authorize=lambda *args: None, clock=lambda: now
        )


@pytest.mark.parametrize(
    "change",
    [
        {"endpoint": "http://cluster.example"},
        {"endpoint": "https://user:password@cluster.example"},
        {"endpoint": "https://cluster.example/path"},
        {"namespace": "../other"},
        {"application_id": "orders,other"},
        {"approved_addresses": ("169.254.169.254",)},
        {"approved_addresses": ("0.0.0.0",)},
        {"revision": True},
        {"endpoint": "https://cluster.example:0"},
        {"endpoint": "https://cluster.example?"},
        {"endpoint": "https://cluster example"},
        {"approved_addresses": ("::ffff:169.254.169.254",)},
        {"approved_addresses": (123,)},
    ],
)
def test_unsafe_registration_rejected(change, now):
    with pytest.raises(ContractError):
        replace(registration(now), **change)


def test_registration_codec_revision_and_unknown_fields(now):
    reg = registration(now)
    assert decode_registration(reg.document) == reg
    changed = replace(reg, namespace_uid="recreated")
    assert changed.fingerprint != reg.fingerprint
    with pytest.raises(ContractError):
        decode_registration({**reg.document, "token": "should-not-be-stored"})


def test_real_typed_list_can_omit_item_gvk(now):
    def omit(path, data):
        for item in data.get("items", []):
            item.pop("kind", None)
            item.pop("apiVersion", None)
        return data

    reader, _ = service(now, omit)
    result = reader.inspect(actor="caller")
    assert len(result["graph"]["resources"]) == 2
