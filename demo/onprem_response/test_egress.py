"""Egress qualification boundary tests; fixtures are not cluster evidence."""

import copy
from types import SimpleNamespace

import pytest

from onprem_response.egress import EgressProbe
from onprem_response.terminal import ProxyAdapter
from onprem_response.trial import Adapter
from sova.domain.contracts import ContractError


class API:
    namespaces = {"blue": "owned-blue"}

    def __init__(self):
        self.pod = {
            "metadata": {
                "uid": "peer-pod",
                "labels": {
                    "app.kubernetes.io/name": "neighbor",
                    "app.kubernetes.io/part-of": "owned-app",
                },
                "ownerReferences": [
                    {
                        "controller": True,
                        "kind": "ReplicaSet",
                        "name": "peer-rs",
                        "uid": "peer-rs-uid",
                    }
                ],
            },
            "status": {"phase": "Running", "podIP": "192.0.2.10"},
        }
        self.rs = {
            "metadata": {
                "uid": "peer-rs-uid",
                "ownerReferences": [
                    {"controller": True, "kind": "Deployment", "uid": "peer-deployment"}
                ],
            }
        }
        self.denied = False
        self.change = None
        self.nonces = []

    def check_owned(self):
        pass

    def get(self, *args):
        return {"metadata": {"uid": "peer-deployment"}}

    def request(self, method, path, body=None):
        if method == "GET":
            return copy.deepcopy(
                self.rs if "replicasets" in path else {"items": [self.pod]}
            )
        assert (
            path == "/api/v1/namespaces/owned-blue/services/api:8080/proxy/egress-check"
        )
        assert set(body) == {"nonce"}
        self.nonces.append(body["nonce"])
        value = {
            "nonce": body["nonce"],
            "application": "owned-app",
            "actor_pod_uid": "actor-pod",
            "baseline_cached": True,
            "peer_pod_uid": "peer-pod",
            "peer_ip": "192.0.2.10",
            "connected": not self.denied,
            "http_ok": not self.denied,
        }
        if self.denied:
            value["error"] = "new_connection_unreachable"
        if self.change:
            self.change(value)
        return value


def probe(api):
    return EgressProbe(
        api,
        application_id="owned-app",
        actor_uid="actor-pod",
        peer_deployment_uid="peer-deployment",
    )


def test_positive_control_then_two_independent_dns_free_denials():
    api = API()
    p = probe(api)
    assert p.baseline()["positive_control"] is True
    api.denied = True
    result = p.denied()
    assert result["outbound_new_connection_denied"] is True
    assert result["dns_independent"] is True and result["samples"] == 2
    assert result["existing_connections_tested"] is False
    assert len(set(api.nonces)) == 3


@pytest.mark.parametrize(
    "field,bad",
    [
        ("nonce", "stale"),
        ("application", "other-app"),
        ("actor_pod_uid", "other-actor"),
        ("peer_pod_uid", "other-peer"),
        ("peer_ip", "192.0.2.99"),
        ("baseline_cached", False),
    ],
)
def test_denial_from_another_actor_or_peer_is_not_evidence(field, bad):
    api = API()
    p = probe(api)
    p.baseline()
    api.denied = True
    api.change = lambda v: v.update({field: bad})
    with pytest.raises(ContractError, match="identity"):
        p.denied()


def test_a_failed_positive_control_cannot_be_used_as_isolation():
    api = API()
    api.denied = True
    with pytest.raises(ContractError, match="positive control"):
        probe(api).baseline()


def test_peer_replacement_during_measurement_invalidates_result():
    api = API()
    p = probe(api)
    p.baseline()
    api.denied = True
    api.change = lambda _: api.pod["metadata"].update(uid="replacement-pod")
    with pytest.raises(ContractError, match="peer changed"):
        p.denied()


def test_spoofed_neighbor_labels_without_controller_identity_are_rejected():
    api = API()
    api.rs["metadata"]["ownerReferences"][0]["uid"] = "unregistered-deployment"
    with pytest.raises(ContractError, match="Deployment"):
        probe(api).baseline()


def test_an_http_error_after_tcp_connected_is_not_connection_denial():
    api = API()
    p = probe(api)
    p.baseline()
    api.denied = True
    api.change = lambda v: v.update(connected=True)
    with pytest.raises(ContractError, match="not confirmed blocked"):
        p.denied()


def test_neighbor_down_cannot_qualify_as_network_isolation(monkeypatch):
    value = object.__new__(ProxyAdapter)
    value.routes = SimpleNamespace(call=lambda _: {"ok": False})
    value.egress_probe = SimpleNamespace(
        denied=lambda: pytest.fail("unhealthy control must stop")
    )
    monkeypatch.setattr(Adapter, "readback", lambda *args: object())
    with pytest.raises(ContractError, match="Healthy neighbor"):
        value.readback(SimpleNamespace(action="apply_isolation"), None)
