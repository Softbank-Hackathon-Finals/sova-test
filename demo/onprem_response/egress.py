"""Bounded actor-originated probes against the same admitted neighbor Pod.

The API service proxy is a measurement transport, not an ingress-denial probe.
The actor caches a verified neighbor IP before isolation, so DNS loss cannot be
mistaken for a failed TCP connection to the registered peer afterwards.
"""

import secrets

from sova.domain.contracts import ContractError


class EgressProbe:
    def __init__(self, api, *, application_id, actor_uid, peer_deployment_uid):
        self.api = api
        self.application_id = application_id
        self.actor_uid = actor_uid
        self.peer_deployment_uid = peer_deployment_uid
        self.peer = None

    def registered_peer(self):
        self.api.check_owned()
        namespace = self.api.namespaces["blue"]
        pods = self.api.request("GET", f"/api/v1/namespaces/{namespace}/pods")["items"]
        found = [
            p
            for p in pods
            if (
                p["metadata"].get("labels", {}).get("app.kubernetes.io/name")
                == "neighbor"
                and p["metadata"].get("labels", {}).get("app.kubernetes.io/part-of")
                == self.application_id
                and not p["metadata"].get("deletionTimestamp")
                and p.get("status", {}).get("phase") == "Running"
                and p["status"].get("podIP")
            )
        ]
        if len(found) != 1:
            raise ContractError("One current registered egress peer required")
        pod = found[0]
        owners = [
            o
            for o in pod["metadata"].get("ownerReferences", [])
            if o.get("controller") is True
        ]
        if len(owners) != 1 or owners[0].get("kind") != "ReplicaSet":
            raise ContractError("Registered egress peer controller required")
        rs = self.api.request(
            "GET",
            f"/apis/apps/v1/namespaces/{namespace}/replicasets/{owners[0]['name']}",
        )
        deps = [
            o
            for o in rs["metadata"].get("ownerReferences", [])
            if o.get("controller") is True
        ]
        dep = self.api.get("deployment", "blue", "neighbor")
        if (
            rs["metadata"].get("uid") != owners[0].get("uid")
            or len(deps) != 1
            or deps[0].get("kind") != "Deployment"
            or deps[0].get("uid") != self.peer_deployment_uid
            or dep["metadata"].get("uid") != self.peer_deployment_uid
        ):
            raise ContractError("Registered egress peer Deployment was replaced")
        return {"uid": found[0]["metadata"]["uid"], "ip": found[0]["status"]["podIP"]}

    def call(self):
        nonce = secrets.token_hex(16)
        namespace = self.api.namespaces["blue"]
        value = self.api.request(
            "POST",
            f"/api/v1/namespaces/{namespace}/services/api:8080/proxy/egress-check",
            {"nonce": nonce},
        )
        if (
            value.get("nonce") != nonce
            or value.get("application") != self.application_id
            or value.get("actor_pod_uid") != self.actor_uid
            or value.get("baseline_cached") is not True
            or self.peer
            != {"uid": value.get("peer_pod_uid"), "ip": value.get("peer_ip")}
        ):
            raise ContractError("Egress evidence identity or cached peer mismatch")
        return value

    def baseline(self):
        self.peer = self.registered_peer()
        value = self.call()
        if value.get("connected") is not True or value.get("http_ok") is not True:
            raise ContractError("Actor to registered neighbor positive control failed")
        if self.registered_peer() != self.peer:
            raise ContractError("Registered egress peer changed during baseline")
        return {
            "actor_uid": self.actor_uid,
            "peer_uid": self.peer["uid"],
            "positive_control": True,
        }

    def denied(self):
        if self.peer is None or self.registered_peer() != self.peer:
            raise ContractError("Current positive egress baseline required")
        for _ in range(2):
            value = self.call()
            if not (
                value.get("connected") is False
                and value.get("http_ok") is False
                and value.get("error") == "new_connection_unreachable"
            ):
                raise ContractError(
                    "Actor outbound TCP connection not confirmed blocked"
                )
        if self.registered_peer() != self.peer:
            raise ContractError("Egress peer changed during denial measurement")
        return {
            "outbound_new_connection_denied": True,
            "samples": 2,
            "actor_uid": self.actor_uid,
            "peer_uid": self.peer["uid"],
            "dns_independent": True,
            "existing_connections_tested": False,
        }
