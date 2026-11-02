"""Adversarial response and stale-intent checks without cloud access."""

import json
from copy import deepcopy
import threading
from types import SimpleNamespace

import pytest

import relocation_server as gateway
from sova.domain.contracts import ContractError
from sova.ports.plans import RecordNotFound


def runtime():
    x = object.__new__(gateway.Relocation)
    x.require_registration = lambda: None
    x.ports = {"aws": 1234}
    x.registration = {
        "code_digest": "expected-code",
        "workloads": {"aws": {"instance": "expected-instance", "pod_uids": ["pod-a"]}},
    }
    return x


def artifacts():
    image = "registry/fixture@sha256:" + "a" * 64
    spec = {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "image": image,
                "securityContext": {
                    "readOnlyRootFilesystem": True,
                    "allowPrivilegeEscalation": False,
                    "capabilities": {"drop": ["ALL"]},
                },
            }
        ],
    }
    deployment = {
        "kind": "Deployment",
        "metadata": {"name": "quote", "uid": "deployment"},
        "spec": {"replicas": 2, "template": {"spec": deepcopy(spec)}},
    }
    replica = {
        "kind": "ReplicaSet",
        "metadata": {
            "uid": "replica",
            "ownerReferences": [
                {"kind": "Deployment", "controller": True, "uid": "deployment"}
            ],
        },
    }
    pods = [
        {
            "kind": "Pod",
            "metadata": {
                "uid": uid,
                "ownerReferences": [
                    {"kind": "ReplicaSet", "controller": True, "uid": "replica"}
                ],
            },
            "spec": deepcopy(spec),
            "status": {
                "phase": "Running",
                "containerStatuses": [{"ready": True, "imageID": image}],
            },
        }
        for uid in ["pod-one", "pod-two"]
    ]
    return {"items": [deployment, replica, *pods]}, {
        "deployment_uid": "deployment",
        "image": image,
        "pod_uids": ["pod-one", "pod-two"],
    }


def test_desired_and_running_digest_and_owner_are_all_checked():
    document, registered = artifacts()
    gateway.validate_running_artifacts(document, registered)


@pytest.mark.parametrize(
    "attack",
    [
        "image",
        "owner",
        "replacement",
        "unready",
        "volume",
        "privileged",
        "host-network",
        "sidecar",
    ],
)
def test_running_pod_change_cannot_hide_behind_unchanged_deployment(attack):
    document, registered = artifacts()
    pod = document["items"][2]
    if attack == "image":
        pod["status"]["containerStatuses"][0]["imageID"] = "sha256:" + "b" * 64
    if attack == "owner":
        pod["metadata"]["ownerReferences"][0]["uid"] = "foreign-controller"
    if attack == "replacement":
        pod["metadata"]["uid"] = "unregistered-new-pod"
    if attack == "unready":
        pod["status"]["containerStatuses"][0]["ready"] = False
    if attack == "volume":
        pod["spec"]["volumes"] = [{"hostPath": {"path": "/"}}]
    if attack == "privileged":
        pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    if attack == "host-network":
        pod["spec"]["hostNetwork"] = True
    if attack == "sidecar":
        pod["spec"]["containers"].append(deepcopy(pod["spec"]["containers"][0]))
    with pytest.raises(ContractError):
        gateway.validate_running_artifacts(document, registered)


def test_restart_cannot_recreate_a_lost_route_as_aws(tmp_path):
    x = runtime()
    x.root, x.tenant, x.app = tmp_path, "tenant", "app"
    (tmp_path / "route-initialized.json").write_text(
        json.dumps({"tenant": "tenant", "application": "app", "route": "quote-entry"})
    )

    def missing(*_):
        raise RecordNotFound("lost route")

    x.routes = SimpleNamespace(
        get=missing,
        register=lambda *_: pytest.fail("must not reset missing control state"),
    )
    with pytest.raises(RecordNotFound):
        x.restore_route()


@pytest.mark.parametrize(
    "change",
    [
        None,
        {"pod_uid": "other"},
        {"total": 0},
        {"environment": "vm"},
        {"code_digest": "other"},
        {"request_id": "replayed"},
        {"database": True},
        {"application": "other"},
        {"instance": "other"},
    ],
)
def test_only_current_owned_business_response_is_accepted(monkeypatch, change):
    x = runtime()

    class Connection:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def request(self, method, path, headers):
            self.nonce = headers["X-Request-ID"]

        def getresponse(self):
            body = dict(
                application="sova-stateless-quote",
                environment="aws",
                instance="expected-instance",
                pod_uid="pod-a",
                code_digest="expected-code",
                request_id=self.nonce,
                total=220,
                database=False,
            )
            body.update(change or {})
            return SimpleNamespace(status=200, read=lambda _: json.dumps(body).encode())

        def close(self):
            self.closed = True

    monkeypatch.setattr(gateway.http.client, "HTTPConnection", Connection)
    # Identity mismatch never counts as a verified response.
    result = x.probe("aws")
    assert result["available"] is (change is None)
    if change:
        assert result["error"] == "response_unverified"


@pytest.mark.parametrize(
    "revision,route,target",
    [
        ("stale", 1, "vm"),
        ("current", 0, "vm"),
        ("current", 1, "aws"),
        ("current", 1, "unknown"),
        ("current", True, "vm"),
    ],
)
def test_stale_approval_never_calls_cluster_or_effect(revision, route, target):
    x = runtime()
    x.action_lock = threading.Lock()
    x.route = lambda: {"revision": 1, "environment_id": "aws"}
    x.revision = "current"
    x.operation = None
    x.inspect_artifacts = lambda: pytest.fail(
        "stale approval reached cluster inspection"
    )
    with pytest.raises(ContractError):
        x.switch(target, revision, route)
    assert not x.action_lock.locked()
