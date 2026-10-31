from copy import deepcopy
from datetime import timedelta
import json

import pytest

from sova.adapters.kubernetes.inventory import snapshot_graph
from sova.domain.contracts import ContractError


def snapshot():
    def item(kind, name, spec):
        return {
            "kind": kind,
            "metadata": {
                "name": name,
                "namespace": "orders",
                "uid": "uid-" + name,
                "resourceVersion": "7",
                "labels": {"app.kubernetes.io/part-of": "orders"},
            },
            "spec": spec,
        }

    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            item("Service", "entry", {"selector": {"app": "api"}}),
            item(
                "Deployment",
                "api",
                {
                    "template": {
                        "metadata": {"labels": {"app": "api"}},
                        "spec": {
                            "containers": [
                                {
                                    "name": "app",
                                    "env": [
                                        {"name": "TOKEN", "value": "must-never-echo"}
                                    ],
                                }
                            ],
                            "volumes": [
                                {
                                    "name": "data",
                                    "persistentVolumeClaim": {"claimName": "data"},
                                }
                            ],
                        },
                    }
                },
            ),
            item("PersistentVolumeClaim", "data", {}),
        ],
    }


def convert(data, now):
    return snapshot_graph(
        data,
        tenant_id="tenant",
        application_id="orders",
        environment_id="cluster-one",
        namespace="orders",
        location="local",
        observed_at=now,
        valid_until=now + timedelta(minutes=5),
    )


def test_normalizes_declared_links_without_secret_values(now):
    graph = convert(snapshot(), now)
    assert graph.origin == "kubernetes_snapshot"
    assert "must-never-echo" not in json.dumps(graph.document)
    assert {(e.source, e.target) for e in graph.relations} == {
        ("service:entry", "deployment:api"),
        ("deployment:api", "persistentvolumeclaim:data"),
    }
    assert all("declared-links-not-traffic" in n.requirements for n in graph.resources)
    assert (
        "plaintext-environment-review"
        in next(
            n for n in graph.resources if n.node_id == "deployment:api"
        ).requirements
    )


@pytest.mark.parametrize(
    "case", ["namespace", "label", "secret", "missing-pvc", "spec", "containers", "uid"]
)
def test_incomplete_or_unscoped_export_blocked(case, now):
    data = deepcopy(snapshot())
    if case == "namespace":
        data["items"][0]["metadata"]["namespace"] = "other"
    elif case == "label":
        data["items"][0]["metadata"]["labels"] = {}
    elif case == "secret":
        data["items"][0]["kind"] = "Secret"
    elif case == "missing-pvc":
        data["items"].pop()
    elif case == "spec":
        data["items"][0]["spec"] = []
    elif case == "containers":
        data["items"][1]["spec"]["template"]["spec"]["containers"] = [None]
    elif case == "uid":
        data["items"][1]["metadata"]["uid"] = data["items"][0]["metadata"]["uid"]
    with pytest.raises(ContractError):
        convert(data, now)
