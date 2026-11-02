"""Actual response adapter must not quarantine another app with the same name."""

from copy import deepcopy
import json
from unittest.mock import Mock

import pytest

from kubernetes_response import OwnedKubernetesResponse
from sova.domain.contracts import ContractError


def subject():
    adapter = object.__new__(OwnedKubernetesResponse)
    adapter.application_id = "orders"
    adapter.target_name = "api"
    adapter.target_ns = "green"
    adapter.target_uid = "registered-deployment"
    adapter.target_template = {
        "metadata": {"labels": adapter.workload_selector("api")},
        "spec": {"containers": [{"name": "api", "image": "fixed-image"}]},
    }
    return adapter


def workload(adapter):
    return {
        "metadata": {"uid": adapter.target_uid, "generation": 2},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": adapter.workload_selector("api")},
            "template": deepcopy(adapter.target_template),
        },
        "status": {"readyReplicas": 1, "observedGeneration": 2},
    }


@pytest.mark.parametrize(
    "case", ["name-only", "another-app", "expression", "pod-drift"]
)
def test_broader_or_other_application_selector_is_rejected(case):
    adapter = subject()
    value = workload(adapter)
    if case == "name-only":
        value["spec"]["selector"]["matchLabels"].pop("app.kubernetes.io/part-of")
    elif case == "another-app":
        value["spec"]["selector"]["matchLabels"]["app.kubernetes.io/part-of"] = "peer"
    elif case == "expression":
        value["spec"]["selector"]["matchExpressions"] = [
            {"key": "other", "operator": "Exists"}
        ]
    else:
        value["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/part-of"] = (
            "peer"
        )
    with pytest.raises(ContractError, match="application and component"):
        adapter.check_workload_selector(value, "api")


def test_readiness_uses_named_get_instead_of_watch_or_list():
    adapter = subject()
    adapter.kube = Mock(return_value=json.dumps(workload(adapter)))
    adapter.wait_replacement_ready()
    assert adapter.kube.call_count == 1
    args = adapter.kube.call_args.args
    assert args == ("-n", "green", "get", "deployment", "api", "-o", "json")
    assert 0 < adapter.kube.call_args.kwargs["timeout"] <= 10


@pytest.mark.parametrize("case", ["recreated", "changed-image", "changed-replicas"])
def test_readiness_cannot_accept_replaced_or_changed_deployment(case):
    adapter = subject()
    value = workload(adapter)
    if case == "recreated":
        value["metadata"]["uid"] = "new-deployment"
    elif case == "changed-image":
        value["spec"]["template"]["spec"]["containers"][0]["image"] = "untrusted"
    else:
        value["spec"]["replicas"] = 2
    adapter.kube = Mock(return_value=json.dumps(value))
    with pytest.raises(ContractError, match="changed"):
        adapter.wait_replacement_ready()


def test_readiness_has_finite_deadline_and_does_not_accept_old_generation(monkeypatch):
    adapter = subject()
    value = workload(adapter)
    value["status"]["observedGeneration"] = 1
    adapter.kube = Mock(return_value=json.dumps(value))
    elapsed = [0]
    monkeypatch.setattr("kubernetes_response.time.monotonic", lambda: elapsed[0])
    monkeypatch.setattr(
        "kubernetes_response.time.sleep",
        lambda _: elapsed.__setitem__(0, elapsed[0] + 15),
    )
    with pytest.raises(ContractError, match="deadline"):
        adapter.wait_replacement_ready()
    assert adapter.kube.call_count == 3
