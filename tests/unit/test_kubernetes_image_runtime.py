from copy import deepcopy

import pytest
from kubernetes_patch_support import image_patch_bundle
from sova.adapters.kubernetes.image_patch_runtime import KubernetesRuntimeCollector
from sova.domain.contracts import ContractError


def runtime_bundle(now):
    reg, command, adapter, state = image_patch_bundle(now)
    adapter.apply(command)
    workload = state["workload"]
    workload["metadata"]["generation"] = 2
    workload["status"] = {
        "observedGeneration": 2,
        "replicas": 1,
        "updatedReplicas": 1,
        "readyReplicas": 1,
        "availableReplicas": 1,
        "conditions": [{"type": "Available", "status": "True"}],
    }
    labels = workload["metadata"]["labels"]
    state["replicasets"] = {
        "kind": "ReplicaSetList",
        "metadata": {},
        "items": [
            {
                "metadata": {
                    "name": "api-rs",
                    "namespace": "owned",
                    "uid": "rs-one",
                    "labels": labels,
                    "ownerReferences": [
                        {
                            "kind": "Deployment",
                            "name": "api",
                            "uid": reg.deployment_uid,
                            "controller": True,
                        }
                    ],
                }
            }
        ],
    }
    state["replicasets"]["items"][0]["spec"] = {
        "template": {"spec": {"containers": [{"name": "http", "image": reg.image}]}}
    }
    state["pods"] = {
        "kind": "PodList",
        "metadata": {},
        "items": [
            {
                "metadata": {
                    "name": "api-pod",
                    "namespace": "owned",
                    "uid": "pod-one",
                    "labels": labels,
                    "ownerReferences": [
                        {
                            "kind": "ReplicaSet",
                            "name": "api-rs",
                            "uid": "rs-one",
                            "controller": True,
                        }
                    ],
                },
                "spec": {"containers": [{"name": "http", "image": reg.image}]},
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                    "containerStatuses": [
                        {
                            "name": "http",
                            "ready": True,
                            "state": {"running": {}},
                            "imageID": reg.image,
                        }
                    ],
                },
            }
        ],
    }
    state["after_children"] = lambda: None

    def children(kind):
        value = deepcopy(state[kind])
        state["after_children"]()
        return value

    adapter.transport.children = children
    collector = KubernetesRuntimeCollector(
        reg,
        transport=adapter.transport,
        current_registration=lambda: state["registration"],
        authenticate_registration=lambda _: state["authenticated"],
        authorize=lambda *_: state["allowed"],
        clock=lambda: state["time"],
    )
    return reg, command, collector, state


def test_exact_ready_pods_are_observed_without_mutation_or_health_claim(now):
    reg, command, collector, state = runtime_bundle(now)
    before = len(state["calls"])
    result = collector.collect(command)
    assert result.rollout_ready and result.reasons == ()
    assert result.observed_image_digests == (reg.artifact.image_digest,)
    assert len(state["calls"]) == before
    assert not hasattr(result, "functional") and not hasattr(
        result, "execution_authorized"
    )


@pytest.mark.parametrize(
    "case",
    [
        "old-generation",
        "rolling",
        "failed",
        "missing-pod",
        "not-ready",
        "old-image",
        "config-id",
        "foreign-owner",
        "terminating",
    ],
)
def test_controller_status_alone_never_proves_the_expected_runtime(now, case):
    reg, command, collector, state = runtime_bundle(now)
    pod = state["pods"]["items"][0]
    status = state["workload"]["status"]
    if case == "old-generation":
        status["observedGeneration"] = 1
    if case == "rolling":
        status["updatedReplicas"] = 0
    if case == "failed":
        status["conditions"] = [{"reason": "ProgressDeadlineExceeded"}]
    if case == "missing-pod":
        state["pods"]["items"] = []
    if case == "not-ready":
        pod["status"]["containerStatuses"][0]["ready"] = False
    if case == "old-image":
        pod["status"]["containerStatuses"][0]["imageID"] = (
            reg.repository + "@sha256:" + reg.base_image_digest
        )
    if case == "config-id":
        pod["status"]["containerStatuses"][0]["imageID"] = (
            "sha256:" + reg.artifact.image_digest
        )
    if case == "foreign-owner":
        pod["metadata"]["ownerReferences"][0]["uid"] = "someone-else"
    if case == "terminating":
        pod["metadata"]["deletionTimestamp"] = "2026-10-31T00:00:00Z"
    result = collector.collect(command)
    assert not result.rollout_ready and result.reasons
    assert len(state["calls"]) == 1


@pytest.mark.parametrize(
    "case", ["namespace", "duplicate", "truncated", "foreign-rs", "sidecar"]
)
def test_unbounded_or_foreign_runtime_input_is_not_complete_proof(now, case):
    _, command, collector, state = runtime_bundle(now)
    pod = state["pods"]["items"][0]
    if case == "namespace":
        pod["metadata"]["namespace"] = "unregistered"
    if case == "duplicate":
        state["pods"]["items"].append(deepcopy(pod))
    if case == "truncated":
        state["pods"]["metadata"]["continue"] = "more"
    if case == "foreign-rs":
        state["replicasets"]["items"][0]["metadata"]["namespace"] = "unregistered"
    if case == "sidecar":
        pod["spec"]["containers"].append(
            {"name": "unregistered", "image": "unregistered"}
        )
    if case == "sidecar":
        assert not collector.collect(command).rollout_ready
    else:
        with pytest.raises(ContractError):
            collector.collect(command)
    assert len(state["calls"]) == 1


@pytest.mark.parametrize("case", ["revoked", "changed-deployment"])
def test_authority_or_resource_change_during_collection_cannot_return_ready(now, case):
    _, command, collector, state = runtime_bundle(now)

    def change():
        if case == "revoked":
            state["authenticated"] = False
        else:
            state["workload"]["metadata"]["resourceVersion"] = "newer-version"

    state["after_children"] = change
    with pytest.raises(ContractError):
        collector.collect(command)
    assert len(state["calls"]) == 1
