"""Local contract tests. Fixtures are not actual on-prem acceptance evidence."""

import copy
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import httpx

from onprem_response.manifests import manifests, names
from onprem_response.projection import projection
from onprem_response.trial import TrialAPI
from onprem_response.trial import Adapter
from sova.domain.contracts import ContractError
from sova.domain.contracts import EffectStatus


def test_json_patch_intent_is_durable_before_dispatch(tmp_path):
    api = object.__new__(TrialAPI)
    api.root = tmp_path
    api.namespaces = names("abcdef12")
    api.token_deadline = datetime.now(UTC) + timedelta(minutes=3)

    def receive(request):
        assert request.headers["content-type"] == "application/json-patch+json"
        assert (tmp_path / "requests.private.jsonl").stat().st_size > 0
        return httpx.Response(200, json={"ok": True})

    with httpx.Client(
        base_url="https://unit.invalid", transport=httpx.MockTransport(receive)
    ) as client:
        api.client = client
        assert api.request(
            "PATCH",
            "/apis/apps/v1/namespaces/sova-wr-abcdef12-blue/deployments/api",
            [{"op": "test", "path": "/metadata/uid", "value": "unit"}],
            patch=True,
        ) == {"ok": True}


IMAGE = "docker.io/library/python@sha256:" + "a" * 64


def test_reused_api_does_not_admit_general_kubectl_operations():
    adapter = object.__new__(Adapter)
    adapter.trial_api = SimpleNamespace(
        namespaces=names("abcdef12"), request=lambda *args: {"ok": True}
    )
    assert adapter.get("deployment", names("abcdef12")["blue"], "api") == {"ok": True}
    with pytest.raises(ContractError):
        adapter.get("deployment", "target-dev", "demo-chat")
    with pytest.raises(ContractError):
        adapter.kube("delete", "namespace", "target-dev")


def fixture():
    objects = manifests("abcdef12", IMAGE)
    for index, obj in enumerate(objects):
        obj["metadata"].update(
            uid=f"fixture-uid-{index}", generation=1, resourceVersion="1"
        )

    def get(kind, side, name):
        kind = {"deployment": "Deployment", "service": "Service"}[kind]
        return next(
            o
            for o in objects
            if o["kind"] == kind
            and o["metadata"]["namespace"] == names("abcdef12")[side]
            and o["metadata"]["name"] == name
        )

    probes = {k: {"ok": k != "green"} for k in ("blue", "neighbor", "green")}
    route = {"environment_id": names("abcdef12")["blue"]}
    at = datetime.now(UTC) - timedelta(seconds=1)
    trial = SimpleNamespace(
        api=SimpleNamespace(get=get),
        observation_started_at=at,
        deadline=at + timedelta(minutes=8),
        run_id="abcdef12",
        ns=names("abcdef12"),
        source=get("deployment", "blue", "api"),
        target=get("deployment", "green", "api"),
        neighbor=get("deployment", "blue", "neighbor"),
        steps=[],
        isolation=None,
        probes=probes,
        routes=SimpleNamespace(
            get=lambda *_: route, call=lambda *_: {"probe": "alive"}
        ),
        entry={"ok": True, "target": "blue", "response": {"environment": "blue"}},
        snapshot_revision=1,
        events=[],
        plan_binding={
            "plan_id": "owned-trial",
            "plan_digest": "b" * 64,
            "plan_version": 1,
        },
    )
    return trial


def test_bounded_resources_and_no_credentials():
    objects = manifests("abcdef12", IMAGE)
    assert {o["metadata"]["name"] for o in objects if o["kind"] == "Namespace"} == set(
        names("abcdef12").values()
    )
    assert not {
        "Secret",
        "PersistentVolumeClaim",
        "Role",
        "RoleBinding",
        "ClusterRoleBinding",
    } & {o["kind"] for o in objects}
    deployments = [o for o in objects if o["kind"] == "Deployment"]
    assert sum(o["spec"]["replicas"] for o in deployments) == 3
    for obj in deployments:
        pod = obj["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False
        assert not any(pod.get(k) for k in ("hostNetwork", "hostPID", "hostIPC"))
        assert pod["containers"][0]["image"] == IMAGE
        assert pod["containers"][0]["securityContext"]["readOnlyRootFilesystem"] is True
        assert all(set(v) == {"name", "configMap"} for v in pod["volumes"])


@pytest.mark.parametrize(
    "image", ["python:latest", "repo/untrusted@sha256:" + "a" * 64]
)
def test_unpinned_or_foreign_image_rejected(image):
    with pytest.raises(ValueError):
        manifests("abcdef12", image)


def test_cleanup_never_deletes_recreated_namespace(tmp_path):
    api = object.__new__(TrialAPI)
    api.root = tmp_path
    api.run_id = "abcdef12"
    namespace = names(api.run_id)["blue"]
    api.uids = {namespace: "original"}
    calls = []

    def request(method, *args, **kwargs):
        calls.append(method)
        return {
            "metadata": {"uid": "replacement", "labels": {"sova.io/trial": api.run_id}}
        }

    api.request = request
    assert api.cleanup()[namespace] == "cleanup_unconfirmed"
    assert calls == ["GET"]


def test_projection_requires_actual_isolation_and_stable_entry():
    trial = fixture()
    doc = projection(trial)
    assert next(n for n in doc["nodes"] if n["id"] == "api")["security"] == "clear"
    trial.source["spec"]["template"]["spec"]["containers"][0]["securityContext"][
        "readOnlyRootFilesystem"
    ] = False
    trial.steps = [
        {"action": a}
        for a in (
            "apply_isolation",
            "activate_replacement",
            "verify_replacement",
            "switch_route",
        )
    ]
    assert (
        next(n for n in projection(trial)["nodes"] if n["id"] == "api")["security"]
        == "warning"
    )
    trial.isolation = SimpleNamespace(status=EffectStatus.APPLIED)
    doc = projection(trial)
    assert next(n for n in doc["nodes"] if n["id"] == "api")["security"] == "isolated"
    assert (
        next(r for r in doc["responses"] if r["stage"] == "recover")["status"]
        == "pending"
    )


def test_projection_cannot_accept_recreated_workload():
    trial = fixture()
    original = copy.deepcopy(trial.source)
    trial.source = original
    trial.api.get("deployment", "blue", "api")["metadata"]["uid"] = "replaced"
    with pytest.raises(ValueError, match="replaced"):
        projection(trial)


def test_projection_uses_start_of_observation_not_refresh_time():
    trial = fixture()
    trial.observation_started_at = datetime.now(UTC) - timedelta(seconds=45)
    doc = projection(trial)
    assert datetime.fromisoformat(doc["expires_at"]) < datetime.now(UTC)
