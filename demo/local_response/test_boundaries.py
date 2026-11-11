"""Deterministic safety checks; real cluster qualification is a separate script."""

from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
import json
import secrets
import threading
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from operator_auth import OperatorAuth
from .manifests import documents, NAMESPACES, OWNER
from .provision import private_json
from .runtime import Runtime
from .server import handler, local_assets


@pytest.fixture
def runtime(tmp_path):
    private_json(
        tmp_path / "settings.private.json",
        {
            "cluster_uid": "fixed",
            "namespace_uids": {},
            "admin": "PRIVATE-DO-NOT-EXPOSE",
            "password": "PRIVATE-DO-NOT-EXPOSE",
        },
    )
    return Runtime(tmp_path, kube=object())


def test_replayed_command_is_not_dispatched_twice(runtime, monkeypatch):
    calls = []

    class PendingThread:
        def __init__(self, **kwargs):
            calls.append(kwargs)

        def start(self):
            pass

    monkeypatch.setattr(threading, "Thread", PendingThread)
    value = {
        "request_id": secrets.token_hex(16),
        "revision": 0,
        "command": "inject lateral-movement --target api,worker",
    }
    assert runtime.submit(value)["duplicate"] is False
    assert runtime.submit(value)["duplicate"] is True
    assert len(calls) == 1
    with pytest.raises(RuntimeError, match="idempotency_conflict"):
        runtime.submit({**value, "command": "response reset"})
    with pytest.raises(ValueError, match="stale_or_busy"):
        runtime.submit({**value, "request_id": secrets.token_hex(16)})


def test_crashed_effect_is_held_without_dispatch(runtime):
    runtime.db.execute("INSERT INTO effects VALUES('lost','request','started','{}')")
    runtime.db.commit()
    restored = Runtime(runtime.root, kube=object())
    assert restored.state["phase"] == "held"
    assert (
        restored.db.execute("SELECT status FROM effects WHERE id='lost'").fetchone()[0]
        == "unknown"
    )
    assert restored.state["history"][-1]["provenance"] == "local-rke2"


@pytest.mark.parametrize(
    "command",
    [
        "response approve",
        "response finalize",
        "recovery finalize",
        "inject lateral-movement --target api,worker,db",
        "rm -rf /",
        "kubectl delete namespace target-dev",
        "response reset; echo injected",
    ],
)
def test_wrong_phase_or_shell_command_rejected(runtime, command):
    with pytest.raises(ValueError):
        runtime.validate_command(command)


def test_status_never_reveals_configuration_secrets(runtime):
    raw = json.dumps(runtime.status())
    assert "PRIVATE-DO-NOT-EXPOSE" not in raw
    assert runtime.status()["actual_execution"] is True
    assert runtime.status()["observation"] is None


def test_manifests_are_scoped_bounded_and_no_app_db_admin():
    image = "localhost/sova-response/app@sha256:" + "a" * 64
    db = "localhost/sova-response/db@sha256:" + "b" * 64
    docs = documents(image, db, "PASSWORD", "ADMIN", "DBADMIN")
    assert len([doc for doc in docs if doc["kind"] == "Namespace"]) == 3
    assert all(doc["metadata"]["labels"]["sova.io/owner"] == OWNER for doc in docs)
    for doc in docs:
        ns = doc["metadata"].get("namespace")
        assert ns is None or ns in NAMESPACES.values()
        if doc["kind"] != "Deployment":
            continue
        spec = doc["spec"]["template"]["spec"]
        assert spec["automountServiceAccountToken"] is False
        assert not any(volume.get("hostPath") for volume in spec["volumes"])
        assert all(
            c["securityContext"]["allowPrivilegeEscalation"] is False
            for c in spec["containers"]
        )
        if doc["metadata"]["name"] not in {"probe", "db"}:
            mounted = next(
                v["secret"] for v in spec["volumes"] if v["name"] == "credentials"
            )
            assert "dbadmin" not in {item["key"] for item in mounted["items"]}


def test_loopback_http_auth_origin_csrf_and_readonly(runtime):
    auth = OperatorAuth(
        deadline=datetime.now(UTC) + timedelta(hours=1), clock=lambda: datetime.now(UTC)
    )
    token = auth.issue_bootstrap()
    server = ThreadingHTTPServer(("127.0.0.1", 0), lambda *args: None)
    origin = "http://127.0.0.1:" + str(server.server_port)
    server.RequestHandlerClass = handler(runtime, auth, origin, local_assets())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def request(path, body=None, headers=None):
        hdr = {"Content-Type": "application/json", "Origin": origin, **(headers or {})}
        req = Request(
            origin + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=hdr,
        )
        try:
            with urlopen(req, timeout=2) as response:
                return response.status, response.headers, json.loads(response.read())
        except HTTPError as error:
            return error.code, error.headers, json.loads(error.read())

    try:
        assert request("/api/state")[0] == 403
        assert (
            request(
                "/api/session", {"token": token}, {"Origin": "https://evil.example"}
            )[0]
            == 403
        )
        code, headers, body = request("/api/session", {"token": token})
        assert code == 200 and "csrf" in body
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        assert (
            "HttpOnly" in headers["Set-Cookie"]
            and "SameSite=Strict" in headers["Set-Cookie"]
        )
        assert request("/api/session", {"token": token})[0] == 403
        assert request("/api/command", {}, {"Cookie": cookie})[0] == 403
        before = runtime.state["revision"]
        assert request("/api/state", headers={"Cookie": cookie})[0] == 200
        assert runtime.state["revision"] == before
        assert (
            request("/api/state", headers={"Cookie": cookie, "Host": "evil.example"})[0]
            == 403
        )
        assert (
            request(
                "/api/command",
                {"command": "response approve"},
                {"Cookie": cookie, "X-Sova-CSRF": body["csrf"]},
            )[0]
            == 409
        )
    finally:
        server.shutdown()
        server.server_close()


def test_live_and_static_sources_remain_distinct():
    from response_scenarios.__main__ import assets

    assert b'data-runtime="local-rke2"' not in assets()["/"][0]
    assert b'data-runtime="local-rke2"' in local_assets()["/"][0]
    assert b"connect-src 'self'" in local_assets()["/"][0]


def test_zero_replicas_waits_for_old_pod_to_disappear(monkeypatch):
    from .kube import Kube

    kube = Kube()
    reads = []
    pod_reads = iter(
        [
            {"items": [{"metadata": {"labels": {"sova.io/role": "worker"}}}]},
            {"items": []},
        ]
    )

    def get(_side, kind, _name=None):
        reads.append(kind)
        return (
            next(pod_reads)
            if kind == "pods"
            else {
                "metadata": {"generation": 2},
                "spec": {"replicas": 0},
                "status": {"observedGeneration": 2},
            }
        )

    monkeypatch.setattr(kube, "get", get)
    monkeypatch.setattr("time.sleep", lambda _seconds: None)
    kube.wait("source", "worker")
    assert reads.count("pods") == 2


def test_http_qualify_stays_on_loopback_and_runs_every_stage():
    from .http_qualify import Console, ORDER, steps

    with pytest.raises(ValueError):
        Console("http://192.168.0.10:18142")
    with pytest.raises(ValueError):
        Console("https://127.0.0.1:18142")
    assert sorted(ORDER) == sorted(
        [
            "isolate",
            "segment",
            "egress",
            "credentials",
            "patch",
            "restart",
            "scale",
            "migrate",
            "rollback",
        ]
    )
    for scenario in ORDER:
        values = steps(scenario)
        assert values[1:6] == [
            "response plan",
            "response submit",
            "response approve",
            "response verify",
            "response finalize",
        ]
        assert (values[-1] == "recovery finalize") == (
            scenario in {"isolate", "segment"}
        )


@pytest.fixture
def hybrid():
    from . import manifests

    manifests.configure("hybrid-aws")
    try:
        yield manifests
    finally:
        manifests.configure("local")


def test_hybrid_paths_cross_clusters_only_through_the_bridge(hybrid):
    assert hybrid.probe_side("source") == "source-control"
    assert hybrid.probe_side("target") == "control"
    assert hybrid.host("target", "db", "source") == "source-db.sova-hybrid-control"
    assert hybrid.host("control", "api", "source") == "source-api.sova-hybrid-control"
    assert hybrid.host("source", "db", "source") == "db.sova-hybrid-source"
    # Nothing on the EKS source can call into this Mac.
    with pytest.raises(ValueError):
        hybrid.host("source", "api", "target")
    with pytest.raises(ValueError):
        hybrid.host("target", "auth", "source")
    with pytest.raises(ValueError):
        hybrid.bridge_documents("aws", ["0.0.0.0/0"])
    froms = hybrid.bridge_documents("aws", ["172.28.10.12", "172.28.10.11"])[0]["spec"][
        "ingress"
    ][0]["from"]
    assert [f["ipBlock"]["cidr"] for f in froms] == [
        "172.28.10.11/32",
        "172.28.10.12/32",
    ]


def test_hybrid_manifests_split_by_cluster_and_pin_images(hybrid):
    ecr = "123456789012.dkr.ecr.ap-northeast-2.amazonaws.com/sova-response-hy1112a@sha256:"
    local = "localhost/sova-response/app@sha256:" + "a" * 64
    with pytest.raises(ValueError):
        hybrid.documents(
            local,
            local,
            "p",
            "a",
            "d",
            cluster="aws",
            node_ips=["172.28.10.11", "172.28.10.12"],
        )
    aws = hybrid.documents(
        ecr + "a" * 64,
        ecr + "b" * 64,
        "p",
        "a",
        "d",
        cluster="aws",
        node_ips=["172.28.10.11", "172.28.10.12"],
    )
    here = hybrid.documents(
        local, local.replace("app", "db"), "p", "a", "d", cluster="local"
    )

    def names(docs):
        return {d["metadata"].get("namespace") for d in docs} - {None}

    assert names(aws) == {"sova-hybrid-source", "sova-hybrid-control"}
    assert names(here) == {"sova-hybrid-target", "sova-hybrid-control"}
    assert all(
        d["metadata"]["labels"]["sova.io/owner"] == "sova-hybrid-response-20261112"
        for d in aws + here
    )
    assert not any(d["kind"] == "PersistentVolume" for d in aws)
    pulls = {
        d["metadata"]["name"]: d["spec"]["template"]["spec"]["containers"][0][
            "imagePullPolicy"
        ]
        for d in aws
        if d["kind"] == "Deployment"
    }
    assert set(pulls.values()) == {"IfNotPresent"}
    edge = next(
        d for d in here if d["kind"] == "Deployment" and d["metadata"]["name"] == "edge"
    )
    env = {
        e["name"]: e.get("value")
        for e in edge["spec"]["template"]["spec"]["containers"][0]["env"]
    }
    assert env["SOURCE_API"] == "source-api.sova-hybrid-control"
    slices = [d for d in here if d["kind"] == "EndpointSlice"]
    assert {s["endpoints"][0]["addresses"][0] for s in slices} == {hybrid.LIMA_HOST}


def test_isolated_role_leaves_the_bridge_allow(hybrid, tmp_path):
    from .operations import ResponseOperations

    applied = []

    class Fake:
        def get(self, side, kind, name):
            assert side == "source"
            return {"metadata": {"name": name}, "spec": {"podSelector": {}}}

        def apply(self, document, **_):
            applied.append(document)

    ops = ResponseOperations()
    ops.kube, ops.state = Fake(), {"evidence": {}}
    ops.policy(("api", "worker"))
    bridge = next(d for d in applied if d["metadata"]["name"] == "bridge-ingress")
    assert bridge["spec"]["podSelector"]["matchExpressions"][0]["values"] == ["db"]


def test_kubectl_failures_expose_only_a_category():
    from .kube import failure_kind

    assert (
        failure_kind(
            "The request is invalid: the server rejected our request due to an error in our request"
        )
        == "rejected"
    )
    assert (
        failure_kind("error: You must be logged in to the server (Unauthorized)")
        == "unauthorized"
    )
    assert failure_kind("dial tcp: lookup x: no such host") == "connection"
    assert failure_kind("something else entirely") == "other"


def test_patch_retries_only_an_atomic_test_rejection(monkeypatch):
    from . import kube as module

    calls = []

    class Fake(module.Kube):
        def patch_once(self, side, kind, name, patch):
            calls.append(1)
            error = module.Unconfirmed("x")
            error.kind = "rejected" if len(calls) < 3 else "forbidden"
            raise error

    monkeypatch.setattr(module.time, "sleep", lambda _s: None)
    with pytest.raises(module.Unconfirmed) as raised:
        Fake().patch("source", "deployment", "worker", {"spec": {}})
    assert raised.value.kind == "forbidden" and len(calls) == 3
