"""Deterministic safety checks; real cluster qualification is a separate script."""

from datetime import UTC, datetime, timedelta
from http.server import ThreadingHTTPServer
import json
import secrets
import threading
import time
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


def test_isolation_changes_rules_never_selectors(hybrid):
    from .operations import ResponseOperations

    applied, deleted = [], []

    class Fake:
        def get(self, side, kind, name):
            assert side == "source"
            return {"metadata": {"name": name}, "spec": {"podSelector": {}}}

        def apply(self, document, **_):
            applied.append(document)

        def delete_legacy_policy(self, side, name):
            deleted.append(name)

    ops = ResponseOperations()
    ops.kube, ops.state = Fake(), {"evidence": {}}
    ops.settings = {"aws": {"node_ips": ["172.28.10.11"]}}
    ops.policy(("api", "worker"))
    allows = {d["metadata"]["name"]: d["spec"] for d in applied}
    for role in ("api", "worker"):
        spec = allows["allow-" + role]
        assert spec["podSelector"] == {"matchLabels": hybrid.labels(role)}
        assert spec["ingress"] == [] and spec["egress"] == []
    assert allows["namespace-boundary"]["podSelector"] == hybrid.boundary_selector(
        "source"
    )
    assert allows["bridge-ingress"]["podSelector"]["matchExpressions"][0]["values"] == [
        "db"
    ]
    assert deleted == ["isolate-api", "isolate-worker"]
    applied.clear()
    ops.policy(())
    api = next(d for d in applied if d["metadata"]["name"] == "allow-api")["spec"]
    assert api["podSelector"] == {"matchLabels": hybrid.labels("api")}
    assert any("ipBlock" in peer for rule in api["ingress"] for peer in rule["from"])


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


def signed(tmp_path, clock=None):
    from .evidence import ResponseEvidence

    evidence = ResponseEvidence(
        tmp_path,
        tenant="owner",
        namespace="sova-hybrid-source",
        **({"clock": clock} if clock else {}),
    )
    checks = [
        {"name": "worker_new_connection_denied", "passed": True, "evidence": None}
    ]
    receipt = evidence.issue(
        run_id="run1",
        scenario="isolate",
        stage="verify",
        revision=3,
        plan_digest="a" * 64,
        environment="b" * 64,
        checks=checks,
    )
    return evidence, receipt


def test_signed_evidence_round_trip_and_bindings(tmp_path):
    from sova_security.contracts.commands import ContractError

    evidence, receipt = signed(tmp_path)
    assert evidence.accept(receipt, plan_digest="a" * 64, environment="b" * 64)
    assert (tmp_path / "evidence-signing.private.json").stat().st_mode & 0o077 == 0
    for plan, environment in (("c" * 64, "b" * 64), ("a" * 64, "c" * 64)):
        with pytest.raises(ContractError):
            evidence.accept(receipt, plan_digest=plan, environment=environment)


def test_tampered_replayed_or_expired_evidence_is_rejected(tmp_path):
    from datetime import UTC, datetime, timedelta
    from sova_security.contracts.commands import ContractError

    now = [datetime(2026, 11, 12, tzinfo=UTC)]
    evidence, receipt = signed(tmp_path, clock=lambda: now[0])
    path = tmp_path / "evidence" / (receipt["evidence_id"] + ".json")
    original = path.read_text()
    document = json.loads(original)
    document["evidence"]["result"] = "pass"
    document["evidence"]["artifact_digest"] = "f" * 64  # swap the checks
    path.write_text(json.dumps(document))
    with pytest.raises(ContractError):
        evidence.accept(receipt, plan_digest="a" * 64, environment="b" * 64)
    path.write_text(original)
    # A receipt pointing at another run's envelope fails the fingerprint binding.
    with pytest.raises(ContractError):
        evidence.accept(
            {**receipt, "fingerprint": "0" * 64},
            plan_digest="a" * 64,
            environment="b" * 64,
        )
    now[0] += timedelta(minutes=6)
    with pytest.raises(ContractError):
        evidence.accept(receipt, plan_digest="a" * 64, environment="b" * 64)


def test_failed_checks_sign_as_fail_and_never_pass_the_gate(tmp_path):
    from .evidence import ResponseEvidence
    from sova_security.contracts.commands import ContractError

    evidence = ResponseEvidence(tmp_path, tenant="owner", namespace="ns")
    receipt = evidence.issue(
        run_id="run1",
        scenario="egress",
        stage="verify",
        revision=1,
        plan_digest="a" * 64,
        environment="b" * 64,
        checks=[{"name": "controlled_external_endpoint_unreachable", "passed": False}],
    )
    assert receipt["result"] == "fail"
    with pytest.raises(ContractError):
        evidence.accept(receipt, plan_digest="a" * 64, environment="b" * 64)


def test_runner_code_change_invalidates_evidence(tmp_path, monkeypatch):
    from . import evidence as module
    from sova_security.contracts.commands import ContractError

    evidence, receipt = signed(tmp_path)
    monkeypatch.setattr(module, "producer_digest", lambda: "e" * 64)
    with pytest.raises(ContractError):
        evidence.accept(receipt, plan_digest="a" * 64, environment="b" * 64)


class HoldRuntime:
    """Just enough runtime for the security gate: state, root, environment."""

    def __init__(self, root):
        self.root = root
        self.environment = "e" * 64
        self.state = {
            "phase": "awaiting_approval",
            "plan": {"digest": "a" * 64},
            "approved": False,
            "checks": [],
            "evidence": {"signed": {"verify": {}}},
        }

    def environment_digest(self):
        return self.environment


def hold_setup(tmp_path, hybrid):
    from .security import SecurityGate
    from .security_approver import init, key_file, register

    runtime = HoldRuntime(tmp_path / "state")
    runtime.root.mkdir(mode=0o700)
    gate = SecurityGate(runtime)
    keys = tmp_path / "approver-keys"
    keys.mkdir(mode=0o700)
    public = init(keys, "recovery-approver")
    register(runtime.root, "recovery-approver", public, 1)
    gate.raise_hold("suspected-compromise")
    return runtime, gate, key_file(keys, "recovery-approver")


def test_security_hold_releases_only_with_independent_signed_current_approval(
    tmp_path, hybrid
):
    from sova_security.contracts.commands import ContractError
    from .security import approve

    runtime, gate, key = hold_setup(tmp_path, hybrid)
    assert gate.active()
    approval = approve(runtime.root, key, "recovery-approver", "contained-and-rotated")
    released = gate.release(approval)
    assert not gate.active() and released.release.approved_by == "recovery-approver"
    # No earlier approval or signed evidence survives the hold.
    assert runtime.state["phase"] == "detected" and runtime.state["plan"] is None
    assert "signed" not in runtime.state["evidence"]
    with pytest.raises(ContractError):
        gate.release(approval)


def test_hold_release_rejects_drift_tamper_and_unregistered_signers(tmp_path, hybrid):
    from sova_security.contracts.commands import ContractError
    from .security import approve
    from .security_approver import init, key_file

    runtime, gate, key = hold_setup(tmp_path, hybrid)
    approval = approve(runtime.root, key, "recovery-approver", "contained-and-rotated")
    runtime.environment = "f" * 64  # the environment changed after approval
    with pytest.raises(ContractError):
        gate.release(approval)
    runtime.environment = "e" * 64
    path = runtime.root / "releases" / (approval + ".json")
    stored = json.loads(path.read_text())
    stored["request"]["reason"] = "rubber-stamp"
    path.write_text(json.dumps(stored))
    with pytest.raises(ContractError):
        gate.release(approval)
    # A key that was never registered cannot approve, even with a valid signature.
    other = tmp_path / "other-keys"
    other.mkdir(mode=0o700)
    init(other, "intruder")
    forged = approve(runtime.root, key_file(other, "intruder"), "intruder", "let-me-in")
    with pytest.raises(ContractError):
        gate.release(forged)
    assert gate.active()


def test_operator_cannot_be_registered_or_approve_its_own_hold(tmp_path, hybrid):
    from sova_security.contracts.commands import ContractError
    from .security import hold_scope
    from .security_approver import register

    runtime, gate, _key = hold_setup(tmp_path, hybrid)
    with pytest.raises(SystemExit):
        register(runtime.root, "console-operator", "0" * 64, 1)
    with pytest.raises(ContractError):
        gate.authorize("console-operator", hold_scope(), "security:release-approve")


def test_runtime_refuses_every_effect_during_a_security_hold(runtime):
    runtime.state["security"] = {"active": True}
    for command in (
        "response reset",
        "response approve",
        "response plan",
        "recovery start",
    ):
        with pytest.raises(ValueError):
            runtime.validate_command(command)
    runtime.validate_command("security release rel-0123abcd")
    with pytest.raises(ValueError):
        runtime.select("isolate")


def observed_profiles():
    return {
        "source": {
            "provider": "aws",
            "backend": "eks",
            "kubernetes": "v1.35.9-eks",
            "network": {
                "cni": "aws-vpc-cni",
                "images": ["amazon-k8s-cni:v1.22.4"],
                "policy_engine": "vpc-cni-network-policy-agent",
            },
            "storage": "ebs-csi-gp3",
            "nodes": [["arm64", "t4g.medium", "Amazon Linux 2023"]],
            "placement": "aws",
        },
        "target": {
            "provider": "on-prem",
            "backend": "rke2",
            "kubernetes": "v1.35.9+rke2r1",
            "network": {
                "cni": "canal-calico",
                "images": ["hardened-calico:v3.32.2"],
                "policy_engine": "calico",
            },
            "storage": "local-pv",
            "nodes": [["arm64", "vm", "Ubuntu 24.04.5 LTS"]],
            "placement": "local",
        },
    }


def nine_report():
    session = {
        "checks": [{"name": "c", "passed": True}],
        "evidence": {"signed": {"verify": {"fingerprint": "f" * 64}}},
    }
    from .support import REQUIRED

    return {
        "passed": True,
        "started_at": "2026-11-12T00:00:00+00:00",
        "base_commit": "abc",
        "cluster_uid": {"aws": "u1", "local": "u2"},
        "results": [
            {"scenario": s, "passed": True, "state": {"session": session}}
            for s in REQUIRED
        ],
    }


def test_support_is_declared_only_from_a_matching_unexpired_record(tmp_path, hybrid):
    from datetime import UTC, datetime, timedelta
    from .evidence import ResponseEvidence
    from . import support

    evidence = ResponseEvidence(
        tmp_path, tenant="owner", namespace="sova-hybrid-source"
    )
    record = support.build(nine_report(), observed_profiles(), evidence=evidence)
    assert record["direction"] == {
        "from": "aws/eks",
        "to": "on-prem/rke2",
        "reverse_qualified": False,
        "failback": record["direction"]["failback"],
    }
    assert support.declare(record, observed_profiles())["status"] == "SUPPORTED"
    assert support.declare(None, observed_profiles())["status"] == "NEEDS_EVIDENCE"
    reverse = support.declare(
        record, observed_profiles(), direction={"from": "on-prem/rke2", "to": "aws/eks"}
    )
    assert reverse["status"] == "UNSUPPORTED"
    upgraded = observed_profiles()
    upgraded["source"]["network"]["images"] = ["amazon-k8s-cni:v1.23.3"]
    assert support.declare(record, upgraded)["status"] == "NEEDS_EVIDENCE"
    later = datetime.now(UTC) + timedelta(days=8)
    assert (
        support.declare(record, observed_profiles(), now=later)["status"]
        == "NEEDS_EVIDENCE"
    )


def test_support_record_requires_all_nine_passing(tmp_path, hybrid):
    from .evidence import ResponseEvidence
    from . import support

    evidence = ResponseEvidence(
        tmp_path, tenant="owner", namespace="sova-hybrid-source"
    )
    report = nine_report()
    report["results"] = report["results"][:-1]
    with pytest.raises(ValueError):
        support.build(report, observed_profiles(), evidence=evidence)


def test_rescan_classifies_findings_and_never_calls_remaining_resolved():
    from .registry import compare

    before = {
        "image_digest": "sha256:a",
        "findings": [["CVE-1", "HIGH"], ["CVE-2", "CRITICAL"]],
    }
    same = {
        "image_digest": "sha256:b",
        "findings": [["CVE-1", "HIGH"], ["CVE-2", "CRITICAL"]],
    }
    fixed = {
        "image_digest": "sha256:c",
        "findings": [["CVE-1", "HIGH"], ["CVE-9", "LOW"]],
    }
    unchanged = compare(before, same)
    assert unchanged["resolved"] == {} and unchanged["remaining"] == {
        "HIGH": 1,
        "CRITICAL": 1,
    }
    changed = compare(before, fixed)
    assert changed["resolved"] == {"CRITICAL": 1}
    assert changed["introduced"] == {"LOW": 1} and changed["introduced_names"] == [
        "CVE-9"
    ]


def test_patch_rescan_outcomes(tmp_path):
    from .operations import ResponseOperations

    checks = []
    ops = ResponseOperations()
    ops.state = {
        "evidence": {
            "image_scan_before": {"not_run": "no_registry_scan_in_local_topology"}
        }
    }
    ops.rescan_patched_image(
        lambda name, ok, ev=None: checks.append((name, ok)),
        "x@sha256:" + "a" * 64,
        True,
    )
    assert ops.state["evidence"]["remediation"]["image_findings"]["status"] == "NOT_RUN"
    assert checks == []  # local topology: no registry rescan, never a PASS


def test_registry_scan_is_bound_to_the_run_repository():
    from .registry import ScanUnavailable, scan

    with pytest.raises(ScanUnavailable):
        scan({}, "repo@sha256:" + "a" * 64)
    settings = {
        "aws": {
            "repository_url": "111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/run-a",
            "region": "ap-northeast-2",
        }
    }
    with pytest.raises(ScanUnavailable):
        scan(
            settings,
            "111111111111.dkr.ecr.ap-northeast-2.amazonaws.com/other@sha256:"
            + "a" * 64,
        )


class SqlKube:
    """Fake adapter: answers the fixed SQL probes and records every statement."""

    def __init__(self, logins, *, old_password_works=False):
        self.logins = logins
        self.old_password_works = old_password_works
        self.statements = []

    def sql(self, side, text, parameters=None, *, admin=False, password=None):
        self.statements.append((side, text))
        if "rolcanlogin" in text:
            return {"ok": True, "rows": [[self.logins[side]]]}
        if password is not None:
            return {"ok": self.old_password_works, "rows": [[1]]}
        return {"ok": True, "rows": []}


@pytest.mark.parametrize(
    "logins",
    [
        {"source": False, "target": False},  # activation intent, result unknown
        {"source": True, "target": True},  # two writers
        {"source": True, "target": False},  # source reopened
    ],
)
def test_uncertain_activation_holds_instead_of_reopening_the_source(runtime, logins):
    """AT-20: after TARGET_ACTIVATION_INTENT nothing reopens the source by guess."""
    from .kube import Unconfirmed

    runtime.kube = SqlKube(logins)
    runtime.state.update(scenario="migrate", phase="held")
    runtime.state["evidence"] = {"migration_authority": "target_pending"}
    with pytest.raises(Unconfirmed, match="writer_authority_ambiguous"):
        runtime.reset()
    assert not any(
        "LOGIN" in text and "NOLOGIN" not in text
        for _side, text in runtime.kube.statements
        if "ALTER" in text
    )


def test_target_is_not_activated_while_the_source_still_accepts_logins(runtime):
    """AT-19: an unconfirmed source fence blocks activation of the target."""
    from .kube import Unconfirmed

    runtime.kube = SqlKube({"source": False, "target": False}, old_password_works=True)
    runtime.state.update(scenario="migrate")
    runtime.settings["password"] = "PRIVATE-DO-NOT-EXPOSE"
    with pytest.raises(Unconfirmed, match="source_writer_not_fenced"):
        runtime.finalize()
    assert not any(
        "ALTER ROLE app LOGIN" in text for _side, text in runtime.kube.statements
    )
    assert runtime.state["evidence"].get("migration_authority") != "target"


def test_approval_refuses_a_plan_whose_effect_changed(runtime):
    """P-AT-03 / INV-05: approval binds the exact image a patch deploys."""
    from .kube import Unconfirmed

    runtime.settings["images"] = {
        v: {"image": "localhost/sova-response/app@sha256:" + c * 64}
        for v, c in (("v1", "a"), ("v2", "b"), ("bad", "c"))
    }
    # The local bundle also carries a plain digest next to the images.
    runtime.settings["images"]["workload_sha256"] = "e" * 64
    runtime.state.update(scenario="patch")
    from .contracts import digest as plan_digest
    from .evidence import producer_digest

    binding = {
        "effect": runtime.intended_effect(),
        "runner": producer_digest(),
        "expires_at": time.time() + 60,
    }

    runtime.state["plan"] = {"binding": binding, "digest": plan_digest(binding)}
    runtime.settings["images"]["v2"]["image"] = (
        "localhost/sova-response/app@sha256:" + "d" * 64
    )
    with pytest.raises(Unconfirmed, match="approved_effect_changed_replan_required"):
        runtime.perform("response approve")


def test_a_closing_runner_refuses_new_commands(runtime):
    runtime.closing = True
    with pytest.raises(ValueError, match="runner_shutting_down"):
        runtime.submit(
            {
                "request_id": secrets.token_hex(16),
                "revision": 0,
                "command": "response reset",
            }
        )


class PodKube:
    """Fake adapter that reports a fixed set of pod UIDs per side and role."""

    def __init__(self, uids):
        self.uids = uids

    def get(self, side, kind, name=None):
        assert kind == "pods"
        return {
            "items": [
                {"metadata": {"uid": uid, "labels": {"sova.io/role": role}}}
                for role, uids in self.uids.get(side, {}).items()
                for uid in uids
            ]
        }


def test_approval_refuses_a_plan_after_the_target_pods_changed(runtime):
    """AT-11: the same names with new UIDs void the plan."""
    from .contracts import digest as plan_digest
    from .evidence import producer_digest
    from .kube import Unconfirmed

    runtime.settings["images"] = {
        "v1": {"image": "localhost/sova-response/app@sha256:" + "a" * 64}
    }
    runtime.state.update(scenario="isolate")
    runtime.kube = PodKube({"source": {"api": ["api-1"], "worker": ["worker-1"]}})
    binding = {
        "pods": runtime.current_uids(),
        "effect": runtime.intended_effect(),
        "runner": producer_digest(),
        "expires_at": time.time() + 60,
    }
    runtime.state["plan"] = {"binding": binding, "digest": plan_digest(binding)}
    runtime.kube = PodKube({"source": {"api": ["api-1"], "worker": ["worker-2"]}})
    with pytest.raises(Unconfirmed, match="workload_changed_replan_required"):
        runtime.perform("response approve")
    assert runtime.state["approved"] is False


def test_foreign_namespaces_are_refused_before_any_change():
    """INV-11: ownership is checked on every call, not inferred from names."""
    from .kube import Cluster, Kube, Unconfirmed

    class Foreign(Cluster):
        def run(self, args, value=None, timeout=35):
            if args[:3] == ["get", "namespace", "kube-system"]:
                return json.dumps({"metadata": {"uid": "fixed"}})
            if args[:2] == ["get", "namespace"]:
                return json.dumps(
                    {
                        "metadata": {
                            "uid": "u",
                            "labels": {"sova.io/owner": "someone-else"},
                        }
                    }
                )
            raise AssertionError("no other call may happen: " + " ".join(args))

    kube = Kube({"local": Foreign("local", [], "fixed")})
    with pytest.raises(Unconfirmed, match="namespace_ownership_mismatch"):
        kube.owned("source")
    with pytest.raises(ValueError):
        kube.apply(
            {
                "metadata": {
                    "name": "x",
                    "namespace": "kube-system",
                    "labels": {"sova.io/owner": OWNER},
                }
            }
        )
    with pytest.raises(ValueError):
        kube.apply(
            {"metadata": {"name": "x", "namespace": NAMESPACES["source"], "labels": {}}}
        )


def test_an_expired_release_approval_cannot_release_the_hold(tmp_path, hybrid):
    from datetime import UTC, datetime, timedelta
    from sova_security.contracts.commands import ContractError
    from .security import approve

    runtime, gate, key = hold_setup(tmp_path, hybrid)
    approval = approve(
        runtime.root, key, "recovery-approver", "contained-and-rotated", minutes=1
    )
    gate.clock = lambda: datetime.now(UTC) + timedelta(minutes=2)
    with pytest.raises(ContractError):
        gate.release(approval)
    assert gate.active()
