"""Bounded stateless EKS/RKE2 qualification gateway, not DB/ALB migration.

Registration and kubeconfigs are owner-supplied files. Browser requests cannot
select commands, endpoints, images or Kubernetes resources. Route changes use
the existing PostgreSQL approval, ownership, effect journal and route CAS.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import http.client
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import threading
import time
import traceback

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import psycopg
from bounded_http import BoundedLoopbackServer
from relocation_receipts import RelocationReceipts
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.adapters.postgres_security_routes import PostgresSecurityRoutes
from sova.adapters.postgres_governance import PostgresSecurityHolds
from sova.application.effects import EffectExecutor
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    EffectObservation,
    EffectStatus,
    canonical_json,
)
from sova.domain.plans import LifecyclePlan, PlanStep, PlanPurpose, PlanApproval
from sova.domain.operations import OperationRequest
from sova.domain.evidence import (
    RevisionSet,
    VerificationObligation,
    Gate,
    EvidenceRecord,
    VerificationResult,
)
from sova.ports.plans import RecordNotFound


def now():
    return datetime.now(UTC)


def fingerprint(value):
    return hashlib.sha256(canonical_json(value).encode()).hexdigest()


def validate_running_artifacts(document, expected):
    """Desired Deployment alone cannot attest to the currently running Pods."""
    try:
        items = document["items"]
        deployments = [x for x in items if x["kind"] == "Deployment"]
        pods = [x for x in items if x["kind"] == "Pod"]
        if (
            len(deployments) != 1
            or deployments[0]["metadata"]["name"] != "quote"
            or deployments[0]["metadata"]["uid"] != expected["deployment_uid"]
            or deployments[0]["spec"]["replicas"] != 2
            or len(pods) != 2
            or {p["metadata"]["uid"] for p in pods} != set(expected["pod_uids"])
        ):
            raise ContractError("Registered workload identity changed")
        owners = {
            x["metadata"]["uid"]
            for x in items
            if x["kind"] == "ReplicaSet"
            and any(
                o.get("kind") == "Deployment"
                and o.get("controller") is True
                and o.get("uid") == expected["deployment_uid"]
                for o in x["metadata"].get("ownerReferences", [])
            )
        }
        specs = [deployments[0]["spec"]["template"]["spec"]] + [p["spec"] for p in pods]
        for spec in specs:
            containers = spec["containers"]
            security = spec["securityContext"]
            if (
                len(containers) != 1
                or containers[0]["image"] != expected["image"]
                or spec.get("volumes")
                or spec.get("initContainers")
                or spec.get("ephemeralContainers")
                or spec.get("hostNetwork")
                or spec.get("hostPID")
                or spec.get("hostIPC")
                or spec.get("automountServiceAccountToken") is not False
                or security.get("runAsNonRoot") is not True
                or security.get("runAsUser") != 10001
                or security.get("seccompProfile", {}).get("type") != "RuntimeDefault"
            ):
                raise ContractError("Registered stateless configuration changed")
            container = containers[0]["securityContext"]
            if (
                container.get("readOnlyRootFilesystem") is not True
                or container.get("allowPrivilegeEscalation") is not False
                or container.get("privileged", False)
                or container.get("capabilities", {}).get("drop") != ["ALL"]
            ):
                raise ContractError("Running workload protection changed")
        for pod in pods:
            statuses = pod["status"]["containerStatuses"]
            if (
                pod["metadata"].get("deletionTimestamp")
                or pod["status"].get("phase") != "Running"
                or len(statuses) != 1
                or statuses[0].get("ready") is not True
                or not statuses[0]
                .get("imageID", "")
                .endswith(expected["image"].split("@")[1])
                or not any(
                    o.get("controller") is True
                    and o.get("kind") == "ReplicaSet"
                    and o.get("uid") in owners
                    for o in pod["metadata"].get("ownerReferences", [])
                )
            ):
                raise ContractError("Running Pod digest, readiness or owner changed")
    except (KeyError, TypeError, IndexError) as exc:
        raise ContractError("Running workload evidence is malformed") from exc


class RouteAdapter:
    adapter_id = "owned-stateless-route-cas"

    def __init__(self, runtime):
        self.runtime = runtime

    def validate(self, command):
        p = command.parameters
        if (
            command.action != "switch_route"
            or set(p) != {"source", "target", "route_revision", "registration"}
            or p["source"] not in {"aws", "vm"}
            or p["target"] not in {"aws", "vm"}
            or p["source"] == p["target"]
            or type(p["route_revision"]) is not int
            or p["registration"] != self.runtime.revision
        ):
            raise ContractError("Exact owned route intent required")

    def apply(self, command):
        self.validate(command)
        self.runtime.require_registration()
        p = command.parameters
        self.runtime.routes.switch(
            self.runtime.app,
            "quote-entry",
            source=p["source"],
            target=p["target"],
            expected_revision=p["route_revision"],
            plan_digest=command.plan_digest,
        )

    def readback(self, command, at):
        p = command.parameters
        route = self.runtime.route()
        applied = (
            route["environment_id"] == p["target"]
            and route["revision"] == p["route_revision"] + 1
            and route["plan_digest"] == command.plan_digest
        )
        # This receipt proves route CAS only; workload response is postflight.
        return EffectObservation(
            command.scope,
            command.fingerprint,
            EffectStatus.APPLIED if applied else EffectStatus.UNKNOWN,
            at,
            canonical_json(route),
        )


class Relocation:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.registration_bytes = (
            self.root / "workload-registration.json"
        ).read_bytes()
        self.registration = json.loads(self.registration_bytes)
        if self.registration["profile"] != "eks-rke2-stateless-v1":
            raise ContractError("Qualified stateless registration required")
        self.expiry = datetime.fromisoformat(self.registration["expires_at"])
        self.revision = hashlib.sha256(self.registration_bytes).hexdigest()
        self.app = (
            "relocation-"
            + json.loads((self.root / "ownership.json").read_text())["run_id"]
        )
        self.tenant = "local-operator"
        self.actor = "local-os-user:" + str(os.geteuid())
        self.ports = {"aws": 18080, "vm": 19980}
        db = json.loads((self.root / "control-db.json").read_text())
        self.connect = lambda: psycopg.connect(db["worker_dsn"])
        self.admitter = lambda: psycopg.connect(db["admitter_dsn"])
        self.lifecycle = PostgresLifecycleRepository(
            self.connect, tenant_id=self.tenant
        )
        self.routes = PostgresSecurityRoutes(self.connect, tenant_id=self.tenant)
        self.restore_route()
        self.holds = PostgresSecurityHolds(self.connect, tenant_id=self.tenant)
        self.lock = threading.RLock()
        self.action_lock = threading.Lock()
        self.stopped = threading.Event()
        self.observations = {}
        self.requests = []
        self.total = self.successes = 0
        self.latencies = []
        self.events = []
        self.receipts = RelocationReceipts(self.lifecycle)
        self.workflows = self.receipts.history(self.app, self.revision)
        self.operation = None
        self.inflight = {"aws": 0, "vm": 0}
        self.require_registration()
        self.thread = threading.Thread(target=self.observe, daemon=True)
        self.thread.start()

    def restore_route(self):
        marker = self.root / "route-initialized.json"
        identity = {
            "tenant": self.tenant,
            "application": self.app,
            "route": "quote-entry",
        }
        if marker.exists():
            if json.loads(marker.read_text()) != identity:
                raise ContractError("Route initialization identity changed")
            # Missing control state after initialization is an incident, not
            # permission to silently recreate a default route.
            self.routes.get(self.app, "quote-entry")
            return
        try:
            self.routes.get(self.app, "quote-entry")
        except RecordNotFound:
            self.routes.register(self.app, "quote-entry", "aws")
        with marker.open("x") as stream:
            stream.write(canonical_json(identity))

    def require_registration(self):
        if (
            self.stopped.is_set()
            or now() >= self.expiry
            or (self.root / "workload-registration.json").read_bytes()
            != self.registration_bytes
        ):
            raise ContractError("Registration expired or changed")

    def route(self):
        return self.routes.get(self.app, "quote-entry")

    def probe(self, side):
        self.require_registration()
        identity = self.registration["workloads"][side]
        nonce = secrets.token_hex(16)
        start = time.monotonic()
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.ports[side], timeout=3
        )
        result = {
            "available": False,
            "observed_at": time.time(),
            "instance": identity["instance"],
        }
        try:
            connection.request(
                "GET", "/quote?quantity=2", headers={"X-Request-ID": nonce}
            )
            response = connection.getresponse()
            raw = response.read(8193)
            if len(raw) > 8192 or response.status != 200:
                raise ContractError("Workload response unverified")
            body = json.loads(raw)
            if type(body) is not dict:
                raise ContractError("Object workload response required")
            if (
                body.get("request_id") != nonce
                or body.get("application") != "sova-stateless-quote"
                or body.get("environment") != side
                or body.get("instance") != identity["instance"]
                or body.get("pod_uid") not in identity["pod_uids"]
                or body.get("code_digest") != self.registration["code_digest"]
                or body.get("total") != 220
                or body.get("database") is not False
            ):
                raise ContractError("Workload identity or business result mismatch")
            result.update(
                available=True,
                request_id=nonce,
                pod_uid=body["pod_uid"],
                total=220,
                code_digest=body["code_digest"],
            )
        except (OSError, ValueError, http.client.HTTPException):
            result["error"] = "response_unverified"
        finally:
            connection.close()
        result["latency_ms"] = round((time.monotonic() - start) * 1000, 3)
        result["observed_at"] = time.time()
        return result

    def observe(self):
        while not self.stopped.is_set() and now() < self.expiry:
            for side in ("aws", "vm"):
                try:
                    result = self.probe(side)
                    with self.lock:
                        self.observations[side] = result
                except ContractError:
                    return
            self.stopped.wait(2)

    def work(self):
        self.require_registration()
        side = self.route()["environment_id"]
        with self.lock:
            self.inflight[side] += 1
        try:
            proof = self.probe(side)
            record = {
                "id": proof.get("request_id", secrets.token_hex(16)),
                "at": time.time(),
                "environment": side,
                "ok": proof["available"],
                "latency_ms": proof["latency_ms"],
                "total": proof.get("total"),
                "pod_uid": proof.get("pod_uid"),
                "code_digest": proof.get("code_digest"),
            }
            with self.lock:
                self.requests.append(record)
                self.requests = self.requests[-200:]
                self.total += 1
                self.successes += record["ok"]
                self.latencies.append(record["latency_ms"])
                self.latencies = self.latencies[-10000:]
                with (self.root / "business-requests.jsonl").open("a") as stream:
                    stream.write(json.dumps(record) + "\n")
            return record
        finally:
            with self.lock:
                self.inflight[side] -= 1

    def inspect_artifacts(self):
        for side in ("aws", "vm"):
            expected = self.registration["workloads"][side]
            result = subprocess.run(
                [
                    "kubectl",
                    "--kubeconfig",
                    str(self.root / (side + "-kubeconfig.json")),
                    "--request-timeout=5s",
                    "-n",
                    expected["namespace"],
                    "get",
                    "deployment,replicaset,pod",
                    "-l",
                    "app.kubernetes.io/name=quote",
                    "-o",
                    "json",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode:
                raise ContractError("Current Kubernetes artifact unverified")
            validate_running_artifacts(json.loads(result.stdout), expected)

    def emit(self, kind, target, detail):
        with self.lock:
            self.events.append(
                {
                    "seq": len(self.events) + 1,
                    "at": time.time(),
                    "kind": kind,
                    "environment": target,
                    "detail": detail,
                }
            )

    def switch(self, target, revision, expected_route):
        if not self.action_lock.acquire(blocking=False):
            raise ContractError("A route change is already running")
        lease = None
        try:
            self.require_registration()
            route = self.route()
            if (
                revision != self.revision
                or type(expected_route) is not int
                or expected_route != route["revision"]
                or type(target) is not str
                or target not in {"aws", "vm"}
                or target == route["environment_id"]
            ):
                raise ContractError("Approval route or registration changed")
            if any(
                w["status"] == "needs_attention"
                for w in self.receipts.history(self.app, self.revision)
            ):
                raise ContractError(
                    "Prior route effect requires postflight reconciliation"
                )
            self.inspect_artifacts()
            target_proof = self.probe(target)
            if not target_proof["available"]:
                raise ContractError("Target business response is not verified")
            if self.holds.active_holds(self.app):
                raise ContractError("Independent security hold blocks route changes")
            scope = ResourceScope(self.tenant, self.app, "local-entry", "quote-entry")
            revisions = RevisionSet(
                self.revision,
                self.registration["code_digest"],
                fingerprint({"profile": self.registration["profile"]}),
                self.revision,
            )
            obligation = VerificationObligation(
                "target-quote-and-artifact",
                scope,
                Gate.PREFLIGHT,
                "owned-stateless-quote-v1",
            )
            until = min(self.expiry, now() + timedelta(seconds=60))
            plan = LifecyclePlan(
                "route-" + secrets.token_hex(8),
                self.tenant,
                self.app,
                "fixed-stateless-plan-compiler:v1",
                PlanPurpose.CHANGE,
                revisions,
                until,
                (
                    PlanStep(
                        "route",
                        scope,
                        RouteAdapter.adapter_id,
                        "switch_route",
                        canonical_json(
                            {
                                "source": route["environment_id"],
                                "target": target,
                                "route_revision": expected_route,
                                "registration": self.revision,
                            }
                        ),
                        "route-" + str(expected_route),
                    ),
                ),
                (obligation,),
            )
            proof = EvidenceRecord(
                "quote-proof",
                obligation.obligation_id,
                scope,
                revisions,
                obligation.verifier_version,
                now(),
                until,
                VerificationResult.PASS,
                "owned-runtime-probe",
                fingerprint(target_proof),
            )
            admission = PostgresLifecycleRepository(
                self.admitter, tenant_id=self.tenant
            )
            admission.save_plan(plan)
            approval = PlanApproval(plan.fingerprint, self.actor, plan.purpose, until)
            approval_id = "approval:" + plan.plan_id
            admission.save_approval(self.app, plan.plan_id, approval_id, approval)
            request = OperationRequest(
                self.tenant,
                self.app,
                "operation:" + plan.plan_id,
                plan.plan_id,
                plan.fingerprint,
                approval_id,
                1,
                self.actor,
                "route:" + plan.fingerprint,
            )
            PostgresOperationRepository(admission).submit(request)
            ownership = PostgresExecutionOwnership(self.lifecycle)
            lease = ownership.acquire(
                self.app, request.operation_id, "local-route-worker", lease_seconds=120
            )
            journal = PostgresEffectJournal(ownership, lease)

            def guard(current, at):
                self.require_registration()
                if self.holds.active_holds(self.app):
                    raise ContractError("Security hold raised during dispatch")
                return self.expiry

            def auth_approval(current, saved):
                if current.fingerprint != plan.fingerprint or saved != approval:
                    raise ContractError("Exact local approval required")

            def auth_evidence(record):
                if record != proof:
                    raise ContractError("Unregistered local evidence")

            executor = ApprovedPlanExecutor(
                EffectExecutor(journal, authorize=journal.authorize, clock=now),
                required_obligations=lambda p: (obligation,),
                authenticate_approval=auth_approval,
                authenticate_evidence=auth_evidence,
                governance_guard=guard,
                clock=now,
            )
            workflow = {
                "id": request.operation_id,
                "target": target,
                "status": "running",
                "plan_digest": plan.fingerprint,
                "full_migration_verified": False,
                "steps": [],
            }
            with self.lock:
                self.operation = workflow
            self.emit("approved", target, "등록·현재 경로·이미지에 결합된 운영자 승인")
            result = StoredPlanExecutor(self.lifecycle, executor).execute_step(
                self.app,
                plan.plan_id,
                approval_id,
                "route",
                operation_id=request.operation_id,
                epoch=lease.epoch,
                evidence=(proof,),
                adapter=RouteAdapter(self),
            )
            if result.status != EffectStatus.APPLIED:
                raise ContractError("Route change unconfirmed; no replay")
            deadline = time.monotonic() + 10
            while (
                self.inflight[route["environment_id"]] and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            postflight = self.work()
            if (
                self.inflight[route["environment_id"]]
                or not postflight["ok"]
                or postflight["environment"] != target
            ):
                raise ContractError("Postflight or old request drain unverified")
            workflow["status"] = "succeeded"
            workflow["steps"] = [
                {
                    "id": "route",
                    "label": "PG 승인·효과·CAS와 실제 신규 응답 확인",
                    "status": "succeeded",
                    "completed_at": time.time(),
                }
            ]
            workflow["effect_digest"] = result.command.fingerprint
            self.receipts.save(
                self.app,
                operation_id=request.operation_id,
                plan_digest=plan.fingerprint,
                effect_digest=result.command.fingerprint,
                registration_digest=self.revision,
                target=target,
                route_revision=expected_route + 1,
                postflight=postflight,
            )
            self.emit(
                "route_verified",
                target,
                "경로 CAS·기존 요청 배출·신규 견적 계산 응답 확인",
            )
            return {"ok": True, "full_migration_verified": False, "workflow": workflow}
        except Exception:
            if self.operation:
                self.operation["status"] = "needs_attention"
                self.emit(
                    "unverified",
                    target,
                    "효과·현재 경로를 재조회해야 합니다. 자동 재시도하지 않습니다.",
                )
            raise
        finally:
            if self.operation:
                self.workflows.insert(0, self.operation.copy())
                self.workflows = self.workflows[:20]
                self.operation = None
            if lease:
                try:
                    ownership.release(lease)
                except Exception:
                    self.emit(
                        "ownership_unresolved",
                        target,
                        "미해결 효과 또는 실행권 확인 필요",
                    )
            self.action_lock.release()

    def snapshot(self):
        self.require_registration()
        route = self.route()
        with self.lock:
            return {
                "now": time.time(),
                "route": route["environment_id"],
                "route_revision": route["revision"],
                "revision": self.revision,
                "registered_at": self.registration["registered_at"],
                "expires_at": self.expiry.isoformat(),
                "profile": self.registration["profile"],
                "workloads": self.registration["workloads"],
                "observations": dict(self.observations),
                "events": self.events[-100:],
                "workflows": list(self.workflows),
                "operation": self.operation,
                "recovery_required": any(
                    w["status"] == "needs_attention" for w in self.workflows
                ),
                "security": {
                    "state": "held" if self.holds.active_holds(self.app) else "normal",
                    "basis": "owned-stateless-config-not-enterprise-qualified",
                },
                "metrics": {
                    "sample_count": self.total,
                    "success_percent": 100 * self.successes / self.total
                    if self.total
                    else None,
                    "p95_ms": sorted(self.latencies)[
                        max(0, (95 * len(self.latencies) + 99) // 100 - 1)
                    ]
                    if self.latencies
                    else None,
                },
                "requests": list(reversed(self.requests)),
                "scope": "실제 AWS·VM 요청 / EKS → RKE2 무상태 견적 계산 앱. 로컬 고정 진입점·짧은 HTTP 요청. DB·파일·세션·공개 ALB/DNS 이전·HA 자격 없음.",
                "full_migration_verified": False,
            }


def handler(runtime, origin, bridge_secret, cookie):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body, *, issue=False):
            raw = json.dumps(body, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(raw)))
            if issue:
                self.send_header(
                    "Set-Cookie",
                    "sova_preview=" + cookie + "; HttpOnly; SameSite=Strict; Path=/",
                )
            self.end_headers()
            self.wfile.write(raw)

        def authenticated(self):
            try:
                cookies = SimpleCookie(self.headers.get("Cookie", ""))
                return hmac.compare_digest(cookies["sova_preview"].value, cookie)
            except Exception:
                return False

        def do_GET(self):
            if self.headers.get("Host") != origin.removeprefix("http://"):
                return self.reply(403, {"error": "host_denied"})
            try:
                if self.path == "/":
                    allowed = hmac.compare_digest(
                        self.headers.get("X-Sova-Bridge", ""), bridge_secret
                    )
                    return self.reply(
                        200 if allowed else 403,
                        {"profile": "eks-rke2-stateless-v1"},
                        issue=allowed,
                    )
                if self.path == "/quote":
                    result = runtime.work()
                    return self.reply(200 if result["ok"] else 503, result)
                if self.path == "/api/state" and self.authenticated():
                    return self.reply(200, runtime.snapshot())
                return self.reply(404, {"error": "not_found"})
            except Exception:
                return self.reply(409, {"error": "state_unverified"})

        def do_POST(self):
            if (
                not self.authenticated()
                or self.headers.get("Host") != origin.removeprefix("http://")
                or self.headers.get("Origin") != origin
            ):
                return self.reply(403, {"error": "session_or_origin_denied"})
            try:
                self.connection.settimeout(3)
                from sova.adapters.registration.graph_codec import json_document

                length = self.headers.get_all("Content-Length", [])
                if (
                    len(length) != 1
                    or not length[0].isdigit()
                    or not 0 < int(length[0]) <= 2048
                    or self.headers.get("Transfer-Encoding")
                    or self.headers.get_all("Content-Type", []) != ["application/json"]
                ):
                    raise ContractError("Exact bounded request required")
                body = json_document(
                    self.rfile.read(int(length[0])).decode(), limit=2048
                )
                if (
                    self.path == "/api/switch-checked"
                    and type(body) is dict
                    and set(body) == {"environment", "revision", "route_revision"}
                ):
                    return self.reply(
                        200,
                        runtime.switch(
                            body["environment"],
                            body["revision"],
                            body["route_revision"],
                        ),
                    )
                if (
                    self.path == "/api/action"
                    and type(body) is dict
                    and set(body) == {"message", "automatic"}
                    and body["automatic"] is False
                ):
                    return self.reply(200, runtime.work())
                raise ContractError("Unregistered action")
            except Exception:
                with (runtime.root / "action-errors.log").open("a") as log:
                    traceback.print_exc(file=log)
                return self.reply(
                    409, {"error": "action_unverified_no_automatic_retry"}
                )

    return Handler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--port", type=int, default=8790)
    args = parser.parse_args()
    os.umask(0o077)
    runtime = Relocation(args.root)
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    secret = (runtime.root / "bridge-token").read_text().strip()
    if len(secret) < 32:
        raise ContractError("Owner bridge token required")
    origin = "http://127.0.0.1:" + str(args.port)
    server = BoundedLoopbackServer(
        ("127.0.0.1", args.port),
        handler(runtime, origin, secret, secrets.token_urlsafe(32)),
    )
    server.timeout = 0.5
    try:
        while not stopped.is_set() and now() < runtime.expiry:
            server.handle_request()
    finally:
        runtime.stopped.set()
        runtime.thread.join(timeout=10)
        server.server_close()


if __name__ == "__main__":
    main()
