"""Local operator console: real HTTPS requests to a dedicated AWS/VM probe.

This is a preview, not a multi-tenant control plane or a DB migration service.
TLS, resource registration and SSH host identity are checked. Browser input
never specifies addresses, shell commands or cloud resources.
"""

import argparse
import hashlib
import hmac
import http.client
import json
import math
import secrets
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import time
from contextlib import ExitStack, contextmanager
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from security import PreviewIngress

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / ".local-notes/live-preview"

# Keep the existing standalone preview command working before packaging/hosting.
# The domain package itself never imports this server or sibling projects.
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from sova.adapters.preview import PreviewIngressAdapter, PreviewRouteAdapter
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    EffectStatus,
    ExecutionPermit,
    ResourceScope,
    canonical_json,
    identifier,
    public_json,
)
from sova.domain.workflows import validate_step_transition


def run(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
    if p.returncode:
        raise RuntimeError("Registered transport unavailable")
    return p.stdout.strip()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port, process):
    for _ in range(100):
        if process.poll() is not None:
            raise RuntimeError("Owned transport stopped")
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise TimeoutError("Owned transport did not start")


@contextmanager
def transports(config):
    session = boto3.Session(profile_name="default", region_name=config["region"])
    assert session.client("sts").get_caller_identity()["Account"] == config["account"]
    ecs = session.client("ecs")
    task = ecs.describe_tasks(
        cluster=config["cluster"], tasks=[config["task_arn"]], include=["TAGS"]
    )["tasks"][0]
    assert (
        task["lastStatus"] == "RUNNING"
        and task["taskDefinitionArn"] == config["task_definition"]
    )
    assert {v["key"]: v["value"] for v in task["tags"]}.get("sova-preview") == config[
        "run_id"
    ]
    definition = ecs.describe_task_definition(taskDefinition=config["task_definition"])[
        "taskDefinition"
    ]
    assert (
        not definition.get("taskRoleArn")
        and definition["executionRoleArn"] == config["role_arn"]
    )
    assert task["containers"][0]["imageDigest"] == config["image"].split("@", 1)[1]
    assert definition["containerDefinitions"][0]["image"] == config["image"]
    descriptors = [
        json.loads(v) for v in run(["limactl", "list", "--json"]).splitlines()
    ]
    vm = next(v for v in descriptors if v["name"] == "sky-vm")
    target = json.loads(
        run(
            [
                "limactl",
                "shell",
                "sky-vm",
                "--",
                "sudo",
                "docker",
                "inspect",
                config["vm_container"],
            ]
        )
    )[0]
    assert (
        target["State"]["Running"]
        and target["Config"]["Labels"]["sova-preview"] == config["run_id"]
    )
    assert (
        target["Image"] == config["local_image"]
        and target["HostConfig"]["ReadonlyRootfs"]
    )
    ports = target["NetworkSettings"]["Ports"]["8443/tcp"]
    assert len(ports) == 1 and ports[0]["HostIp"] == "127.0.0.1"
    key = run(
        [
            "limactl",
            "shell",
            "sky-vm",
            "--",
            "sudo",
            "cat",
            "/etc/ssh/ssh_host_ed25519_key.pub",
        ]
    ).split()
    expected = key[:2]
    known = STATE / "known_hosts"
    if known.exists() and known.read_text().split()[1:] != expected:
        raise RuntimeError("Registered SSH host key changed")
    known.write_text(f"[127.0.0.1]:{vm['sshLocalPort']} {' '.join(expected)}\n")
    known.chmod(0o600)
    with ExitStack() as stack:
        aws_port, vm_port = free_port(), free_port()
        args = {
            "Target": "i-00b8bcbda73f15616",
            "DocumentName": "AWS-StartPortForwardingSessionToRemoteHost",
            "Parameters": {
                "host": [config["private_ip"]],
                "portNumber": ["8443"],
                "localPortNumber": [str(aws_port)],
            },
        }
        ssm = session.client("ssm")
        reply = ssm.start_session(**args)
        stack.callback(lambda: ssm.terminate_session(SessionId=reply["SessionId"]))
        plugin = (
            (
                ROOT.parent
                / "sky/.local-notes/validation/personal-ssm-schema-20261022/plugin-path.txt"
            )
            .read_text()
            .strip()
        )
        log = stack.enter_context((STATE / "transport.log").open("a"))
        processes = []
        try:
            processes.append(
                subprocess.Popen(
                    [
                        plugin,
                        json.dumps(reply),
                        config["region"],
                        "StartSession",
                        "",
                        json.dumps(args),
                        "https://ssm." + config["region"] + ".amazonaws.com",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=log,
                )
            )
            ssh = [
                "ssh",
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "UserKnownHostsFile=" + str(known),
                "-o",
                "ForwardAgent=no",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ExitOnForwardFailure=yes",
                "-o",
                "ServerAliveInterval=15",
                "-i",
                vm["IdentityFile"],
                "-p",
                str(vm["sshLocalPort"]),
                "-N",
                "-L",
                f"127.0.0.1:{vm_port}:127.0.0.1:{ports[0]['HostPort']}",
                "lima@127.0.0.1",
            ]
            processes.append(
                subprocess.Popen(ssh, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
            )
            for port, process in zip((aws_port, vm_port), processes):
                wait_port(port, process)
            yield {"aws": aws_port, "vm": vm_port}
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


class Console:
    def __init__(
        self,
        config,
        ports,
        *,
        network=None,
        database=None,
        start_collector=True,
        tls_context=None,
    ):
        self.config, self.ports = config, ports
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.db = sqlite3.connect(
            database or STATE / "console.sqlite", check_same_thread=False
        )
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, at REAL, kind TEXT, environment TEXT, detail TEXT)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS route(id INTEGER PRIMARY KEY CHECK(id=1), environment TEXT, revision INTEGER)"
        )
        self.db.execute(
            "INSERT OR IGNORE INTO route(id,environment,revision) VALUES(1, 'aws', 1)"
        )
        if "last_effect_digest" not in {
            row[1] for row in self.db.execute("PRAGMA table_info(route)")
        }:
            self.db.execute("ALTER TABLE route ADD COLUMN last_effect_digest TEXT")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY, at REAL, environment TEXT, elapsed REAL, ok INTEGER, automatic INTEGER)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS workflows(id TEXT PRIMARY KEY, kind TEXT, target TEXT, status TEXT, started REAL, completed REAL, steps TEXT)"
        )
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS security_state(id INTEGER PRIMARY KEY CHECK(id=1), document TEXT)"
        )
        interrupted_security = False
        for identity, kind, raw_steps in self.db.execute(
            "SELECT id,kind,steps FROM workflows WHERE completed IS NULL"
        ).fetchall():
            steps = json.loads(raw_steps)
            for stage in steps:
                if stage["status"] == "running":
                    stage.update(
                        status="needs_attention",
                        evidence={
                            "result": "서버 재시작 · 외부 결과 미확인 · 자동 재실행 없음"
                        },
                    )
                elif stage["status"] == "pending":
                    stage["status"] = "blocked"
            self.db.execute(
                "UPDATE workflows SET status='needs_attention',steps=? WHERE id=?",
                (json.dumps(steps), identity),
            )
            interrupted_security = interrupted_security or kind.startswith("security_")
        self.db.commit()
        self.route, self.route_revision = self.db.execute(
            "SELECT environment,revision FROM route WHERE id=1"
        ).fetchone()
        self.operation = None
        self.network = network or PreviewIngress(config)
        self.effect_journal = SQLiteEffectJournal(self.db, lock=self.lock)
        self.effect_executor = EffectExecutor(
            self.effect_journal,
            authorize=self.authorize_effect,
        )
        self.effect_plan = hashlib.sha256(
            canonical_json(
                {
                    "run_id": config["run_id"],
                    "revision": config["revision"],
                    "account": config["account"],
                    "security_group": config["security_group"],
                    "expires_at": config["expires_at"],
                }
            ).encode()
        ).hexdigest()
        self.ingress_adapter = PreviewIngressAdapter(
            ResourceScope(
                "local-preview",
                config["name"],
                config["run_id"],
                config["security_group"],
            ),
            self.network,
        )
        self.route_adapter = PreviewRouteAdapter(
            ResourceScope(
                "local-preview",
                config["name"],
                config["run_id"],
                "local-gateway",
            ),
            read=self.read_route,
            apply=self.apply_route,
        )
        prior = self.db.execute(
            "SELECT document FROM security_state WHERE id=1"
        ).fetchone()
        self.security = (
            json.loads(prior[0])
            if prior
            else {"state": "normal", "controlled_test": False, "network": None}
        )
        if interrupted_security:
            self.security.update(state="needs_attention", controlled_test=True)
            self.save_security()
        self.last_operation = self.read_workflow()
        self.observations = {}
        self.context = tls_context or ssl.create_default_context(
            cafile=str(STATE / "ca.pem")
        )
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.emit(
            "connected", self.route, "실제 AWS·VM 자원과 TLS 신원 확인 · 무상태 테스트"
        )
        self.thread = threading.Thread(target=self.collect, daemon=True)
        if start_collector:
            self.thread.start()

    def save_security(self):
        with self.lock:
            self.db.execute(
                "INSERT INTO security_state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET document=excluded.document",
                (json.dumps(self.security),),
            )
            self.db.commit()

    def read_workflow(self):
        row = self.db.execute(
            "SELECT id,kind,target,status,started,completed,steps FROM workflows ORDER BY started DESC LIMIT 1"
        ).fetchone()
        return (
            None
            if not row
            else {
                "id": row[0],
                "kind": row[1],
                "target": row[2],
                "status": row[3],
                "started_at": row[4],
                "completed_at": row[5],
                "steps": json.loads(row[6]),
            }
        )

    def workflow_history(self):
        return [
            {
                "id": r[0],
                "kind": r[1],
                "target": r[2],
                "status": r[3],
                "started_at": r[4],
                "completed_at": r[5],
                "steps": json.loads(r[6]),
            }
            for r in self.db.execute(
                "SELECT id,kind,target,status,started,completed,steps FROM workflows ORDER BY started DESC LIMIT 8"
            )
        ]

    def persist_workflow(self, operation):
        with self.lock:
            changed = self.db.execute(
                "INSERT INTO workflows VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,completed=excluded.completed,steps=excluded.steps "
                "WHERE workflows.status='running' AND workflows.completed IS NULL",
                (
                    operation["id"],
                    operation["kind"],
                    operation["target"],
                    operation["status"],
                    operation["started_at"],
                    operation.get("completed_at"),
                    json.dumps(operation["steps"]),
                ),
            ).rowcount
            if changed != 1:
                self.db.rollback()
                raise ContractError("Workflow execution is no longer active")
            self.db.commit()

    def begin_workflow(self, kind, target, steps):
        with self.lock:
            if self.operation:
                raise RuntimeError("다른 실행이 진행 중입니다")
            self.require_active_registration()
            if kind not in {
                "route_switch",
                "security_drill",
                "security_restore",
            } or target not in {"aws", "vm"}:
                raise ContractError("Unregistered preview workflow")
            if (
                not steps
                or len(steps) > 32
                or len({key for key, _ in steps}) != len(steps)
            ):
                raise ContractError("Bounded, unique workflow steps are required")
            for key, label in steps:
                identifier(key, "step_id")
                identifier(label, "step label")
            operation = {
                "id": secrets.token_hex(8),
                "kind": kind,
                "target": target,
                "status": "running",
                "started_at": time.time(),
                "steps": [
                    {"id": key, "label": label, "status": "pending"}
                    for key, label in steps
                ],
            }
            self.persist_workflow(operation)
            self.operation = operation
            return operation

    def step(self, operation, key, function):
        with self.lock:
            if not self.operation or self.operation["id"] != operation["id"]:
                raise ContractError("The workflow does not own this execution")
            stage = next(s for s in operation["steps"] if s["id"] == key)
            validate_step_transition(stage["status"], "running")
            if any(
                s["status"] != "succeeded"
                for s in operation["steps"][: operation["steps"].index(stage)]
            ):
                raise ContractError("Prior verification steps have not succeeded")
            stage.update(status="running", started_at=time.time())
            self.persist_workflow(operation)
        self.emit("stage_running", operation["target"], stage["label"])
        try:
            evidence = function()
            if not isinstance(evidence, dict) or not evidence:
                raise ContractError("A successful step requires nonempty evidence")
        except (
            OSError,
            ValueError,
            RuntimeError,
            sqlite3.Error,
            http.client.HTTPException,
            BotoCoreError,
            ClientError,
        ) as error:
            with self.lock:
                stage.update(
                    status="failed",
                    completed_at=time.time(),
                    evidence={
                        **stage.get("evidence", {}),
                        "result": "미확인 또는 실패 · 외부 변경 재실행 없음",
                        "error_type": type(error).__name__,
                    },
                )
                self.persist_workflow(operation)
            raise
        with self.lock:
            stage.update(
                status="succeeded", completed_at=time.time(), evidence=evidence
            )
            self.persist_workflow(operation)
        self.emit(
            "stage_succeeded", operation["target"], stage["label"] + " · 실제 결과 확인"
        )
        return evidence

    def finish_workflow(self, operation, succeeded):
        with self.lock:
            succeeded = succeeded and all(
                s["status"] == "succeeded" for s in operation["steps"]
            )
            operation.update(
                status="succeeded" if succeeded else "needs_attention",
                completed_at=time.time(),
            )
            if not succeeded:
                for step in operation["steps"]:
                    if step["status"] == "pending":
                        step["status"] = "blocked"
            try:
                self.persist_workflow(operation)
            except ContractError:
                # A restart/other controller already terminated this record.
                # Preserve its state; an old in-memory object must not revive it.
                self.last_operation = self.read_workflow()
            else:
                self.last_operation = json.loads(json.dumps(operation))
            self.operation = None

    def read_route(self):
        with self.lock:
            environment, revision, marker = self.db.execute(
                "SELECT environment,revision,last_effect_digest FROM route WHERE id=1"
            ).fetchone()
            return {
                "environment": environment,
                "revision": revision,
                "last_effect_digest": marker,
            }

    def apply_route(self, side, expected_revision, effect_digest):
        with self.lock:
            self.db.execute(
                "UPDATE route SET environment=?,revision=revision+1,last_effect_digest=? WHERE id=1 AND revision=?",
                (side, effect_digest, expected_revision),
            )
            if self.db.execute("SELECT changes()").fetchone()[0] != 1:
                self.db.rollback()
                raise RuntimeError("Gateway revision conflict")
            self.db.commit()
            self.route, self.route_revision = self.db.execute(
                "SELECT environment,revision FROM route WHERE id=1"
            ).fetchone()

    def authorize_effect(self, command, permit, now, mutation):
        with self.lock:
            self.require_active_registration()
            operation = self.operation
            if not operation or command.plan_digest != self.effect_plan:
                raise ContractError("No active registered preview execution")
            row = self.db.execute(
                "SELECT rowid,status,completed FROM workflows WHERE id=?",
                (command.operation_id,),
            ).fetchone()
            if not row or row[0] != command.fencing_epoch:
                raise ContractError("Preview execution epoch changed")
            if mutation:
                if row[1] != "running" or row[2] is not None:
                    raise ContractError("Workflow execution is no longer active")
                if operation["id"] != command.operation_id:
                    raise ContractError("Another workflow owns the preview")
                stage = next(
                    (s for s in operation["steps"] if s["id"] == command.step_id), None
                )
                if not stage or stage["status"] != "running":
                    raise ContractError("Effect is outside its running step")
                if command.action == "set_route":
                    if (
                        command.step_id != "route"
                        or operation["kind"] not in {"route_switch", "security_drill"}
                        or command.parameters["environment"] != operation["target"]
                    ):
                        raise ContractError(
                            "Route effect does not match the workflow target"
                        )
                if command.action == "set_ingress":
                    expected_kind = (
                        "security_drill"
                        if command.parameters["blocked"]
                        else "security_restore"
                    )
                    if operation["kind"] != expected_kind or not self.security.get(
                        "controlled_test"
                    ):
                        raise ContractError(
                            "Ingress change is outside a controlled test"
                        )
                    expected_step = (
                        "isolate" if command.parameters["blocked"] else "restore"
                    )
                    if (
                        command.step_id != expected_step
                        or command.expected_revision != self.config["revision"]
                    ):
                        raise ContractError("Ingress step or source revision changed")
                if (
                    command.action == "set_route"
                    and command.parameters["environment"] == "aws"
                    and self.security["state"] != "normal"
                ):
                    raise ContractError("AWS is under a security hold")
            elif operation["kind"] != "security_restore":
                raise ContractError(
                    "Only explicit test restoration may reconcile old effects"
                )
            elif row[1] == "running" or row[2] is None:
                raise ContractError(
                    "Prior preview executor has not confirmed termination"
                )

    @staticmethod
    def effect_permit(command):
        return ExecutionPermit(
            command.scope,
            command.operation_id,
            command.plan_digest,
            command.fingerprint,
            command.fencing_epoch,
            command.expires_at,
        )

    def run_effect(
        self, operation, key, adapter, action, parameters, expected_revision
    ):
        with self.lock:
            epoch = self.db.execute(
                "SELECT rowid FROM workflows WHERE id=?", (operation["id"],)
            ).fetchone()[0]
            command = EffectCommand(
                adapter.scope,
                operation["id"],
                key,
                adapter.adapter_id,
                action,
                operation["id"] + ":" + key,
                self.effect_plan,
                str(expected_revision),
                epoch,
                datetime.fromisoformat(self.config["expires_at"]),
                canonical_json(parameters),
            )
        result = self.effect_executor.execute(
            command, self.effect_permit(command), adapter
        )
        return {
            **result.observation.evidence,
            "effect_digest": command.fingerprint,
            "effect_status": str(result.status),
            "effect_record_revision": result.revision,
        }

    def reconcile_ingress(self):
        observed = self.network.read()
        records = []
        for pending in self.effect_journal.unresolved(self.ingress_adapter.scope):
            command = pending.command
            if pending.status == EffectStatus.PREPARED:
                result = self.effect_executor.cancel_prepared(
                    command, self.effect_permit(command), self.ingress_adapter
                )
            else:
                result = self.effect_executor.reconcile(
                    command, self.effect_permit(command), self.ingress_adapter
                )
            records.append(
                {"effect_digest": command.fingerprint, "status": str(result.status)}
            )
            if result.status not in (EffectStatus.APPLIED, EffectStatus.NOT_APPLIED):
                raise RuntimeError(
                    "Prior ingress effect remains unknown; no new mutation"
                )
        return {**observed, "prior_effect_readbacks": records}

    def route_to(self, side):
        with self.lock:
            previous = self.route
            operation = self.operation
            expected_revision = self.route_revision
            if not operation:
                raise ContractError("A route change requires an active workflow")
        result = self.run_effect(
            operation,
            "route",
            self.route_adapter,
            "set_route",
            {"environment": side},
            expected_revision,
        )
        return {"previous": previous, **result}

    def verify_response(self, side):
        receipt, latency = self.remote(
            side, request_id=secrets.token_hex(16), message="workflow-readiness-check"
        )
        return {
            "environment": receipt["environment"],
            "instance": receipt["instance"],
            "revision": receipt["revision"],
            "request_id": receipt["request_id"],
            "latency_ms": latency,
            "tls_hostname_verified": True,
        }

    def verify_active(self, side):
        result = self.action("post-switch-verification", automatic=True)
        if not result["ok"] or result["environment"] != side:
            raise RuntimeError("Active request not verified")
        return {
            k: result[k]
            for k in ("request_id", "environment", "latency_ms", "route_revision")
        }

    def verify_restored(self, operation, *, attempts=4, pause=0.5):
        """Retry only read-only HTTPS readiness, never the rule mutation or POST.

        SG control-plane readback can precede usable data-plane connectivity.
        Certificate/identity mismatches remain terminal failures.
        """
        checks = []
        for attempt in range(1, attempts + 1):
            try:
                self.remote("aws")
            except ssl.SSLCertVerificationError:
                raise
            except (
                TimeoutError,
                ConnectionError,
                http.client.RemoteDisconnected,
            ) as error:
                checks.append(
                    {
                        "attempt": attempt,
                        "at": time.time(),
                        "result": "transport_not_ready",
                        "error_type": type(error).__name__,
                    }
                )
                with self.lock:
                    stage = next(s for s in operation["steps"] if s["id"] == "verify")
                    stage["evidence"] = {
                        "result": "수신 규칙 복원됨 · 읽기 전용 HTTPS 준비 확인 중",
                        "connection_checks": checks.copy(),
                        "rule_change_repeated": False,
                    }
                    self.persist_workflow(operation)
                self.emit(
                    "readiness_wait",
                    "aws",
                    f"HTTPS 연결 준비 대기 {attempt}/{attempts} · 규칙 변경 재실행 없음",
                )
                if attempt == attempts:
                    raise RuntimeError(
                        "Restored HTTPS remained unavailable within bounded checks"
                    ) from error
                if self.stop.wait(pause):
                    raise RuntimeError("Verification interrupted")
                continue
            checks.append(
                {
                    "attempt": attempt,
                    "at": time.time(),
                    "result": "https_identity_verified",
                }
            )
            # Exactly one application POST after read-only readiness succeeds.
            result = self.verify_response("aws")
            return {
                **result,
                "connection_checks": checks,
                "rule_change_repeated": False,
            }
        raise RuntimeError("No readiness observation")

    def controlled_denial(self):
        """A fixed synthetic request, no real Secret lookup or exploit payload."""
        c = http.client.HTTPSConnection("aws.sova.test", self.ports["aws"], timeout=4)
        raw = socket.create_connection(("127.0.0.1", self.ports["aws"]), timeout=4)
        try:
            c.sock = self.context.wrap_socket(raw, server_hostname="aws.sova.test")
            c.request("GET", "/admin/export-secrets", headers={"Connection": "close"})
            response = c.getresponse()
            body = response.read(1025)
            if (
                response.status != 404
                or len(body) > 1024
                or json.loads(body) != {"error": "not_found"}
                or response.getheader("X-Sova-Environment") != "aws"
            ):
                raise ValueError("Controlled rejection was not verified")
            return {
                "type": "controlled_security_test",
                "request": "GET /admin/export-secrets",
                "status_code": 404,
                "tls_hostname_verified": True,
                "meaning": "미등록 관리 경로 거부 확인 · 실제 침해 탐지 아님",
            }
        finally:
            c.close()
            raw.close()

    def verify_network_block(self):
        observed = self.network.read()
        if not observed["blocked"]:
            raise RuntimeError("Ingress still open")
        try:
            self.remote("aws")
        except (TimeoutError, ConnectionRefusedError):
            self.security.update(
                state="isolated",
                network={**observed, "observed_at": time.time()},
                probe_blocked=True,
            )
            self.save_security()
            return {
                **observed,
                "new_https_connection_blocked": True,
                "container_deleted": False,
                "physical_location": "AWS 유지",
            }
        raise RuntimeError("HTTPS still reachable; do not declare isolation")

    def security_action(self, action):
        if action == "drill":
            if self.security["state"] != "normal":
                raise ValueError("이전 시험을 복구한 뒤 실행하세요")
            steps = [
                ("scope", "등록·권한 확인"),
                ("signal", "통제된 시험 요청"),
                ("standby", "VM 대기본 검증"),
                ("isolate", "AWS 유입 차단"),
                ("blocked", "실제 연결 거부 확인"),
                ("route", "VM 경로 적용"),
                ("verify", "VM 응답 확인"),
            ]
        else:
            if not self.security.get("controlled_test") or self.security[
                "state"
            ] not in {"isolated", "needs_attention"}:
                raise ValueError("복구할 통제 시험이 없습니다")
            steps = [
                ("scope", "등록·격리 상태 확인"),
                ("restore", "시험 유입 규칙 복원"),
                ("verify", "AWS HTTPS 재검증"),
            ]
        operation = self.begin_workflow(
            "security_drill" if action == "drill" else "security_restore",
            "vm" if action == "drill" else "aws",
            steps,
        )
        threading.Thread(
            target=self.execute_security, args=(operation, action), daemon=True
        ).start()
        return json.loads(json.dumps(operation))

    def execute_security(self, operation, action):
        succeeded = False
        try:
            self.step(
                operation,
                "scope",
                self.reconcile_ingress if action == "restore" else self.network.read,
            )
            if action == "drill":
                self.security.update(
                    state="investigating",
                    controlled_test=True,
                    incident_id=operation["id"],
                    probe_blocked=False,
                )
                self.save_security()
                self.step(operation, "signal", self.controlled_denial)
                self.step(operation, "standby", lambda: self.verify_response("vm"))
                self.security.update(state="isolating")
                self.save_security()

                def isolate():
                    result = self.run_effect(
                        operation,
                        "isolate",
                        self.ingress_adapter,
                        "set_ingress",
                        {"blocked": True},
                        self.config["revision"],
                    )
                    self.security.update(network={**result, "observed_at": time.time()})
                    self.save_security()
                    return result

                self.step(operation, "isolate", isolate)
                self.step(operation, "blocked", self.verify_network_block)
                self.step(operation, "route", lambda: self.route_to("vm"))
                self.step(operation, "verify", lambda: self.verify_active("vm"))
                self.emit(
                    "security_isolated",
                    "aws",
                    "통제 시험 완료 · AWS TCP8443 유입 차단 · 태스크는 보존 · VM 서비스 확인",
                )
            else:

                def restore():
                    result = self.run_effect(
                        operation,
                        "restore",
                        self.ingress_adapter,
                        "set_ingress",
                        {"blocked": False},
                        self.config["revision"],
                    )
                    self.security.update(network={**result, "observed_at": time.time()})
                    self.save_security()
                    return result

                self.step(operation, "restore", restore)
                self.step(operation, "verify", lambda: self.verify_restored(operation))
                self.security.update(
                    state="normal", controlled_test=False, probe_blocked=False
                )
                self.save_security()
                self.emit(
                    "security_restored",
                    "aws",
                    "통제 시험의 원래 유입만 복원 · AWS는 대기 · 실제 침해 사고의 보류 해제 기능 아님",
                )
            succeeded = True
        except (
            OSError,
            ValueError,
            RuntimeError,
            sqlite3.Error,
            http.client.HTTPException,
            BotoCoreError,
            ClientError,
        ):
            self.security.update(state="needs_attention")
            self.save_security()
            self.emit(
                "attention", "aws", "보안 시험 결과 조정 필요 · 자동 복구·재실행 없음"
            )
        finally:
            self.finish_workflow(operation, succeeded)

    def emit(self, kind, environment, detail):
        with self.lock:
            self.db.execute(
                "INSERT INTO events(at,kind,environment,detail) VALUES(?,?,?,?)",
                (time.time(), kind, environment, detail),
            )
            self.db.commit()

    def remote(self, environment, *, request_id=None, message=None):
        name = environment + ".sova.test"
        c = http.client.HTTPSConnection(name, self.ports[environment], timeout=4)
        raw = socket.create_connection(
            ("127.0.0.1", self.ports[environment]), timeout=4
        )
        started = time.perf_counter()
        try:
            c.sock = self.context.wrap_socket(raw, server_hostname=name)
            body = (
                None
                if request_id is None
                else json.dumps({"request_id": request_id, "message": message}).encode()
            )
            c.request(
                "GET" if body is None else "POST",
                "/health" if body is None else "/action",
                body=body,
                headers={"Connection": "close", "Content-Type": "application/json"},
            )
            response = c.getresponse()
            data = response.read(2049)
            if response.status != 200 or len(data) > 2048:
                raise ValueError("Probe unavailable")
            receipt = json.loads(data)
            for key, value in {
                "environment": environment,
                "revision": self.config["revision"],
                "run_id": self.config["run_id"],
                "instance": self.config["name"] + "-" + environment,
            }.items():
                if receipt.get(key) != value:
                    raise ValueError("Probe identity changed")
            if request_id is not None and (
                receipt.get("request_id") != request_id
                or receipt.get("message") != message
                or receipt.get("message_sha256")
                != hashlib.sha256(message.encode()).hexdigest()
            ):
                raise ValueError("Request receipt differs")
            return receipt, round((time.perf_counter() - started) * 1000, 1)
        finally:
            c.close()
            raw.close()

    def collect(self):
        network_checked = 0
        while not self.stop.is_set():
            if time.monotonic() - network_checked > 10:
                try:
                    observed = self.network.read()
                    with self.lock:
                        if not self.operation:
                            self.security["network"] = {
                                **observed,
                                "observed_at": time.time(),
                            }
                            self.save_security()
                except (
                    OSError,
                    ValueError,
                    KeyError,
                    RuntimeError,
                    BotoCoreError,
                    ClientError,
                ):
                    with self.lock:
                        if not self.operation:
                            self.security["network"] = None
                network_checked = time.monotonic()
            for side in ("aws", "vm"):
                try:
                    receipt, latency = self.remote(side)
                    value = {
                        "available": True,
                        "observed_at": time.time(),
                        "latency_ms": latency,
                        "instance": receipt["instance"],
                    }
                except (OSError, ValueError, http.client.HTTPException):
                    value = {
                        "available": False,
                        "observed_at": time.time(),
                        "error": "응답 또는 TLS/등록 신원 확인 실패",
                    }
                with self.lock:
                    self.observations[side] = value
            self.stop.wait(2)

    def require_active_registration(self):
        if datetime.now(UTC) >= datetime.fromisoformat(self.config["expires_at"]):
            raise ValueError("테스트 실행 시간이 만료됐습니다")

    def action(self, message, automatic=False):
        self.require_active_registration()
        request_id = secrets.token_hex(16)
        with self.lock:
            side, revision = self.route, self.route_revision
        started = time.perf_counter()
        try:
            receipt, latency = self.remote(side, request_id=request_id, message=message)
            ok = True
        except (OSError, ValueError, http.client.HTTPException):
            receipt, latency, ok = (
                {},
                round((time.perf_counter() - started) * 1000, 1),
                False,
            )
        with self.lock:
            self.db.execute(
                "INSERT INTO requests VALUES(?,?,?,?,?,?)",
                (request_id, time.time(), side, latency, int(ok), int(automatic)),
            )
            self.db.commit()
        self.emit(
            "request" if ok else "request_failed",
            side,
            ("테스트 요청 " if automatic else "직접 보낸 요청 ")
            + request_id[:8]
            + (" · HTTPS 응답 검증" if ok else " · 응답 미확인, 재실행하지 않음"),
        )
        return {
            "request_id": request_id,
            "environment": side,
            "route_revision": revision,
            "latency_ms": latency,
            "ok": ok,
            "receipt": receipt,
        }

    def switch(self, side, *, expected_revision=None, expected_route_revision=None):
        with self.lock:
            if expected_revision is not None and (
                expected_revision != self.config["revision"]
                or expected_route_revision != self.route_revision
            ):
                raise ValueError("승인 후 실행본 또는 경로가 변경됐습니다")
            if side == self.route:
                raise ValueError("이미 요청을 처리하는 환경입니다")
            if side == "aws" and self.security["state"] != "normal":
                raise ValueError("시험 격리를 명시적으로 해제한 뒤 AWS로 복귀하세요")
            operation = self.begin_workflow(
                "route_switch",
                side,
                [
                    ("standby", "목적지 실행본 확인"),
                    ("probe", "실제 요청 리허설"),
                    ("route", "경로 적용·재조회"),
                    ("verify", "새 응답 검증"),
                ],
            )
        threading.Thread(
            target=self.execute_switch, args=(operation,), daemon=True
        ).start()
        return json.loads(json.dumps(operation))

    def execute_switch(self, operation):
        side = operation["target"]
        succeeded = False
        try:
            self.step(operation, "standby", lambda: self.verify_response(side))
            self.step(operation, "probe", lambda: self.verify_response(side))
            self.step(operation, "route", lambda: self.route_to(side))
            self.step(operation, "verify", lambda: self.verify_active(side))
            self.emit(
                "verified", side, "새 경로의 실제 요청 응답 확인 · 데이터 이전 없음"
            )
            succeeded = True
        except (
            OSError,
            ValueError,
            RuntimeError,
            sqlite3.Error,
            http.client.HTTPException,
        ):
            self.emit(
                "attention",
                side,
                "전환 검증 실패 · 실제 경로 확인 필요, 자동 재시도 없음",
            )
        finally:
            self.finish_workflow(operation, succeeded)

    def snapshot(self):
        with self.lock:
            now = time.time()
            events = [
                {
                    "seq": r[0],
                    "at": r[1],
                    "kind": r[2],
                    "environment": r[3],
                    "detail": r[4],
                }
                for r in self.db.execute(
                    "SELECT * FROM events ORDER BY seq DESC LIMIT 60"
                )
            ][::-1]
            requests = [
                {
                    "id": r[0],
                    "at": r[1],
                    "environment": r[2],
                    "latency_ms": r[3],
                    "ok": bool(r[4]),
                    "automatic": bool(r[5]),
                }
                for r in self.db.execute(
                    "SELECT * FROM requests ORDER BY at DESC LIMIT 100"
                )
            ]
            window = self.db.execute(
                "SELECT elapsed,ok FROM requests WHERE at>=? ORDER BY elapsed",
                (now - 60,),
            ).fetchall()
            observations = {
                k: {**v, "stale": now - v["observed_at"] > 8}
                for k, v in self.observations.items()
            }
            return {
                "now": now,
                "route": self.route,
                "route_revision": self.route_revision,
                "observations": observations,
                "operation": json.loads(json.dumps(self.operation)),
                "last_operation": getattr(self, "last_operation", None),
                "workflows": self.workflow_history(),
                "security": json.loads(json.dumps(self.security)),
                "workloads": {
                    side: {
                        "instance": self.config["name"] + "-" + side,
                        "revision": self.config["revision"],
                        "runtime": "Fargate ARM64"
                        if side == "aws"
                        else "Lima Linux / Docker ARM64",
                        "components": [
                            {"id": "tls", "label": "TLS 수신"},
                            {"id": "handler", "label": "HTTP 핸들러"},
                            {"id": "reply", "label": "응답 생성"},
                        ],
                        "boundary": "동일 컨테이너 내부 · 독립 마이크로서비스 아님",
                        "nonroot": True,
                        "readonly_root": True,
                        "database": False,
                    }
                    for side in ("aws", "vm")
                },
                "events": events,
                "requests": requests,
                "revision": self.config["revision"],
                "expires_at": self.config["expires_at"],
                "registered_at": self.config.get("created_at"),
                "metrics": {
                    "sample_count": len(window),
                    "rps": round(sum(r["at"] >= now - 5 for r in requests) / 5, 2),
                    "success_percent": round(
                        sum(v[1] for v in window) / len(window) * 100, 1
                    )
                    if window
                    else None,
                    "p95_ms": window[max(0, math.ceil(0.95 * len(window)) - 1)][0]
                    if window
                    else None,
                },
                "scope": "실제 AWS·VM 요청 / 통제 시험과 AWS 전용 유입 격리 / DB 이전·실제 침해 탐지 없음",
            }


def handler(console, origin, token):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, data, content_type="application/json", cookie=False):
            raw = (
                data
                if isinstance(data, bytes)
                else json.dumps(data, ensure_ascii=False).encode()
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            if cookie:
                self.send_header(
                    "Set-Cookie",
                    "sova_preview=" + token + "; HttpOnly; SameSite=Strict; Path=/",
                )
            self.end_headers()
            self.wfile.write(raw)

        def trusted(self):
            return self.headers.get("Host") == urlsplit(origin).netloc

        def authenticated(self):
            from http.cookies import CookieError, SimpleCookie

            try:
                cookie = SimpleCookie(self.headers.get("Cookie", ""))
                value = cookie.get("sova_preview")
                return bool(value and hmac.compare_digest(value.value, token))
            except (CookieError, TypeError, ValueError):
                return False

        def do_GET(self):
            if not self.trusted():
                return self.reply(403, {"error": "host_denied"})
            path = urlsplit(self.path).path
            if path in {"/", "/app.js", "/style.css", "/pipeline.css"}:
                name, kind = {
                    "/": ("index.html", "text/html; charset=utf-8"),
                    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                    "/style.css": ("style.css", "text/css; charset=utf-8"),
                    "/pipeline.css": ("pipeline.css", "text/css; charset=utf-8"),
                }[path]
                return self.reply(
                    200,
                    (ROOT / "demo/web" / name).read_bytes(),
                    kind,
                    cookie=path == "/",
                )
            if path == "/api/state" and self.authenticated():
                return self.reply(200, console.snapshot())
            self.reply(404, {"error": "not_found"})

        def do_POST(self):
            if (
                not self.trusted()
                or not self.authenticated()
                or self.headers.get("Origin") != origin
            ):
                return self.reply(403, {"error": "origin_or_session_denied"})
            try:
                self.connection.settimeout(4)
                size = int(self.headers.get("Content-Length", "0"))
                if (
                    self.headers.get("Transfer-Encoding")
                    or not 0 < size <= 512
                    or self.headers.get("Content-Type") != "application/json"
                ):
                    raise ValueError("bounded_json_required")
                body = public_json(self.rfile.read(size).decode("utf-8"))
                if (
                    self.path == "/api/action"
                    and isinstance(body, dict)
                    and set(body) == {"message", "automatic"}
                    and isinstance(body["message"], str)
                    and len(body["message"]) <= 80
                    and type(body["automatic"]) is bool
                ):
                    result = console.action(body["message"], body["automatic"])
                    return self.reply(200 if result["ok"] else 502, result)
                if (
                    self.path == "/api/switch-checked"
                    and isinstance(body, dict)
                    and set(body) == {"environment", "revision", "route_revision"}
                    and type(body["environment"]) is str
                    and body["environment"] in {"aws", "vm"}
                    and type(body["revision"]) is str
                    and type(body["route_revision"]) is int
                ):
                    return self.reply(
                        202,
                        console.switch(
                            body["environment"],
                            expected_revision=body["revision"],
                            expected_route_revision=body["route_revision"],
                        ),
                    )
                if (
                    self.path == "/api/switch"
                    and isinstance(body, dict)
                    and set(body) == {"environment"}
                    and type(body["environment"]) is str
                    and body["environment"] in {"aws", "vm"}
                ):
                    return self.reply(202, console.switch(body["environment"]))
                if (
                    self.path == "/api/security-test"
                    and isinstance(body, dict)
                    and set(body) == {"action", "confirm"}
                    and type(body["action"]) is str
                    and body["action"] in {"drill", "restore"}
                    and body["confirm"] is True
                ):
                    return self.reply(202, console.security_action(body["action"]))
                raise ValueError("invalid_request")
            except ValueError as error:
                return self.reply(400, {"error": str(error)[:100]})
            except RuntimeError:
                return self.reply(409, {"error": "전환 작업 충돌"})

    return Handler


def main():
    global STATE
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8790)
    parser.add_argument(
        "--state-root", type=Path, help="Separate private registration directory"
    )
    args = parser.parse_args()
    if args.state_root:
        selected = args.state_root.resolve()
        if not selected.is_relative_to((ROOT / ".local-notes").resolve()):
            parser.error("state root must be within private local notes")
        STATE = selected
    config = json.loads((STATE / "resources.json").read_text())
    if datetime.now(UTC) >= datetime.fromisoformat(config["expires_at"]):
        raise RuntimeError("Preview registration expired; no implicit renewal")
    with transports(config) as ports:
        console = Console(config, ports)
        origin = f"http://127.0.0.1:{args.port}"
        server = ThreadingHTTPServer(
            ("127.0.0.1", args.port),
            handler(console, origin, secrets.token_urlsafe(32)),
        )
        server.daemon_threads = True
        (STATE / "server.pid").write_text(str(__import__("os").getpid()))

        def stop(*_args):
            threading.Thread(target=server.shutdown, daemon=True).start()

        signal.signal(signal.SIGTERM, stop)
        print("Sova live preview: " + origin, flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            console.stop.set()
            console.thread.join(timeout=10)
            server.server_close()


if __name__ == "__main__":
    main()
