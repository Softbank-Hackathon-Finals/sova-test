"""Local operator qualification console: real k3s, PG, probes, guarded response.

This is not enterprise authentication, remote cloud migration or Harbor. Start
only with an owner-private registration of this session's dedicated test cluster.
"""

from __future__ import annotations
import argparse
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
from http.cookies import SimpleCookie, CookieError
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
from urllib.parse import urlsplit, parse_qs
from operator_auth import OperatorAuth, write_bootstrap_file
from bounded_http import BoundedLoopbackServer
from console_web import ConsoleWebBundle
from dependency_bridge import DependencyBridge
from migration_bridge import MigrationBridge

ROOT = Path(__file__).resolve().parent
if str(ROOT.parent / "src") not in sys.path:
    sys.path.insert(0, str(ROOT.parent / "src"))
import psycopg
from kubernetes_response import OwnedKubernetesResponse, IndependentPodProbe
from sova.adapters.kubernetes.https import private_text, KubernetesHTTPS
from sova.adapters.kubernetes.registration import decode_registration
from sova.adapters.registration.graph_codec import json_document
from sova.adapters.kubernetes.posture import posture_projection
from sova.adapters.postgres_security_events import PostgresSecurityObservations
from sova.adapters.postgres_security_routes import PostgresSecurityRoutes
from sova.adapters.postgres_governance import PostgresSecurityHolds
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.application.kubernetes_discovery import KubernetesDiscovery
from sova.application.security_collection import SecurityCollector
from sova.application.security_response import SecurityResponseGuard
from sova.application.security_response_runner import SecurityResponseRunner
from sova.application.protection_projection import compare_configuration
from sova.domain.security_response import (
    StatelessResponseProfile,
    SecurityResponseBinding,
)
from sova.domain.plans import PlanApproval
from sova.domain.operations import OperationRequest
from sova.domain.evidence import EvidenceRecord, VerificationResult
from sova.domain.security_events import SecurityEvent, SecurityEventKind
from sova.domain.contracts import ContractError, canonical_json
from sova.ports.plans import RecordNotFound


def now():
    return datetime.now(UTC)


class SecurityConsole:
    def __init__(self, session_root):
        self.root = Path(session_root).resolve()
        self.session = json_document(private_text(self.root / "session.json"))
        self.deadline = datetime.fromisoformat(self.session["deadline"])
        if not now() < self.deadline <= now() + timedelta(hours=12):
            raise ContractError("Live bounded operator session required")
        self.db = json_document(private_text(self.root / "control-db.json"))
        self.clean = json.loads((self.root / "clean-target-proof.json").read_text())
        self.registrations = {
            env: decode_registration(
                json_document(private_text(self.root / (env + "-registration.json")))
            )
            for env in ("blue", "green")
        }
        blue = self.registrations["blue"]
        green = self.registrations["green"]
        if (blue.tenant_id, blue.application_id) != (
            green.tenant_id,
            green.application_id,
        ):
            raise ContractError("Registered application mismatch")
        self.tenant = blue.tenant_id
        self.app = blue.application_id
        self.operator = "local-os-user:" + str(os.geteuid())
        self.collector_id = "registered-local-security-collector"
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.busy = False
        self.action_thread = None
        self.phase = "observing"
        self.error = None
        self.prepared = None
        self.operation = None
        self.steps = []
        self.probe_results = {}
        self.collector_errors = {}
        self.last_collected = 0
        self.last_isolation_check = 0
        self.isolation_proof = None
        self.probe = IndependentPodProbe(
            json.loads((self.root / "probe-forward.json").read_text())["port"],
            application_id=self.app,
        )
        self.recorder = lambda: psycopg.connect(self.db["recorder_dsn"])
        self.viewer = lambda: psycopg.connect(self.db["viewer_dsn"])
        self.worker_connect = lambda: psycopg.connect(self.db["worker_dsn"])
        self.admitter_connect = lambda: psycopg.connect(self.db["admitter_dsn"])
        self.observations = PostgresSecurityObservations(
            self.recorder, tenant_id=self.tenant
        )
        self.read_observations = PostgresSecurityObservations(
            self.viewer, tenant_id=self.tenant
        )
        self.holds = PostgresSecurityHolds(self.recorder, tenant_id=self.tenant)
        self.read_holds = PostgresSecurityHolds(self.viewer, tenant_id=self.tenant)
        self.routes = PostgresSecurityRoutes(self.worker_connect, tenant_id=self.tenant)
        self.routes.register(self.app, "test-entry", blue.environment_id)
        self.collectors = {}
        for env, reg in self.registrations.items():

            def token(env=env):
                return private_text(self.root / (env + "-token"), limit=16384).strip()

            transport = KubernetesHTTPS(
                reg, ca_pem=(self.root / "ca.pem").read_bytes(), token_provider=token
            )

            def authorize(actor, scope, action, env=env):
                fresh = decode_registration(
                    json_document(
                        private_text(self.root / (env + "-registration.json"))
                    )
                )
                if (
                    actor != self.collector_id
                    or fresh.fingerprint != scope.fingerprint
                    or action != "inventory:read"
                ):
                    raise ContractError("Scoped collection not authorized")

            reader = KubernetesDiscovery(
                reg,
                transport,
                authorize=authorize,
                clock=now,
                projection=posture_projection,
            )
            self.collectors[env] = SecurityCollector(
                self.observations,
                self.holds,
                collect=lambda reader=reader: reader.inspect(actor=self.collector_id),
                authorize=self.authorize_record,
                actor_id=self.collector_id,
                blocking_controls=frozenset(
                    {"read-only-root", "no-privileged", "no-host-mounts"}
                ),
                clock=now,
            )
        self.collect()
        self.recover_read_only()
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def recover_read_only(self):
        reference = self.root / "prepared-reference.json"
        if not reference.exists():
            return
        try:
            data = json_document(private_text(reference))
            lifecycle = PostgresLifecycleRepository(
                self.worker_connect, tenant_id=self.tenant
            )
            plan = lifecycle.get_plan(self.app, data["plan_id"])
            operations = PostgresOperationRepository(lifecycle)
            operation = operations.get(self.app, data["operation_id"])
            if operation.request.plan_digest != plan.fingerprint:
                raise ContractError("Recovered operation binding mismatch")
            completion = None
            if operation.state.status.value == "response_verified":
                try:
                    _, completion = operations.get_response_completion(
                        self.app, operation.request.operation_id
                    )
                except RecordNotFound:
                    # A legacy status is history, not a newly qualified receipt.
                    pass
            parameters = plan.steps[0].parameters_json
            parameters = json.loads(parameters)
            source = self.read_observations.get_snapshot(
                self.app, parameters["source_snapshot"]
            )
            target = self.read_observations.get_snapshot(
                self.app, parameters["target_snapshot"]
            )
            profile = StatelessResponseProfile(
                "owned-local-stateless-test",
                self.clean["image"].split("@sha256:")[1],
                self.clean["configuration_digest"],
                True,
                True,
                True,
                self.operator,
                self.deadline,
            )
            binding = SecurityResponseBinding(
                source,
                target,
                parameters["source_node"],
                parameters["target_node"],
                tuple(parameters["hold_ids"]),
                profile,
                parameters["policy_digest"],
            )
            if binding.document != parameters:
                raise ContractError("Recovered response profile mismatch")
            adapter = OwnedKubernetesResponse(
                kubeconfig=self.root / "admin-kubeconfig.json",
                binding=binding,
                source_namespace_uid=self.registrations["blue"].namespace_uid,
                target_namespace_uid=self.registrations["green"].namespace_uid,
                probe_port=self.probe.probe_port,
                routes=self.routes,
            )
            with lifecycle.transaction() as conn:
                receipts = conn.execute(
                    "SELECT command_document,fingerprint,status,observation_document FROM sova_control.effects WHERE tenant_id=%s AND application_id=%s AND operation_id=%s",
                    (self.tenant, self.app, operation.request.operation_id),
                ).fetchall()
            from sova.domain.contracts import EffectCommand

            verified = {}
            for document, fingerprint, status, observation in receipts:
                command = EffectCommand.from_document(document)
                expected = plan.command(
                    command.step_id,
                    operation_id=operation.request.operation_id,
                    epoch=command.fencing_epoch,
                )
                if (
                    command.fingerprint != fingerprint
                    or command.fingerprint != expected.fingerprint
                    or (
                        completion is not None
                        and command.fencing_epoch != completion.command.fencing_epoch
                    )
                ):
                    raise ContractError("Recovered effect receipt mismatch")
                if status == "confirmed_applied":
                    verified[command.step_id] = {
                        "action": command.action,
                        "status": status,
                        "at": observation["observed_at"],
                        "effect_digest": fingerprint,
                        "historical": True,
                    }
            if completion is not None and set(verified) != {
                step.step_id for step in plan.steps
            }:
                raise ContractError("Completed response has incomplete effect history")
            self.steps = [
                verified[step.step_id]
                for step in plan.steps
                if step.step_id in verified
            ]
            self.prepared = {
                "binding": binding,
                "plan": plan,
                "adapter": adapter,
                "evidence": (),
                "read_only_recovered": True,
            }
            self.operation = {
                "operation_id": operation.request.operation_id,
                "status": str(operation.state.status),
                "revision": operation.state.revision,
                "plan_digest": plan.fingerprint,
                "read_only_recovered": True,
                "completion_digest": completion.fingerprint if completion else None,
                "completion_receipt": "recorded" if completion else "unavailable",
            }
            self.phase = "read_only_recovered:" + str(operation.state.status)
            self.error = (
                None
                if operation.state.status.value == "response_verified"
                and completion is not None
                else "historical_receipt_unavailable_or_recovery_required_no_replay"
            )
        except Exception:
            self.phase = "read_only_recovery_unverified"
            self.error = "persisted_response_requires_review_no_replay"

    def authorize_record(self, actor, subject, action):
        if actor != self.collector_id or action not in {
            "security:record",
            "security:hold",
        }:
            raise ContractError("Unregistered local recording identity")
        tenant = getattr(subject, "tenant_id", None)
        app = getattr(subject, "application_id", None)
        if (tenant, app) != (self.tenant, self.app):
            raise ContractError("Recording scope mismatch")

    def collect(self):
        for env, collector in self.collectors.items():
            try:
                collector.run_once()
                with self.lock:
                    self.collector_errors.pop(env, None)
            except Exception:
                with self.lock:
                    self.collector_errors[env] = "collection_unverified"
        self.last_collected = time.monotonic()

    def loop(self):
        while not self.stop.wait(1) and now() < self.deadline:
            if time.monotonic() - self.last_collected >= 5:
                self.collect()
            for env in ("blue", "green"):
                try:
                    result = self.probe.probe(env)
                except Exception:
                    result = {
                        "ok": False,
                        "target": env,
                        "observed_at": now().isoformat(),
                        "basis": "probe-unavailable",
                    }
                with self.lock:
                    self.probe_results[env] = result
            if time.monotonic() - self.last_isolation_check >= 5:
                self.refresh_isolation()

    def refresh_isolation(self):
        prepared = self.prepared
        if prepared is None or not any(
            step["action"] == "apply_isolation" for step in self.steps
        ):
            return
        try:
            command = prepared["plan"].command(
                "apply_isolation", operation_id="read-only-observation", epoch=1
            )
            observed = prepared["adapter"].readback(command, now())
            with self.lock:
                self.isolation_proof = {
                    "status": str(observed.status),
                    "observed_at": observed.observed_at.isoformat(),
                    "facts": observed.evidence,
                }
                if "blue" in prepared["adapter"].last_probes:
                    self.probe_results["blue"] = prepared["adapter"].last_probes["blue"]
        except Exception:
            with self.lock:
                self.isolation_proof = {
                    "status": "unknown",
                    "observed_at": now().isoformat(),
                }
        self.last_isolation_check = time.monotonic()

    def snapshot(self, after=0, *, recent=False):
        snapshots = {}
        collected = {}
        for env, reg in self.registrations.items():
            snapshot = self.read_observations.latest_snapshot(
                self.app, reg.environment_id
            )
            collected[env] = snapshot
            snapshots[env] = {
                "digest": snapshot.fingerprint,
                "graph": snapshot.graph.document,
                "findings": [f.document for f in snapshot.findings],
                "stale": now() >= snapshot.graph.valid_until
                or (now() - snapshot.graph.observed_at).total_seconds() > 15
                or env in self.collector_errors,
            }
        events = [
            {"sequence": seq, **event.document}
            for seq, event in self.read_observations.list_events(
                self.app, after=after, recent=recent
            )
        ]
        holds = [
            {
                "hold_id": s.hold.hold_id,
                "scope": s.hold.document["scope"],
                "reason": s.hold.reason,
                "raised_at": s.hold.raised_at.isoformat(),
            }
            for s in self.read_holds.active_holds(self.app)
        ]
        try:
            if any(s["stale"] for s in snapshots.values()):
                raise ContractError("Current protection observations unavailable")
            protection = compare_configuration(
                collected["blue"],
                collected["green"],
                source_node="deployment:api",
                target_node="deployment:api",
                now=now(),
            )
        except ContractError:
            protection = {
                "accepted": False,
                "basis": "configuration_only",
                "execution_authority": False,
                "reason": "current_comparison_unverified",
                "requirements": [],
            }
        with self.lock:
            return {
                "at": now().isoformat(),
                "expires_at": self.deadline.isoformat(),
                "application_id": self.app,
                "snapshots": snapshots,
                "events": events,
                "holds": holds,
                "route": self.routes.get(self.app, "test-entry"),
                "probes": dict(self.probe_results),
                "phase": self.phase,
                "busy": self.busy,
                "error": self.error,
                "steps": list(self.steps),
                "operation": self.operation,
                "isolation_proof": self.isolation_proof,
                "protection_comparison": protection,
                "prepared": None
                if self.prepared is None
                else {
                    "plan_digest": self.prepared["plan"].fingerprint,
                    "expires_at": self.prepared["plan"].valid_until.isoformat(),
                    "actions": [s.action for s in self.prepared["plan"].steps],
                },
                "scope": "real owned local k3s + PostgreSQL; stateless test fixture; operator session; not cloud migration or cyberattack detection",
            }

    def kube(self, *args):
        result = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                str(self.root / "admin-kubeconfig.json"),
                "--request-timeout=10s",
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=40,
        )
        if result.returncode:
            raise ContractError("Owned test action unverified")
        return result.stdout

    def inject(self):
        if (
            self.routes.get(self.app, "test-entry")["environment_id"]
            != self.registrations["blue"].environment_id
        ):
            raise ContractError("Fault injection requires original test route")
        current = json.loads(
            self.kube(
                "-n",
                self.registrations["blue"].namespace,
                "get",
                "deployment",
                "api",
                "-o",
                "json",
            )
        )
        patch = [
            {
                "op": "test",
                "path": "/metadata/uid",
                "value": current["metadata"]["uid"],
            },
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
                "value": False,
            },
        ]
        self.kube(
            "-n",
            self.registrations["blue"].namespace,
            "patch",
            "deployment",
            "api",
            "--type=json",
            "-p",
            json.dumps(patch),
        )
        self.kube(
            "-n",
            self.registrations["blue"].namespace,
            "rollout",
            "status",
            "deployment/api",
            "--timeout=30s",
        )
        self.collect()
        self.phase = "policy_violation_observed"

    def prepare(self):
        self.collect()
        source = self.read_observations.latest_snapshot(
            self.app, self.registrations["blue"].environment_id
        )
        target = self.read_observations.latest_snapshot(
            self.app, self.registrations["green"].environment_id
        )
        active = self.read_holds.active_holds(self.app)
        if not active:
            raise ContractError("An observed incident hold is required")
        profile = StatelessResponseProfile(
            "owned-local-stateless-test",
            self.clean["image"].split("@sha256:")[1],
            self.clean["configuration_digest"],
            True,
            True,
            True,
            self.operator,
            self.deadline,
        )
        binding = SecurityResponseBinding(
            source,
            target,
            "deployment:api",
            "deployment:api",
            tuple(h.hold.hold_id for h in active),
            profile,
            hashlib.sha256(b"local-stateless-security-policy-v1").hexdigest(),
        )
        plan = binding.compile(
            plan_id="response-" + secrets.token_hex(8),
            created_by="registered-security-planner",
            now=now(),
            valid_until=min(now() + timedelta(minutes=3), self.deadline),
        )
        adapter = OwnedKubernetesResponse(
            kubeconfig=self.root / "admin-kubeconfig.json",
            binding=binding,
            source_namespace_uid=self.registrations["blue"].namespace_uid,
            target_namespace_uid=self.registrations["green"].namespace_uid,
            probe_port=self.probe.probe_port,
            routes=self.routes,
        )

        def verify(binding, plan):
            adapter.check_identities()
            if not self.probe.probe_alive() or any(
                f.result != VerificationResult.PASS for f in binding.target.findings
            ):
                raise ContractError("Clean target or observation path unverified")
            if (
                adapter.initial_target["spec"]["template"]["spec"]["containers"][0][
                    "image"
                ]
                != self.clean["image"]
            ):
                raise ContractError("Admitted artifact changed")

        verify(binding, plan)
        artifact = hashlib.sha256(
            canonical_json(
                {
                    "binding": binding.fingerprint,
                    "profile": profile.fingerprint,
                    "kind": "owned-local-qualification-admission",
                }
            ).encode()
        ).hexdigest()
        evidence = tuple(
            EvidenceRecord(
                "admission:" + o.obligation_id,
                o.obligation_id,
                o.scope,
                plan.revisions,
                o.verifier_version,
                now(),
                plan.valid_until,
                VerificationResult.PASS,
                "local-admission-report",
                artifact,
            )
            for o in plan.obligations
        )
        self.prepared = {
            "binding": binding,
            "plan": plan,
            "adapter": adapter,
            "evidence": evidence,
            "verify": verify,
        }
        lifecycle = PostgresLifecycleRepository(
            self.admitter_connect, tenant_id=self.tenant
        )
        lifecycle.save_plan(plan)
        reference = self.root / "prepared-reference.json"
        reference.write_text(
            json.dumps(
                {"plan_id": plan.plan_id, "operation_id": "operation:" + plan.plan_id},
                indent=2,
            )
            + "\n"
        )
        reference.chmod(0o600)
        self.emit(
            SecurityEventKind.RESPONSE_PLANNED,
            source,
            "deployment:api",
            {"plan_digest": plan.fingerprint, "basis": "local-qualified-fixture"},
            "planned:" + plan.fingerprint,
        )
        self.phase = "awaiting_security_approval"

    def emit(self, kind, snapshot, node, details, event_id):
        resource = next(r for r in snapshot.graph.resources if r.node_id == node)
        event = SecurityEvent(
            event_id,
            resource.scope,
            snapshot.fingerprint,
            snapshot.graph.fingerprint,
            kind,
            (node,),
            now(),
            canonical_json(details),
        )
        self.observations.append_event(event)

    def approve(self, plan_digest):
        prepared = self.prepared
        if prepared is None or prepared["plan"].fingerprint != plan_digest:
            raise ContractError("Exact prepared response approval required")
        plan = prepared["plan"]
        binding = prepared["binding"]
        plan_expiry = plan.valid_until
        if now() + timedelta(seconds=60) >= min(plan_expiry, self.deadline):
            raise ContractError("Insufficient remaining response window; prepare again")
        approval = PlanApproval(
            plan.fingerprint, self.operator, plan.purpose, plan.valid_until
        )
        lifecycle = PostgresLifecycleRepository(
            self.admitter_connect, tenant_id=self.tenant
        )
        lifecycle.save_approval(
            self.app, plan.plan_id, "approval:" + plan.plan_id, approval
        )
        request = OperationRequest(
            self.tenant,
            self.app,
            "operation:" + plan.plan_id,
            plan.plan_id,
            plan.fingerprint,
            "approval:" + plan.plan_id,
            1,
            self.operator,
            "response:" + plan.fingerprint,
        )
        PostgresOperationRepository(lifecycle).submit(request)
        self.emit(
            SecurityEventKind.RESPONSE_APPROVED,
            binding.source,
            binding.source_node,
            {
                "plan_digest": plan.fingerprint,
                "actor_id": self.operator,
                "basis": "local-operator-session",
            },
            "approved:" + plan.fingerprint,
        )
        worker = PostgresLifecycleRepository(self.worker_connect, tenant_id=self.tenant)

        def auth_approval(current, saved):
            if current.fingerprint != plan.fingerprint or saved != approval:
                raise ContractError("Unregistered exact local response approval")

        def auth_evidence(record):
            if record not in prepared["evidence"]:
                raise ContractError("Unregistered local admission evidence")

        def authorize_profile(profile, current):
            if profile != binding.profile or current.fingerprint != plan.fingerprint:
                raise ContractError("Profile mismatch")

        guard = SecurityResponseGuard(
            binding,
            PostgresSecurityHolds(self.worker_connect, tenant_id=self.tenant),
            authorize_profile=authorize_profile,
            verify_admission=prepared["verify"],
            clock=now,
        )
        runner = SecurityResponseRunner(
            worker,
            PostgresOperationRepository(worker),
            PostgresExecutionOwnership(worker),
            journal_factory=PostgresEffectJournal,
            authenticate_approval=auth_approval,
            authenticate_evidence=auth_evidence,
            clock=now,
        )

        def emit(action, result):
            kinds = {
                "apply_isolation": SecurityEventKind.ISOLATION_VERIFIED,
                "activate_replacement": SecurityEventKind.OBSERVED,
                "verify_replacement": SecurityEventKind.REPLACEMENT_VERIFIED,
                "switch_route": SecurityEventKind.ROUTE_SWITCHED,
            }
            snapshot = binding.source if action == "apply_isolation" else binding.target
            node = (
                binding.source_node
                if action == "apply_isolation"
                else binding.target_node
            )
            self.emit(
                kinds[action],
                snapshot,
                node,
                {
                    "plan_digest": plan.fingerprint,
                    "effect_digest": result.command.fingerprint,
                    "basis": "runtime_probe",
                    "result": action,
                },
                "effect:" + result.command.fingerprint,
            )
            with self.lock:
                self.steps.append(
                    {
                        "action": action,
                        "status": str(result.status),
                        "at": now().isoformat(),
                        "effect_digest": result.command.fingerprint,
                    }
                )
                self.phase = action

        self.operation = runner.run(
            self.app,
            request.operation_id,
            owner_id="owned-response-worker",
            evidence=prepared["evidence"],
            guard=guard,
            adapter=prepared["adapter"],
            emit=emit,
        )
        self.phase = "response_verified_hold_retained"
        self.collect()

    def start_action(self, action, plan_digest=None):
        if action not in {"inject", "prepare", "approve"}:
            raise ContractError("Unregistered local action")
        with self.lock:
            if self.stop.is_set():
                raise ContractError("Console is shutting down")
            if self.busy:
                raise ContractError("Another response action is running")
            if now() + timedelta(seconds=60) >= self.deadline:
                raise ContractError("Session near expiry")
            if action == "approve" and (
                self.prepared is None
                or self.prepared["plan"].fingerprint != plan_digest
                or self.operation is not None
            ):
                raise ContractError("Exact pending response approval required")
            self.busy = True
            self.error = None
            self.phase = "running:" + action

        def run():
            try:
                if action == "inject":
                    self.inject()
                elif action == "prepare":
                    self.prepare()
                else:
                    self.approve(plan_digest)
            except Exception as exc:
                with self.lock:
                    self.error = "action_unverified_inspect_evidence"
                    self.phase = "needs_attention"
                # Only sanitized exception type/message for these owned test tools.
                (self.root / "console-last-error.json").write_text(
                    json.dumps(
                        {
                            "type": type(exc).__name__,
                            "message": str(exc)[:300],
                            "at": now().isoformat(),
                        },
                        indent=2,
                    )
                )
            finally:
                with self.lock:
                    self.busy = False

        with self.lock:
            if self.stop.is_set():
                self.busy = False
                raise ContractError("Console is shutting down")
            self.action_thread = threading.Thread(target=run, daemon=True)
            self.action_thread.start()

    def close(self):
        self.stop.set()
        with self.lock:
            action = self.action_thread
        self.thread.join(timeout=20)
        if action is not None:
            action.join(timeout=30)
        return {
            "collector_stopped": not self.thread.is_alive(),
            "action_drained": action is None or not action.is_alive(),
        }


def handler(
    console,
    origin,
    auth,
    *,
    ui_bundle=None,
    dependency_bridge=None,
    migration_bridge=None,
):
    expected_host = urlsplit(origin).netloc
    web = ROOT / "security_web"

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def parse_request(self):
            if not super().parse_request():
                return False
            if (
                len(self.path) > 2048
                or len(self.headers) > 32
                or sum(len(k) + len(v) for k, v in self.headers.items()) > 8192
            ):
                self.reply(431, {"error": "request_boundary_exceeded"})
                return False
            return True

        def session_token(self):
            try:
                values = self.headers.get_all("Cookie", [])
                if len(values) != 1 or values[0].count("sova_security=") != 1:
                    return None
                return SimpleCookie(values[0])["sova_security"].value
            except (KeyError, ValueError, TypeError, CookieError):
                return None

        def same_boundary(self, *, post=False):
            return (
                self.headers.get_all("Host", []) == [expected_host]
                and self.headers.get("Sec-Fetch-Site")
                not in {"cross-site", "same-site"}
                and (
                    self.headers.get_all("Origin", []) == [origin]
                    if post
                    else self.headers.get_all("Origin", []) in ([], [origin])
                )
            )

        def origin_proof(self, session):
            try:
                values = self.headers.get_all("X-Sova-CSRF", [])
                return (
                    session is not None
                    and len(values) == 1
                    and hmac.compare_digest(values[0], session.csrf)
                )
            except (ValueError, TypeError):
                return False

        def reply(
            self,
            status,
            body,
            kind="application/json",
            cookie=None,
            inline_styles=False,
        ):
            raw = (
                body
                if isinstance(body, bytes)
                else json.dumps(body, ensure_ascii=False).encode()
            )
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'"
                + (" 'unsafe-inline'" if inline_styles else "")
                + "; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
            )
            if cookie is not None:
                self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if not self.same_boundary():
                return self.reply(403, {"error": "host_denied"})
            if now() >= console.deadline:
                return self.reply(409, {"error": "session_expired"})
            parsed = urlsplit(self.path)
            session = auth.authenticate(self.session_token())
            if session is None:
                public = {
                    "/": ("login.html", "text/html; charset=utf-8"),
                    "/login.js": ("login.js", "text/javascript"),
                    "/security.css": ("security.css", "text/css"),
                }
                if ui_bundle is not None:
                    public.update({"/console": public["/"], "/console/": public["/"]})
                if parsed.path in public and not parsed.query:
                    file, kind = public[parsed.path]
                    return self.reply(200, (web / file).read_bytes(), kind)
                return self.reply(404, {"error": "not_found"})
            assets = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/security.js": ("security.js", "text/javascript"),
                "/security.css": ("security.css", "text/css"),
                "/workload": ("workload.html", "text/html; charset=utf-8"),
                "/workload.js": ("workload.js", "text/javascript"),
                "/legacy": ("index.html", "text/html; charset=utf-8"),
            }
            if ui_bundle is not None:
                asset = ui_bundle.get(parsed.path)
                if asset is not None:
                    data, kind = asset
                    if parsed.query and not kind.startswith("text/html"):
                        return self.reply(404, {"error": "not_found"})
                    return self.reply(
                        200, data, kind, inline_styles=kind.startswith("text/html")
                    )
            if parsed.path in assets:
                file, kind = assets[parsed.path]
                return self.reply(
                    200,
                    (web / file).read_bytes(),
                    kind,
                )
            # Cookies are shared across ports on the same loopback hostname.
            # A second proof stays in browser origin storage and is never sent
            # automatically to an uploaded app listening on another port.
            if parsed.path.startswith("/api/") and not self.origin_proof(session):
                return self.reply(403, {"error": "operator_origin_proof_required"})
            try:
                if (
                    parsed.path == "/api/migration/readiness"
                    and migration_bridge is not None
                ):
                    if parsed.query:
                        raise ContractError("No readiness query parameters allowed")
                    return self.reply(200, migration_bridge.readiness())
                if (
                    parsed.path == "/api/migration/state"
                    and migration_bridge is not None
                ):
                    if parsed.query:
                        raise ContractError("No migration state parameters allowed")
                    return self.reply(200, migration_bridge.state())
                if (
                    parsed.path == "/api/dependency/state"
                    and dependency_bridge is not None
                ):
                    if parsed.query:
                        raise ContractError("Unregistered dependency state parameters")
                    return self.reply(200, dependency_bridge.state())
                if parsed.path == "/api/state":
                    query = parse_qs(
                        parsed.query, keep_blank_values=True, strict_parsing=True
                    )
                    if set(query) - {"after", "recent"} or any(
                        len(values) != 1 for values in query.values()
                    ):
                        raise ContractError("Ambiguous state cursor")
                    after = int(query.get("after", ["0"])[0])
                    if not 0 <= after <= 10**12:
                        raise ContractError("Invalid cursor")
                    if "recent" in query:
                        if query["recent"] != ["1"] or after != 0:
                            raise ContractError("Exact recent event request required")
                        return self.reply(
                            200,
                            {
                                **console.snapshot(recent=True),
                                "csrf": session.csrf,
                                "interfaces": {
                                    "dependency": dependency_bridge is not None,
                                    "migration": migration_bridge is not None,
                                },
                            },
                        )
                    return self.reply(
                        200,
                        {
                            **console.snapshot(after),
                            "csrf": session.csrf,
                            "interfaces": {
                                "dependency": dependency_bridge is not None,
                                "migration": migration_bridge is not None,
                            },
                        },
                    )
                if parsed.path == "/api/workload":
                    if parsed.query:
                        raise ContractError("Unregistered workload request parameters")
                    if now() >= console.deadline:
                        return self.reply(409, {"error": "session_expired"})
                    route = console.routes.get(console.app, "test-entry")
                    env = next(
                        (
                            env
                            for env, reg in console.registrations.items()
                            if reg.environment_id == route["environment_id"]
                        ),
                        None,
                    )
                    if env is None:
                        raise ContractError("Unregistered route environment")
                    return self.reply(
                        200,
                        {
                            "route_revision": route["revision"],
                            "proof": console.probe.probe(env),
                        },
                    )
                return self.reply(404, {"error": "not_found"})
            except Exception:
                return self.reply(409, {"error": "state_unverified"})

        def do_POST(self):
            if not self.same_boundary(post=True):
                return self.reply(403, {"error": "operator_session_denied"})
            if now() >= console.deadline:
                return self.reply(409, {"error": "session_expired"})
            try:
                self.connection.settimeout(3)
                length = self.headers.get("Content-Length", "")
                if not length or any(c not in "0123456789" for c in length):
                    raise ContractError("Exact request body length required")
                size = int(length)
                if (
                    self.path
                    not in {
                        "/api/session",
                        "/api/logout",
                        "/api/action",
                        "/api/dependency/action",
                        "/api/dependency/application",
                        "/api/migration/action",
                    }
                    or len(self.headers.get_all("Content-Length", [])) != 1
                    or self.headers.get_all("Content-Type", []) != ["application/json"]
                    or self.headers.get_all("Transfer-Encoding", [])
                    or not 0 < size <= 2048
                ):
                    raise ContractError("Invalid action request")
                raw = self.rfile.read(size)
                if len(raw) != size:
                    raise ContractError("Incomplete request body")
                data = json_document(raw.decode(), limit=2048)
                if self.path == "/api/session":
                    if not isinstance(data, dict) or set(data) != {"bootstrap"}:
                        raise ContractError("Invalid bootstrap request")
                    token, session = auth.exchange(data["bootstrap"])
                    age = max(0, int((session.expires_at - now()).total_seconds()))
                    return self.reply(
                        200,
                        {
                            "status": "authenticated",
                            "expires_at": session.expires_at.isoformat(),
                            "origin_proof": session.csrf,
                        },
                        cookie="sova_security="
                        + token
                        + "; HttpOnly; SameSite=Strict; Path=/; Max-Age="
                        + str(age),
                    )
                session = auth.authenticate(self.session_token())
                if not self.origin_proof(session):
                    return self.reply(403, {"error": "operator_session_denied"})
                if self.path == "/api/migration/action":
                    if migration_bridge is None:
                        raise ContractError("Migration backend not configured")
                    return self.reply(202, migration_bridge.action(data))
                if self.path in {
                    "/api/dependency/action",
                    "/api/dependency/application",
                }:
                    if dependency_bridge is None:
                        raise ContractError("Dependency adapter not configured")
                    result = (
                        dependency_bridge.action(data)
                        if self.path == "/api/dependency/action"
                        else dependency_bridge.application(data)
                    )
                    return self.reply(200, result)
                if self.path == "/api/logout":
                    if data != {}:
                        raise ContractError("Invalid logout")
                    auth.revoke(self.session_token())
                    return self.reply(
                        200,
                        {"status": "logged_out"},
                        cookie="sova_security=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
                    )
                if (
                    not isinstance(data, dict)
                    or set(data) - {"action", "plan_digest"}
                    or "action" not in data
                ):
                    raise ContractError("Invalid action fields")
                if type(data["action"]) is not str or data["action"] not in {
                    "inject",
                    "prepare",
                    "approve",
                }:
                    raise ContractError("Unregistered action")
                if set(data) != (
                    {"action", "plan_digest"}
                    if data["action"] == "approve"
                    else {"action"}
                ):
                    raise ContractError("Unregistered action schema")
                console.start_action(data["action"], data.get("plan_digest"))
                return self.reply(202, {"status": "accepted-not-complete"})
            except (ValueError, TypeError, UnicodeError, TimeoutError, ContractError):
                return self.reply(409, {"error": "action_rejected"})

    return Handler


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--session-root", required=True)
    parser.add_argument("--port", type=int, default=8792)
    parser.add_argument("--ui-root", help="Operator-selected built React bundle")
    parser.add_argument(
        "--migration-token-file",
        type=Path,
        help="Owner-private upstream bootstrap credential; never sent to browser",
    )
    parser.add_argument(
        "--security-only",
        action="store_true",
        help="Expose only this session's security-response path",
    )
    parser.add_argument(
        "--no-migration",
        action="store_true",
        help="Disable the separate AWS/VM preview without disabling Dependency Lab",
    )
    parser.add_argument(
        "--migration-port", type=int, default=8790, help="Fixed AWS/VM preview port"
    )
    parser.add_argument(
        "--dependency-port", type=int, help="Fixed loopback Dependency Lab port"
    )
    args = parser.parse_args(argv)
    if args.security_only and args.dependency_port is not None:
        parser.error("security-only demo cannot enable the separate Dependency Lab")
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if args.dependency_port == args.port:
        parser.error("dependency port must differ from console port")
    if args.dependency_port is not None and not 1 <= args.dependency_port <= 65535:
        parser.error("dependency port must be between 1 and 65535")
    if not 1 <= args.migration_port <= 65535 or args.migration_port in {
        args.port,
        args.dependency_port,
    }:
        parser.error("migration port must be distinct and between 1 and 65535")
    ui_bundle = ConsoleWebBundle(args.ui_root) if args.ui_root else None
    dependency_bridge = (
        DependencyBridge(args.dependency_port) if args.dependency_port else None
    )
    stopped = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stopped.set())
    signal.signal(signal.SIGINT, lambda *_: stopped.set())
    origin = "http://127.0.0.1:" + str(args.port)
    console = server = bootstrap_path = None
    try:
        console = SecurityConsole(args.session_root)
        explicit_until = console.session.get("operator_session_until")
        session_until = (
            datetime.fromisoformat(explicit_until) if explicit_until else None
        )
        auth = OperatorAuth(
            deadline=console.deadline
            if session_until
            else min(console.deadline, now() + timedelta(hours=2)),
            clock=now,
            session_until=session_until,
        )
        bootstrap_path = write_bootstrap_file(
            console.root,
            origin=origin,
            token=auth.issue_bootstrap(),
            expires_at=auth.bootstrap_until,
        )
        server = BoundedLoopbackServer(
            ("127.0.0.1", args.port),
            handler(
                console,
                origin,
                auth,
                ui_bundle=ui_bundle,
                dependency_bridge=dependency_bridge,
                migration_bridge=None
                if args.security_only or args.no_migration
                else MigrationBridge(
                    args.migration_port,
                    bootstrap_token_provider=(
                        lambda: private_text(
                            args.migration_token_file, limit=256
                        ).strip()
                    )
                    if args.migration_token_file
                    else None,
                ),
            ),
        )
        server.timeout = 0.5
        (console.root / "console-server.json").write_text(
            json.dumps(
                {
                    "pid": os.getpid(),
                    "url": origin,
                    "expires_at": console.deadline.isoformat(),
                },
                indent=2,
            )
            + "\n"
        )
        print("Sova security qualification console: " + origin, flush=True)
        print("One-time owner login URL is in: " + str(bootstrap_path), flush=True)
        while not stopped.is_set() and now() < console.deadline:
            server.handle_request()
    finally:
        try:
            drained = console.close() if console is not None else None
        finally:
            if server is not None:
                server.server_close()
            if bootstrap_path is not None:
                bootstrap_path.unlink(missing_ok=True)
        if console is not None:
            (console.root / "console-shutdown.json").write_text(
                json.dumps(
                    {
                        "pid": os.getpid(),
                        "at": now().isoformat(),
                        "scope": "local qualification only",
                        "drain": drained,
                    },
                    indent=2,
                )
                + "\n"
            )


if __name__ == "__main__":
    main()
