"""Personal, bounded qualification on newly owned namespaces only.

Consumes the existing team direct-API credential and existing Sova effect ledger
and response adapter. It is not the T10/T31 product execution or approval host.
"""

import argparse
import hashlib
import hmac
import http.client
import json
import os
import secrets
import signal
import socket
import sqlite3
import ssl
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
from sova.adapters.kubernetes.inventory import snapshot_graph
from sova.adapters.kubernetes.posture import posture_projection
from sova.adapters.security_codec import decode_finding
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.domain.contracts import (
    ContractError,
    EffectStatus,
    ExecutionPermit,
    canonical_json,
)
from sova.domain.security_events import SecuritySnapshot
from sova.domain.security_response import (
    SecurityResponseBinding,
    StatelessResponseProfile,
)
from sova.security.application.security_response import SecurityResponseGuard
from sova.security.qualification.kubernetes_response import OwnedKubernetesResponse
from sova_security.domain.governance import SecurityHold, StoredHold

from .manifests import manifests, names, validate_names
from .controls import read as read_control


def now():
    return datetime.now(UTC)


def atomic_json(path, value):
    path = Path(path)
    tmp = path.with_suffix(".new")
    with tmp.open("w") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    tmp.chmod(0o600)
    tmp.replace(path)


class TrialAPI:
    def __init__(self, profile, run_id, root):
        self.profile, self.run_id, self.root = profile, run_id, root
        self.namespaces = names(run_id)
        self.uids = {}
        self.token_deadline = datetime.fromisoformat(
            os.environ["BRAVO_TEAM_DIRECT_EXPIRY"].replace("Z", "+00:00")
        )
        config = json.loads(Path(os.environ["KUBECONFIG"]).read_text())
        server = config["clusters"][0]["cluster"]["server"]
        if server.rstrip("/") != profile["direct_server"].rstrip("/"):
            raise ContractError("Registered direct API required")
        self.client = httpx.Client(
            base_url=server,
            verify=ssl.create_default_context(),
            trust_env=False,
            headers={
                "Authorization": "Bearer " + os.environ["BRAVO_TEAM_DIRECT_TOKEN"]
            },
            follow_redirects=False,
            timeout=15,
        )
        self.verify_identity()

    def request(self, method, path, body=None, *, patch=False, allow_absent=False):
        if now() >= self.token_deadline - timedelta(seconds=10):
            raise ContractError("Personal credential expiring; no new request")
        if method != "GET":
            allowed = any(
                f"/namespaces/{n}/" in path or path == f"/api/v1/namespaces/{n}"
                for n in self.namespaces.values()
            )
            if path == "/api/v1/namespaces" and method == "POST":
                allowed = (
                    body.get("metadata", {}).get("name") in self.namespaces.values()
                )
            if path == "/apis/authentication.k8s.io/v1/selfsubjectreviews":
                allowed = method == "POST"
            if not allowed:
                raise ContractError("Mutation outside owned trial namespace refused")
            with (self.root / "requests.private.jsonl").open("a") as stream:
                stream.write(
                    json.dumps(
                        {
                            "at": now().isoformat(),
                            "method": method,
                            "path": path,
                            "body_digest": hashlib.sha256(
                                canonical_json(
                                    {"document": body}, limit=131072
                                ).encode()
                            ).hexdigest(),
                        }
                    )
                    + "\n"
                )
                stream.flush()
                os.fsync(stream.fileno())
        try:
            response = self.client.request(
                method,
                path,
                json=body,
                headers={"Content-Type": "application/json-patch+json"}
                if patch
                else None,
            )
        except httpx.HTTPError:
            raise ContractError(
                "Trial API response unconfirmed; do not replay"
            ) from None
        if response.status_code == 404 and method == "GET" and allow_absent:
            return None
        if response.status_code >= 400 or len(response.content) > 1048576:
            raise ContractError(f"Trial API refused request ({response.status_code})")
        return response.json()

    def verify_identity(self):
        identity = self.request(
            "POST",
            "/apis/authentication.k8s.io/v1/selfsubjectreviews",
            {"apiVersion": "authentication.k8s.io/v1", "kind": "SelfSubjectReview"},
        )
        self.subject = identity["status"]["userInfo"]["username"]
        if (
            self.subject
            != "system:serviceaccount:"
            + self.profile["access_namespace"]
            + ":member-04"
        ):
            raise ContractError("This qualification is bound to member-04")
        ns = self.request("GET", "/api/v1/namespaces/kube-system")
        if ns["metadata"]["uid"] != self.profile["cluster_uid"]:
            raise ContractError("Registered on-prem cluster UID mismatch")

    def create(self, document):
        kind, meta = document["kind"], document["metadata"]
        if kind == "Namespace":
            path = "/api/v1/namespaces"
        else:
            namespace = meta["namespace"]
            if namespace not in self.uids:
                raise ContractError("Unregistered trial namespace")
            self.check_owned()
            base, plural = {
                "ResourceQuota": ("/api/v1", "resourcequotas"),
                "ConfigMap": ("/api/v1", "configmaps"),
                "Service": ("/api/v1", "services"),
                "Deployment": ("/apis/apps/v1", "deployments"),
                "NetworkPolicy": ("/apis/networking.k8s.io/v1", "networkpolicies"),
            }[kind]
            path = f"{base}/namespaces/{namespace}/{plural}"
        try:
            result = self.request("POST", path, document)
        except ContractError:
            # A lost create response is not permission to create again. Read back
            # only the random name and our two ownership labels for cleanup.
            if kind == "Namespace":
                try:
                    found = self.request("GET", path + "/" + meta["name"])
                    labels = found["metadata"].get("labels", {})
                    if (
                        labels.get("sova.io/trial") == self.run_id
                        and labels.get("app.kubernetes.io/part-of")
                        == "sova-wr-" + self.run_id
                    ):
                        self.uids[meta["name"]] = found["metadata"]["uid"]
                        atomic_json(
                            self.root / "owned-namespaces.private.json", self.uids
                        )
                except Exception:
                    pass
            raise
        if kind == "Namespace":
            self.uids[meta["name"]] = result["metadata"]["uid"]
            atomic_json(self.root / "owned-namespaces.private.json", self.uids)
        return result

    def get(self, kind, side, name):
        base, plural = {
            "deployment": ("/apis/apps/v1", "deployments"),
            "service": ("/api/v1", "services"),
            "configmap": ("/api/v1", "configmaps"),
        }[kind]
        return self.request(
            "GET", f"{base}/namespaces/{self.namespaces[side]}/{plural}/{name}"
        )

    def check_owned(self):
        for namespace, uid in self.uids.items():
            doc = self.request("GET", f"/api/v1/namespaces/{namespace}")
            if (
                doc["metadata"]["uid"] != uid
                or doc["metadata"].get("labels", {}).get("sova.io/trial") != self.run_id
            ):
                raise ContractError("Trial namespace UID or ownership changed")

    def cleanup(self):
        result = {}
        for namespace, uid in tuple(self.uids.items()):
            try:
                doc = self.request("GET", f"/api/v1/namespaces/{namespace}")
                if (
                    doc["metadata"]["uid"] != uid
                    or doc["metadata"].get("labels", {}).get("sova.io/trial")
                    != self.run_id
                ):
                    raise ContractError("Cleanup ownership mismatch")
                self.request(
                    "DELETE",
                    f"/api/v1/namespaces/{namespace}",
                    {
                        "apiVersion": "v1",
                        "kind": "DeleteOptions",
                        "preconditions": {"uid": uid},
                        "propagationPolicy": "Foreground",
                    },
                )
                result[namespace] = "deletion_requested_with_uid_precondition"
                until = time.monotonic() + 12
                while time.monotonic() < until:
                    current = self.request(
                        "GET", f"/api/v1/namespaces/{namespace}", allow_absent=True
                    )
                    if current is None:
                        result[namespace] = "absence_confirmed"
                        break
                    if current["metadata"]["uid"] != uid:
                        result[namespace] = "original_absent_name_reused_do_not_delete"
                        break
                    time.sleep(0.5)
            except Exception:
                result[namespace] = "cleanup_unconfirmed"
        atomic_json(self.root / "cleanup.private.json", result)
        return result


class Routes:
    def __init__(self, port, source, target):
        self.port, self.source, self.target = port, source, target

    def call(self, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=4)
        try:
            nonce = secrets.token_hex(16)
            connection.request(
                "POST" if body is not None else "GET",
                path,
                body=json.dumps(body) if body is not None else None,
                headers={"X-Request-ID": nonce, "Content-Type": "application/json"},
            )
            response = connection.getresponse()
            raw = response.read(65537)
            if response.status != 200 or len(raw) > 65536:
                raise ContractError("Owned probe response unavailable")
            value = json.loads(raw)
            if path.startswith("/probe") or path == "/entry":
                if (
                    value.get("ok")
                    and value.get("response", {}).get("request_id") != nonce
                ):
                    raise ContractError("Probe request nonce mismatch")
            return value
        finally:
            connection.close()

    def get(self, _app, _route):
        return self.call("/route")

    def switch(self, _app, _route, **body):
        if body["source"] != self.source or body["target"] != self.target:
            raise ContractError("Unregistered trial routing target")
        self.call("/route", body)


class Adapter(OwnedKubernetesResponse):
    def __init__(self, *args, api, **kwargs):
        self.trial_api = api
        super().__init__(*args, **kwargs)

    def get(self, kind, namespace, name):
        if namespace not in self.trial_api.namespaces.values():
            raise ContractError("Foreign namespace read refused by trial adapter")
        base, plural = {
            "deployment": ("/apis/apps/v1", "deployments"),
            "service": ("/api/v1", "services"),
            "configmap": ("/api/v1", "configmaps"),
            "networkpolicy": ("/apis/networking.k8s.io/v1", "networkpolicies"),
        }[kind]
        if not name or "/" in name:
            raise ContractError("Named trial resource required")
        return self.trial_api.request(
            "GET", f"{base}/namespaces/{namespace}/{plural}/{name}"
        )

    def kube(self, *args, input=None, timeout=20):
        # Reuse the verified TLS connection instead of repeatedly launching the
        # credential plugin. Only the existing adapter's exact operations exist.
        if (
            len(args) == 5
            and args[:2] == ("get", "namespace")
            and args[-2:] == ("-o", "json")
        ):
            if args[2] not in self.trial_api.namespaces.values():
                raise ContractError("Foreign namespace refused")
            result = self.trial_api.request("GET", "/api/v1/namespaces/" + args[2])
        elif (
            len(args) == 6
            and args[0] == "-n"
            and args[2:] == ("get", "networkpolicy", "-o", "json")
        ):
            if args[1] not in self.trial_api.namespaces.values():
                raise ContractError("Foreign namespace refused")
            result = self.trial_api.request(
                "GET",
                f"/apis/networking.k8s.io/v1/namespaces/{args[1]}/networkpolicies",
            )
        elif (
            len(args) == 7
            and args[0] == "-n"
            and args[2:4] == ("get", "deployment")
            and args[-2:] == ("-o", "json")
        ):
            result = self.get("deployment", args[1], args[4])
        elif args == ("create", "-f", "-"):
            document = json.loads(input)
            if (
                document.get("kind") != "NetworkPolicy"
                or document["metadata"]["namespace"] != self.source_ns
            ):
                raise ContractError(
                    "Only the owned source isolation policy is admitted"
                )
            result = self.trial_api.create(document)
        elif (
            len(args) == 8
            and args[:4] == ("-n", self.target_ns, "patch", "deployment")
            and args[4:7] == (self.target_name, "--type=json", "-p")
        ):
            result = self.trial_api.request(
                "PATCH",
                f"/apis/apps/v1/namespaces/{self.target_ns}/deployments/{self.target_name}",
                json.loads(args[7]),
                patch=True,
            )
        else:
            raise ContractError("Unregistered trial API operation")
        return json.dumps(result)

    def check_identities(self):
        self.trial_api.check_owned()
        super().check_identities()

    def policy(self, command):
        doc = super().policy(command)
        doc["metadata"]["labels"]["io.sova/session"] = self.trial_api.run_id
        return doc

    def readback(self, command, at):
        result = super().readback(command, at)
        if command.action == "switch_route":
            entry = self.routes.call("/entry")
            if (
                not entry.get("ok")
                or entry.get("response", {}).get("environment") != "green"
            ):
                raise ContractError("Stable test entry did not reach the replacement")
        return result


class Trial:
    def __init__(self, root, image, profile):
        if root.is_symlink() or (root.exists() and any(root.iterdir())):
            raise ContractError("Fresh owner-private trial directory required")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        self.root, self.image = root, image
        repository = Path(__file__).resolve().parents[2]
        self.source_revision = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True
        ).strip()
        if subprocess.check_output(
            ["git", "status", "--porcelain", "--", "demo/onprem_response"],
            cwd=repository,
            text=True,
        ):
            raise ContractError("Commit qualification source before live execution")
        self.run_id = secrets.token_hex(4)
        validate_names(self.run_id, image)
        self.app = "sova-wr-" + self.run_id
        self.ns = names(self.run_id)
        self.api = TrialAPI(profile, self.run_id, root)
        self.deadline = min(
            now() + timedelta(minutes=8),
            self.api.token_deadline - timedelta(seconds=50),
        )
        self.steps = []
        self.events = []
        self.forward = None
        self.adapter = None
        self.phase = "preparing"
        self.snapshot_revision = 0
        self.hmac_key = secrets.token_bytes(32)
        (root / "feed-key.private").write_bytes(self.hmac_key)
        (root / "feed-key.private").chmod(0o600)
        self.plan_binding = None
        self.probes = {}
        self.isolation = None
        self.db = sqlite3.connect(
            root / "effects.private.sqlite", check_same_thread=False
        )
        self.journal = SQLiteEffectJournal(self.db)
        self.executor = EffectExecutor(self.journal, authorize=self.authorize)

    def authorize(self, command, permit, at, mutation):
        if at >= self.deadline or command.fingerprint not in self.registered_commands:
            raise ContractError("Unregistered or expired trial effect")
        self.api.verify_identity()
        self.guard(self.plan, at)
        return True

    def operator_control(self, path):
        return read_control(
            path,
            key=self.hmac_key,
            binding=self.plan_binding,
            revision=self.source_revision,
            at=now(),
            deadline=self.deadline,
        )

    def stop_requested(self, directory):
        control = self.operator_control(directory / "stop.private.json")
        if control and control["action"] != "stop":
            raise ContractError("Stop control requires the stop action")
        return bool(control)

    def await_operator(self, directory):
        last_publish = time.monotonic()
        while now() < self.deadline - timedelta(seconds=40):
            if self.stop_requested(directory):
                return False
            control = self.operator_control(directory / "respond.private.json")
            if control:
                if control["action"] != "respond":
                    raise ContractError("Response approval required")
                if self.deadline - now() < timedelta(minutes=4):
                    raise ContractError(
                        "Insufficient time for bounded response; prepare a new trial"
                    )
                atomic_json(self.root / "consumed-control.private.json", control)
                return True
            if time.monotonic() - last_publish >= 8:
                self.publish("normal", record_event=False)
                last_publish = time.monotonic()
            time.sleep(0.5)
        return False

    def wait(self, side, component, seconds=55):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            obj = self.api.get("deployment", side, component)
            if (
                obj.get("status", {}).get("readyReplicas") == 1
                and obj["status"].get("updatedReplicas") == 1
                and obj["status"].get("replicas") == 1
                and obj["status"].get("observedGeneration", 0)
                >= obj["metadata"]["generation"]
            ):
                return obj
            time.sleep(1)
        raise ContractError("Trial Deployment readiness deadline exceeded")

    def start(self):
        atomic_json(
            self.root / "trial.private.json",
            {
                "run_id": self.run_id,
                "namespaces": self.ns,
                "image": self.image,
                "subject": self.api.subject,
                "deadline": self.deadline.isoformat(),
                "cluster_uid": self.api.profile["cluster_uid"],
                "source_revision": self.source_revision,
                "qualification_only": True,
            },
        )
        for doc in manifests(self.run_id, self.image):
            self.api.create(doc)
        self.wait("blue", "api")
        self.wait("blue", "neighbor")
        self.wait("probe", "probe")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        log = (self.root / "forward.private.log").open("w")
        self.forward = subprocess.Popen(
            [
                "kubectl",
                "--request-timeout=20s",
                "-n",
                self.ns["probe"],
                "port-forward",
                "service/probe",
                f"{port}:8080",
                "--address=127.0.0.1",
            ],
            stdout=log,
            stderr=log,
        )
        self.routes = Routes(port, self.ns["blue"], self.ns["green"])
        for _ in range(30):
            if self.forward.poll() is not None:
                raise ContractError("Owned probe forwarding failed")
            try:
                if self.routes.call("/health").get("probe") == "alive":
                    break
            except OSError:
                pass
            time.sleep(0.3)
        else:
            raise ContractError("Owned probe forwarding unavailable")
        self.port = port
        self.source = self.api.get("deployment", "blue", "api")
        self.neighbor = self.api.get("deployment", "blue", "neighbor")
        self.target = self.api.get("deployment", "green", "api")
        actual = {
            side: self.api.get("service", side, "api")["metadata"]["uid"]
            for side in ("blue", "green")
        }
        self.plan_binding = {
            "tenant_id": "onprem-qualification",
            "application_id": self.app,
            "plan_id": "onprem-trial-" + self.run_id,
            "plan_digest": hashlib.sha256(
                canonical_json(
                    {
                        "namespaces": self.api.uids,
                        "source_uid": self.source["metadata"]["uid"],
                        "target_uid": self.target["metadata"]["uid"],
                        "image": self.image,
                        "services": actual,
                    }
                ).encode()
            ).hexdigest(),
            "plan_version": 1,
            "source_environment_id": self.ns["blue"],
            "target_environment_id": self.ns["green"],
        }
        atomic_json(self.root / "registration.private.json", self.plan_binding)
        self.publish("normal")

    def snapshot(self, side):
        dep = self.api.get("deployment", side, "api")
        svc = self.api.get("service", side, "api")
        graph = snapshot_graph(
            {"kind": "List", "items": [dep, svc]},
            tenant_id="onprem-qualification",
            application_id=self.app,
            environment_id=self.ns[side],
            namespace=self.ns[side],
            location="onprem-trial",
            observed_at=now(),
            valid_until=min(now() + timedelta(minutes=5), self.deadline),
        )
        findings = tuple(
            decode_finding(f) for f in posture_projection((dep, svc), graph)["findings"]
        )
        return SecuritySnapshot(
            graph,
            findings,
            hashlib.sha256(
                json.dumps(
                    {"deployment": dep, "service": svc},
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode()
            ).hexdigest(),
        )

    def inject_and_bind(self):
        self.api.check_owned()
        original = self.api.get("deployment", "blue", "api")
        self.api.request(
            "PATCH",
            f"/apis/apps/v1/namespaces/{self.ns['blue']}/deployments/api",
            [
                {
                    "op": "test",
                    "path": "/metadata/uid",
                    "value": original["metadata"]["uid"],
                },
                {
                    "op": "replace",
                    "path": "/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem",
                    "value": False,
                },
            ],
            patch=True,
        )
        self.wait("blue", "api")
        source, target = self.snapshot("blue"), self.snapshot("green")
        if not any(
            f.control_id == "read-only-root" and str(f.result) == "fail"
            for f in source.findings
        ):
            raise ContractError("Controlled configuration violation was not observed")
        template = self.api.get("deployment", "green", "api")["spec"]["template"]
        cm = self.api.get("configmap", "green", "api-code")
        projection = {
            "template": template,
            "configmaps": [
                {
                    "name": "api-code",
                    "uid": cm["metadata"]["uid"],
                    "data_digest": hashlib.sha256(
                        canonical_json(cm["data"], limit=65536).encode()
                    ).hexdigest(),
                }
            ],
        }
        profile = StatelessResponseProfile(
            "owned-onprem-stateless-test",
            self.image.split("@sha256:")[1],
            hashlib.sha256(
                canonical_json(projection, limit=65536).encode()
            ).hexdigest(),
            True,
            True,
            True,
            "member-04-qualification",
            self.deadline,
        )
        resource = next(
            r for r in source.graph.resources if r.node_id == "deployment:api"
        )
        hold = StoredHold(
            SecurityHold(
                "trial-hold-" + self.run_id,
                resource.scope,
                "personal-operator",
                "controlled-read-only-root-violation",
                now(),
            ),
            1,
        )
        self.hold = hold
        self.binding = SecurityResponseBinding(
            source,
            target,
            "deployment:api",
            "deployment:api",
            (hold.hold.hold_id,),
            profile,
            hashlib.sha256(b"owned-onprem-trial-policy-v1").hexdigest(),
        )
        self.plan = self.binding.compile(
            plan_id="response-" + self.run_id,
            created_by="member-04-qualification",
            now=now(),
            valid_until=min(
                now() + timedelta(minutes=5),
                self.deadline,
                source.graph.valid_until,
                target.graph.valid_until,
            ),
        )
        self.adapter = Adapter(
            kubeconfig=os.environ["KUBECONFIG"],
            binding=self.binding,
            source_namespace_uid=self.api.uids[self.ns["blue"]],
            target_namespace_uid=self.api.uids[self.ns["green"]],
            probe_port=self.port,
            routes=self.routes,
            api=self.api,
        )

        def admission(_binding, _plan):
            self.adapter.check_identities()

        self.guard = SecurityResponseGuard(
            self.binding,
            SimpleNamespace(
                tenant_id=self.plan.tenant_id,
                active_holds=lambda app: (hold,) if app == self.app else (),
            ),
            authorize_profile=admission,
            verify_admission=admission,
            clock=now,
        )
        self.registered_commands = {
            self.plan.command(step.action, operation_id=self.app, epoch=1).fingerprint
            for step in self.plan.steps
        }
        atomic_json(
            self.root / "approved-trial.private.json",
            {
                "purpose": "operator-owned-qualification-only",
                "actor": self.api.subject,
                "plan": self.plan.document,
                "hold": hold.hold.document,
                "not_a_product_approval": True,
            },
        )
        self.publish("detected")

    def execute(self, action):
        command = self.plan.command(action, operation_id=self.app, epoch=1)
        permit = ExecutionPermit(
            command.scope,
            command.operation_id,
            command.plan_digest,
            command.fingerprint,
            command.fencing_epoch,
            command.expires_at,
        )
        result = self.executor.execute(command, permit, self.adapter)
        if result.status != EffectStatus.APPLIED:
            raise ContractError("Trial effect not confirmed")
        self.steps.append(
            {
                "action": action,
                "command_digest": command.fingerprint,
                "observation": result.observation.document
                if hasattr(result.observation, "document")
                else result.observation.evidence,
            }
        )
        atomic_json(self.root / "effects-summary.private.json", self.steps)
        self.publish(action)

    def publish(self, phase, *, record_event=True):
        from .projection import projection

        self.observation_started_at = now()
        self.phase = phase
        self.snapshot_revision += 1
        self.probes = {
            target: self.routes.call("/probe?target=" + target)
            for target in ("blue", "green", "neighbor")
        }
        self.entry = self.routes.call("/entry")
        if self.adapter and any(s["action"] == "apply_isolation" for s in self.steps):
            command = self.plan.command(
                "apply_isolation", operation_id=self.app, epoch=1
            )
            self.isolation = self.adapter.readback(command, now())
        if record_event and (
            phase != "watch"
            or (self.entry.get("ok") and self.probes["neighbor"].get("ok"))
        ):
            self.events.append(
                {"phase": phase, "occurred_at": self.observation_started_at.isoformat()}
            )
        body = projection(self)
        self.write_feed(body)

    def write_feed(self, body):
        envelope = {
            "producer_id": "owned-onprem-qualification",
            "source_revision": self.source_revision,
            "body": body,
        }
        raw = json.dumps(
            envelope, separators=(",", ":"), ensure_ascii=False, sort_keys=True
        ).encode()
        atomic_json(
            self.root / "feed.private.json",
            {
                **envelope,
                "hmac_sha256": hmac.new(self.hmac_key, raw, hashlib.sha256).hexdigest(),
            },
        )

    def close(self):
        try:
            path = self.root / "feed.private.json"
            if path.exists():
                body = json.loads(path.read_text())["body"]
                # Preserve original observations; never renew evidence at shutdown.
                expiry = (
                    datetime.fromisoformat(body["observed_at"])
                    + timedelta(milliseconds=1)
                ).isoformat()
                body["expires_at"] = expiry
                body["source_label"] = (
                    "종료된 실제 온프렘 전용 시험 기록 · 현재 자원 상태 및 제품 운영 인수 아님"
                )
                for evidence in body["evidence"]:
                    evidence["expires_at"] = expiry
                self.write_feed(body)
        except Exception:
            pass
        result = self.api.cleanup()
        if self.forward:
            self.forward.terminate()
            try:
                self.forward.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.forward.kill()
                self.forward.wait(timeout=3)
        self.db.close()
        self.api.client.close()
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--hold-seconds", type=int, default=240)
    parser.add_argument("--start-delay", type=int, default=15)
    parser.add_argument("--operator-control", type=Path)
    args = parser.parse_args()
    if not 0 <= args.hold_seconds <= 300 or not 0 <= args.start_delay <= 30:
        parser.error("Bounded qualification interval required")
    os.umask(0o077)
    trial = Trial(args.state, args.image, json.loads(args.profile.read_text()))

    def stop(_sig, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    result = {"qualification_only": True, "product_workflow_qualified": False}
    try:
        trial.start()
        print(
            "Owned on-prem trial ready; waiting before controlled response.", flush=True
        )
        if args.operator_control:
            directory = args.operator_control
            if directory.is_symlink() or directory.stat().st_mode & 0o077:
                raise ContractError("Private operator control directory required")
            if not trial.await_operator(directory):
                result["stopped_before_response"] = True
                return
        else:
            time.sleep(args.start_delay)
        trial.inject_and_bind()
        time.sleep(4)
        for action in (
            "apply_isolation",
            "activate_replacement",
            "verify_replacement",
            "switch_route",
        ):
            trial.execute(action)
            print("Confirmed owned trial step: " + action, flush=True)
            time.sleep(4)
        result["response_verified"] = True
        until = min(now() + timedelta(seconds=args.hold_seconds), trial.deadline)
        while now() < until:
            if args.operator_control and trial.stop_requested(args.operator_control):
                break
            trial.publish("watch", record_event=False)
            time.sleep(6)
    except Exception as error:
        result.update(response_verified=False, error_type=type(error).__name__)
        raise
    finally:
        result["cleanup"] = trial.close()
        atomic_json(args.state / "result.private.json", result)


if __name__ == "__main__":
    main()
