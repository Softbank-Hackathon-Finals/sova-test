"""Fixed, owned local response effects; no UI-selected shell or provider."""

import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from .contracts import now, require
from .manifests import (
    ISOLATABLE,
    NAMESPACES,
    PROFILE,
    boundary_selector,
    host,
    meta,
    role_allow,
)
from .provision import private_json


class ResponseOperations:
    def set_image(self, side, role, version):
        image = self.image(side, version)
        container = self.container(side, role)
        container["image"] = image
        self.kube.patch(
            side,
            "deployment",
            role,
            {"spec": {"template": {"spec": {"containers": [container]}}}},
        )
        self.kube.wait(side, role)

    def inject(self):
        s = self.state["scenario"]
        if s in {"isolate", "segment"}:
            nonce = secrets.token_hex(16)
            attempt = self.admin("source", "worker", "attempt", {"nonce": nonce})
            audit = self.kube.request(
                "source", "auth", "/audit", admin=self.settings["admin"]
            )
            require(
                attempt.get("body", {}).get("upstream_status") == 403
                and any(
                    item["nonce"] == nonce and item["status"] == 403
                    for item in audit.get("body", {}).get("events", [])
                ),
                "denial_and_independent_audit_required",
            )
            self.state["evidence"]["injection"] = {"attempt": attempt, "audit": audit}
        elif s == "egress":
            baseline = self.admin("source", "worker", "check", {"target": "external"})
            require(
                baseline.get("body", {}).get("status") == 200,
                "egress_baseline_required",
            )
            self.state["evidence"]["egress_baseline"] = baseline
        elif s == "restart":
            require(
                self.admin("source", "worker", "fault", {"enabled": True})["status"]
                == 200
            )
            require(
                self.kube.request("source", "worker")["status"] == 503,
                "worker_fault_not_observed",
            )
            self.state["evidence"]["restart_jobs"] = self.seed_jobs(6, "restart")
        elif s == "rollback":
            self.set_image("source", "api", "bad")
            require(
                self.kube.request("source", "api", "/messages")["status"] == 500,
                "regression_not_observed",
            )
        elif s == "patch":
            check = self.kube.request("source", "api", "/security-check")
            require(
                check.get("body", {}).get("legacy_feature_enabled") is True,
                "controlled_legacy_feature_required",
            )
            self.state["evidence"]["security_baseline"] = check
        elif s == "scale":
            require(
                self.admin("source", "worker", "fault", {"enabled": True})["status"]
                == 200
            )
            for index in range(16):
                self.sql(
                    "source",
                    "INSERT INTO jobs(id,body) VALUES(%s,%s)",
                    [secrets.token_hex(16), "local-scale-job-" + str(index)],
                )
            self.state["evidence"]["queue_before"] = self.fingerprint("source")
        elif s == "credentials":
            require(
                self.kube.sql("source", "SELECT 1", password=self.settings["password"])[
                    "ok"
                ],
                "credential_baseline_required",
            )
            self.state["evidence"]["credential_baseline"] = {"current_login": True}
        elif s == "migrate":
            require(self.kube.request("source", "api", "/messages")["status"] == 200)
            self.state["evidence"]["migration_source"] = self.fingerprint("source")

    def policy(self, roles=(), *, egress=False, recovery=False):
        """Set each isolatable role's own allow policy; selectors never move.

        `roles` get the isolated (or egress-limited, or recovery) rules and the
        others get normal rules. Enforcement is observed separately, because
        policy agents program the dataplane asynchronously.
        """
        mode = "recovery" if recovery else "egress" if egress else "isolated"
        node_ips = (self.settings.get("aws") or {}).get("node_ips")
        # One-time convergence from the earlier selector-edit model.
        converge = [("namespace-boundary", boundary_selector("source"))]
        if PROFILE["name"] == "hybrid-aws":
            converge.append(
                (
                    "bridge-ingress",
                    {
                        "matchExpressions": [
                            {"key": "sova.io/role", "operator": "In", "values": ["db"]}
                        ]
                    },
                )
            )
        for name, selector in converge:
            current = self.kube.get("source", "networkpolicy", name)
            if current["spec"]["podSelector"] != selector:
                current.pop("status", None)
                current["spec"]["podSelector"] = selector
                self.kube.apply(current)
        for role in ISOLATABLE:
            self.kube.apply(
                role_allow(role, mode if role in roles else "normal", node_ips)
            )
        for role in ISOLATABLE:
            self.kube.delete_legacy_policy("source", "isolate-" + role)
        self.state["evidence"]["policy_roles"] = list(roles)

    def set_writer(self, side, enabled):
        self.sql(side, "ALTER ROLE app " + ("LOGIN" if enabled else "NOLOGIN"))
        if not enabled:
            self.sql(
                side,
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='app' AND pid<>pg_backend_pid()",
            )
        require(
            self.admin(side, "api", "write", {"enabled": enabled})["status"] == 200,
            "app_write_gate_unconfirmed",
        )

    def respond(self):
        s = self.state["scenario"]
        if s in {"isolate", "segment"}:
            roles = ("api", "worker") if s == "segment" else ("worker",)
            with ThreadPoolExecutor(max_workers=2) as pool:
                streams = self.open_streams(pool, roles)
                require(
                    all(not future.done() for future in streams.values()),
                    "existing_connection_baseline_lost",
                )
                self.policy(roles)
                denials = {}
                for role in roles:
                    response = self.denied_while_running(role)
                    require(
                        response["status"] is None and bool(self.pods("source", role)),
                        "running_pod_ingress_denial_unconfirmed",
                    )
                    denials[role] = response
                    self.kube.scale("source", role, 0)
                    self.kube.wait("source", role)
                receipts = {
                    role: future.result(timeout=20) for role, future in streams.items()
                }
                require(
                    all(
                        receipt.get("opened")
                        and receipt.get("ended")
                        and receipt.get("pod_uid")
                        in self.state["evidence"]["before_uids"]["source"][role]
                        for role, receipt in receipts.items()
                    ),
                    "existing_connection_fencing_unconfirmed",
                )
                self.state["evidence"]["stream_fencing"] = receipts
                self.state["evidence"]["running_pod_ingress_denials"] = denials
            if s == "segment":
                # Replacement uses the same preserved DB; migration is separate.
                self.kube.patch(
                    "target",
                    "deployment",
                    "api",
                    {
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        self.container(
                                            "target",
                                            "api",
                                            db_host=host("target", "db", "source"),
                                        )
                                    ]
                                }
                            }
                        }
                    },
                )
                self.kube.scale("target", "api", 1)
                self.kube.wait("target", "api")
                self.kube.patch(
                    "target",
                    "deployment",
                    "worker",
                    {
                        "spec": {
                            "template": {
                                "spec": {
                                    "containers": [
                                        self.container(
                                            "target",
                                            "worker",
                                            db_host=host("target", "db", "source"),
                                        )
                                    ]
                                }
                            }
                        }
                    },
                )
                self.kube.scale("target", "worker", 1)
                self.kube.wait("target", "worker")
        elif s == "egress":
            self.policy(("worker",), egress=True)
            # Existing connections are ended by replacing only this worker Pod.
            self.restart("source", "worker")
        elif s == "credentials":
            self.rotate()
        elif s == "patch":
            self.set_image("source", "api", "v2")
            require(
                self.admin("source", "api", "write", {"enabled": True})["status"] == 200
            )
        elif s == "restart":
            self.restart("source", "worker")
        elif s == "scale":
            # A faulted worker fails readiness and leaves the Service, so the
            # Service name no longer reaches it. Clear the fault on each pod.
            cleared = self.admin_each_pod(
                "source", "worker", "fault", {"enabled": False}
            )
            require(
                all(item["status"] == 200 for item in cleared.values()),
                "worker_fault_clear_unconfirmed",
            )
            self.state["evidence"]["scale_fault_cleared"] = sorted(cleared)
            self.kube.scale("source", "worker", 2)
            self.kube.wait("source", "worker")
            self.state["evidence"]["scale_distribution_jobs"] = self.seed_jobs(
                16, "distribution"
            )
        elif s == "rollback":
            self.set_image("source", "api", "v1")
            require(
                self.admin("source", "api", "write", {"enabled": True})["status"] == 200
            )
        elif s == "migrate":
            self.migrate_prepare()

    def container(self, side, role, *, db_host=None):
        value = self.kube.get(side, "deployment", role)["spec"]["template"]["spec"][
            "containers"
        ][0]
        if db_host:
            for env in value["env"]:
                if env["name"] == "DB_HOST":
                    env["value"] = db_host
        return value

    def open_streams(self, pool, roles):
        code = r"""
import json,sys,pathlib,time,urllib.request,socket
v=json.load(sys.stdin);path=pathlib.Path('/tmp/sova-stream-'+v['run']+'-'+v['role']+'.json')
result={'opened':False,'ended':False}
try:
 with urllib.request.urlopen('http://'+v['host']+':8080/stream',timeout=4) as response:
  first=json.loads(response.readline(4096));result.update(opened=True,pod_uid=first['pod_uid'],frames=1)
  path.write_text(json.dumps(result))
  end=time.monotonic()+35
  while time.monotonic()<end:
   line=response.readline(4096)
   if not line:result.update(ended=True,reason='peer_eof');break
   value=json.loads(line)
   if value.get('pod_uid')!=first['pod_uid']:raise ValueError()
   result['frames']+=1
except (TimeoutError,socket.timeout):result.update(ended=result['opened'],reason='stream_stopped_and_probe_closed_socket')
except (ConnectionResetError,OSError):result.update(ended=result['opened'],reason='peer_reset_or_disconnect')
except Exception:result.update(ended=False,reason='unconfirmed')
path.write_text(json.dumps(result));print(json.dumps(result))
"""
        reader = "import json,pathlib,sys;v=json.load(sys.stdin);p=pathlib.Path('/tmp/sova-stream-'+v['run']+'-'+v['role']+'.json');print(p.read_text() if p.exists() else '{}')"
        futures = {}
        for role in roles:
            value = {
                "run": self.state["run_id"],
                "role": role,
                "host": role + "." + NAMESPACES["source"],
            }
            future = pool.submit(
                lambda value=value: json.loads(self.kube.probe("source", code, value))
            )
            until = time.monotonic() + 10
            opened = False
            while time.monotonic() < until:
                receipt = json.loads(self.kube.probe("source", reader, value))
                if receipt.get("opened"):
                    opened = True
                    break
                if future.done():
                    break
                time.sleep(0.2)
            require(opened, "existing_stream_not_established")
            futures[role] = future
        return futures

    def denied_while_running(self, role, timeout=45):
        """Wait, bounded, until the running pod is observed refusing new
        connections. Policy agents program the dataplane asynchronously (the
        EKS VPC CNI takes seconds), so a write alone is not enforcement."""
        until = time.monotonic() + timeout
        attempts = 0
        while True:
            attempts += 1
            response = self.kube.request("source", role)
            if response["status"] is None or time.monotonic() >= until:
                response["attempts"] = attempts
                return response
            time.sleep(2)

    def admin_each_pod(self, side, role, path, body):
        """Send an admin call to every current pod by IP, bypassing the Service."""
        pods = [
            pod
            for pod in self.pods(side, role)
            if not pod["metadata"].get("deletionTimestamp")
        ]
        require(pods, "pod_required")
        results = {}
        for pod in pods:
            address = pod.get("status", {}).get("podIP")
            require(address, "pod_address_unconfirmed")
            results[pod["metadata"]["uid"]] = self.kube.request(
                side,
                role,
                "/admin/" + path,
                body=body,
                admin=self.settings["admin"],
                host_ip=address,
            )
        return results

    def restart(self, side, role):
        self.kube.patch(
            side,
            "deployment",
            role,
            {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {"sova.io/restart": secrets.token_hex(8)}
                        }
                    }
                }
            },
        )
        self.kube.wait(side, role)

    def seed_jobs(self, count, label):
        require(1 <= count <= 32, "bounded_jobs_required")
        ids = []
        for index in range(count):
            job_id = secrets.token_hex(16)
            self.sql(
                "source",
                "INSERT INTO jobs(id,body) VALUES(%s,%s)",
                [job_id, "local-" + label + "-" + str(index)],
            )
            ids.append(job_id)
        return ids

    def rotate(self):
        old = self.settings["password"]
        new = secrets.token_hex(24)
        # Persist recovery material before changing either DB. Never expose values.
        private_json(
            self.root / "rotation.private.json", {"old": old, "new": new, "at": now()}
        )
        code = r"""
import json,sys,psycopg,pathlib
from psycopg import sql
v=json.load(sys.stdin)
with psycopg.connect(host=v['host'],dbname='workload',user='postgres',password=pathlib.Path('/credentials/dbadmin').read_text().strip(),connect_timeout=3) as c:c.execute(sql.SQL('ALTER ROLE app PASSWORD {}').format(sql.Literal(v['password'])))
print(json.dumps({'rotated':True}))
"""
        for side in ("source", "target"):
            require(
                json.loads(
                    self.kube.probe(
                        side,
                        code,
                        {"host": "db." + NAMESPACES[side], "password": new},
                    )
                )["rotated"]
            )
        for side, ns in NAMESPACES.items():
            self.kube.apply(
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": meta("workload-credentials", ns),
                    "stringData": {
                        "password": new,
                        "admin": self.settings["admin"],
                        "dbadmin": self.settings["dbadmin"],
                    },
                },
                side=side,
            )
        self.settings["password"] = new
        private_json(self.root / "settings.private.json", self.settings)
        for role in ("api", "worker"):
            self.restart("source", role)
        for side in self.kube.probe_sides():
            self.restart(side, "probe")
        self.state["evidence"]["credential_old_denied"] = not self.kube.sql(
            "source", "SELECT 1", password=old
        )["ok"]
        self.state["evidence"]["credential_new_allowed"] = self.kube.sql(
            "source", "SELECT 1", password=new
        )["ok"]
        require(
            self.admin("source", "api", "write", {"enabled": True})["status"] == 200
        )

    def migrate_prepare(self):
        self.state["evidence"]["migration_authority"] = "source"
        self.save()
        self.kube.scale("source", "worker", 0)
        self.kube.wait("source", "worker")
        self.set_writer("source", False)
        # Target is not serving traffic. Fence it while replacing only owned test rows.
        self.sql("target", "ALTER ROLE app NOLOGIN")
        self.kube.patch(
            "target",
            "deployment",
            "api",
            {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                self.container(
                                    "target",
                                    "api",
                                    db_host="db." + NAMESPACES["target"],
                                )
                            ]
                        }
                    }
                }
            },
        )
        self.copy_data("source", "target")
        self.kube.scale("target", "api", 1)
        self.kube.wait("target", "api")
        self.state["evidence"]["source_fingerprint"] = self.fingerprint("source")
        self.state["evidence"]["target_fingerprint"] = self.fingerprint("target")
        self.state["evidence"]["migration_kind"] = (
            "bounded stop-and-copy between local PostgreSQL databases; no cloud migration or CDC claim"
        )

    def copy_data(self, source, target):
        require(
            source in {"source", "target"}
            and target in {"source", "target"}
            and source != target
        )
        messages = self.sql(
            source, 'SELECT id,body FROM messages ORDER BY id COLLATE "C"'
        )
        jobs = self.sql(
            source, 'SELECT id,body,completed FROM jobs ORDER BY id COLLATE "C"'
        )
        require(len(messages) + len(jobs) < 2000, "bounded_dataset_required")
        code = r"""
import json,sys,psycopg,pathlib
v=json.load(sys.stdin)
with psycopg.connect(host=v['host'],dbname='workload',user='postgres',password=pathlib.Path('/credentials/dbadmin').read_text().strip(),connect_timeout=3) as c:
 c.execute('TRUNCATE messages,jobs')
 with c.cursor() as cur:
  cur.executemany('INSERT INTO messages(id,body) VALUES(%s,%s)',v['messages'])
  cur.executemany('INSERT INTO jobs(id,body,completed) VALUES(%s,%s,%s)',v['jobs'])
print(json.dumps({'copied':True}))
"""
        require(
            json.loads(
                self.kube.probe(
                    target,
                    code,
                    {
                        "host": "db." + NAMESPACES[target],
                        "messages": messages,
                        "jobs": jobs,
                    },
                )
            )["copied"]
        )
        require(
            self.fingerprint(source) == self.fingerprint(target), "copied_data_mismatch"
        )

    def verify(self):
        s = self.state["scenario"]
        checks = []

        def check(name, passed, evidence=None):
            checks.append(
                {
                    "name": name,
                    "passed": bool(passed),
                    "evidence": evidence,
                    "at": now(),
                }
            )

        if s in {"isolate", "segment"}:
            roles = ("api", "worker") if s == "segment" else ("worker",)
            for role in roles:
                check(role + "_old_pods_gone", not self.pods("source", role))
                check(
                    role + "_new_connection_denied",
                    self.kube.request("source", role)["status"] is None,
                )
                check(
                    role + "_existing_stream_fenced",
                    self.state["evidence"]
                    .get("stream_fencing", {})
                    .get(role, {})
                    .get("ended")
                    is True,
                    self.state["evidence"].get("stream_fencing", {}).get(role),
                )
            check(
                "neighbor_auth_healthy",
                self.kube.request("source", "auth")["status"] == 200,
            )
            check(
                "object_path_healthy",
                self.kube.request("source", "objects")["status"] == 200,
            )
            if s == "isolate":
                check(
                    "api_continues",
                    self.kube.request("source", "api", "/messages")["status"] == 200,
                )
            else:
                check(
                    "replacement_http",
                    self.kube.request("target", "api", "/messages")["status"] == 200,
                )
                check(
                    "replacement_worker_http",
                    self.kube.request("target", "worker")["status"] == 200,
                )
        elif s == "egress":
            external = self.admin("source", "worker", "check", {"target": "external"})
            db = self.admin("source", "worker", "check", {"target": "db"})
            check(
                "controlled_external_endpoint_unreachable",
                external.get("body", {}).get("status") is None
                and external["status"] == 200,
                external,
            )
            check(
                "database_connection_preserved",
                db.get("body", {}).get("connected") is True,
                db,
            )
            check(
                "old_connections_fenced_by_pod_replacement",
                self.state["evidence"]["before_uids"]["source"]["worker"]
                != self.current_uids()["source"]["worker"],
            )
        elif s == "credentials":
            check(
                "previous_credential_rejected",
                self.state["evidence"].get("credential_old_denied"),
            )
            check(
                "new_credential_accepted",
                self.state["evidence"].get("credential_new_allowed"),
            )
            check(
                "business_read",
                self.kube.request("source", "api", "/messages")["status"] == 200,
            )
        elif s in {"patch", "rollback"}:
            expected = "v2" if s == "patch" else "v1"
            response = self.kube.request("source", "api", "/messages")
            check(
                "business_http",
                response["status"] == 200
                and response.get("body", {}).get("release") == expected,
                response,
            )
            pods = self.pods("source", "api")
            image = self.image("source", expected)
            check(
                "exact_image_spec",
                bool(pods)
                and all(p["spec"]["containers"][0]["image"] == image for p in pods),
            )
            check(
                "runtime_manifest_digest_matches",
                bool(pods)
                and all(
                    p.get("status", {})
                    .get("containerStatuses", [{}])[0]
                    .get("imageID", "")
                    .endswith("@" + image.split("@", 1)[1])
                    for p in pods
                ),
                [
                    p.get("status", {}).get("containerStatuses", [{}])[0].get("imageID")
                    for p in pods
                ],
            )
            if s == "patch":
                check(
                    "controlled_security_regression_closed",
                    self.kube.request("source", "api", "/security-check")
                    .get("body", {})
                    .get("legacy_feature_enabled")
                    is False,
                )
        elif s == "restart":
            require(self.wait_queue(), "restarted_worker_queue_unconfirmed")
            check(
                "new_worker_uid",
                self.state["evidence"]["before_uids"]["source"]["worker"]
                != self.current_uids()["source"]["worker"],
            )
            check("worker_http", self.kube.request("source", "worker")["status"] == 200)
            jobs = self.sql(
                "source",
                "SELECT count(*),count(DISTINCT id),bool_and(completed) FROM jobs WHERE id=ANY(%s)",
                [self.state["evidence"]["restart_jobs"]],
            )
            check(
                "durable_jobs_completed_without_duplicate_ids",
                jobs == [[6, 6, True]],
                jobs,
            )
        elif s == "scale":
            require(self.wait_queue(), "queue_drain_unconfirmed")
            workers = self.pods("source", "worker")
            check(
                "two_ready_workers",
                len(workers) == 2
                and all(
                    any(
                        c["type"] == "Ready" and c["status"] == "True"
                        for c in p.get("status", {}).get("conditions", [])
                    )
                    for p in workers
                ),
            )
            counts = self.sql(
                "source",
                "SELECT worker_uid,count(*) FROM jobs WHERE completed GROUP BY worker_uid",
            )
            check(
                "queue_drained",
                self.fingerprint("source")["completed"]
                == self.fingerprint("source")["jobs"],
                counts,
            )
            distribution = self.sql(
                "source",
                "SELECT worker_uid,count(*) FROM jobs WHERE completed AND id=ANY(%s) GROUP BY worker_uid",
                [self.state["evidence"]["scale_distribution_jobs"]],
            )
            check(
                "work_processed_by_two_current_pods",
                len(distribution) == 2
                and {row[0] for row in distribution}
                == {p["metadata"]["uid"] for p in workers},
                distribution,
            )
        elif s == "migrate":
            source, target = self.fingerprint("source"), self.fingerprint("target")
            check(
                "final_data_fingerprint",
                source == target,
                {"source": source, "target": target},
            )
            check(
                "both_app_logins_fenced",
                all(
                    not self.kube.sql(
                        side, "SELECT 1", password=self.settings["password"]
                    )["ok"]
                    for side in ("source", "target")
                ),
            )
            check(
                "target_http_ready", self.kube.request("target", "api")["status"] == 200
            )
        self.state["checks"] = checks
        require(
            checks and all(item["passed"] for item in checks), "actual_checks_failed"
        )

    def wait_queue(self):
        until = time.monotonic() + 40
        while time.monotonic() < until:
            value = self.fingerprint("source")
            if value["completed"] == value["jobs"]:
                return True
            time.sleep(1)
        return False

    def finalize(self):
        s = self.state["scenario"]
        if s == "segment":
            require(
                self.admin("source", "api", "write", {"enabled": False})["status"]
                is None
                or not self.pods("source", "api")
            )
            require(
                self.admin("target", "api", "write", {"enabled": True})["status"] == 200
            )
            require(
                self.admin("control", "edge", "route", {"route": "target"})["status"]
                == 200
            )
        if s == "migrate":
            require(
                self.fingerprint("source") == self.fingerprint("target"),
                "last_barrier_mismatch",
            )
            require(
                not self.kube.sql(
                    "source", "SELECT 1", password=self.settings["password"]
                )["ok"],
                "source_writer_not_fenced",
            )
            self.state["evidence"]["migration_authority"] = "target_pending"
            self.save()
            self.set_writer("target", True)
            self.state["evidence"]["migration_authority"] = "target"
            self.save()
            require(
                self.admin("control", "edge", "route", {"route": "target"})["status"]
                == 200
            )
            self.kube.scale("target", "worker", 1)
            self.kube.wait("target", "worker")
        if s in {"migrate", "segment"}:
            entry = self.kube.request("control", "edge", "/messages")
            require(
                entry["status"] == 200
                and entry.get("body", {}).get("environment") == "local-target",
                "entry_route_unconfirmed",
            )
            canary = {
                "id": secrets.token_hex(16),
                "body": "대응 후 실제 로컬 업무 쓰기 확인",
            }
            require(
                self.kube.request("control", "edge", "/messages", body=canary)["status"]
                == 200,
                "new_write_unconfirmed",
            )
            self.state["evidence"]["entry_after"] = entry
            self.state["evidence"]["post_change_message_id"] = canary["id"]

    def recover_prepare(self):
        roles = (
            ("api", "worker") if self.state["scenario"] == "segment" else ("worker",)
        )
        self.policy(roles, recovery=True)
        for role in (
            ("api", "worker") if self.state["scenario"] == "segment" else ("worker",)
        ):
            self.kube.scale("source", role, 1)
            self.kube.wait("source", role)
            require(
                self.kube.request("source", role)["status"] == 200,
                "original_response_unconfirmed",
            )

    def recover_finalize(self):
        require(self.kube.request("source", "api", "/messages")["status"] == 200)
        require(
            self.admin("target", "api", "write", {"enabled": False})["status"]
            in {200, None}
        )
        require(
            self.admin("source", "api", "write", {"enabled": True})["status"] == 200
        )
        self.policy(())
        require(
            self.admin("control", "edge", "route", {"route": "source"})["status"] == 200
        )
        self.kube.scale("target", "api", 0)
        require(self.kube.request("control", "edge", "/messages")["status"] == 200)
        self.kube.scale("target", "worker", 0)

    def reset(self):
        # Resource recovery, not history deletion. User data and journals survive.
        scenario = self.state["scenario"]
        # A completed local migration may have accepted new destination writes.
        # Preserve them before returning the entry to the source. Never merely
        # reopen the stale source DB or treat a traffic rollback as data recovery.
        authority = self.state.get("evidence", {}).get("migration_authority")
        if scenario == "migrate" and authority:
            login = {
                side: self.sql(
                    side, "SELECT rolcanlogin FROM pg_roles WHERE rolname='app'"
                )[0][0]
                for side in ("source", "target")
            }
            if authority in {"target", "target_pending"}:
                require(
                    not login["source"] and login["target"],
                    "writer_authority_ambiguous",
                )
            else:
                require(authority == "source", "writer_authority_ambiguous")
            for side in ("source", "target"):
                self.kube.scale(side, "worker", 0)
                self.kube.wait(side, "worker")
                self.sql(side, "ALTER ROLE app NOLOGIN")
                self.sql(
                    side,
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename='app'",
                )
            post_change_id = self.state.get("evidence", {}).get(
                "post_change_message_id"
            )
            if authority in {"target", "target_pending"}:
                if post_change_id:
                    require(
                        self.sql(
                            "target",
                            "SELECT count(*) FROM messages WHERE id=%s",
                            [post_change_id],
                        )
                        == [[1]],
                        "destination_write_missing",
                    )
                self.copy_data("target", "source")
            else:
                # Before promotion the source remains authoritative. Target data
                # is retained, but is never silently chosen as the writer.
                require(
                    not self.state.get("evidence", {}).get("entry_after"),
                    "writer_authority_ambiguous",
                )
        self.policy(())
        for side in ("source", "target"):
            self.sql(side, "ALTER ROLE app LOGIN")
            self.kube.scale(side, "worker", 0)
            self.kube.wait(side, "worker")
            self.kube.scale(side, "api", 1)
            self.set_image(side, "api", "v1")
            self.kube.patch(
                side,
                "deployment",
                "api",
                {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    self.container(
                                        side, "api", db_host="db." + NAMESPACES[side]
                                    )
                                ]
                            },
                            "metadata": {
                                "annotations": {"sova.io/reset": secrets.token_hex(8)}
                            },
                        }
                    }
                },
            )
            self.kube.wait(side, "api")
            require(
                self.admin(side, "api", "write", {"enabled": side == "source"})[
                    "status"
                ]
                == 200
            )
        require(
            self.admin("control", "edge", "route", {"route": "source"})["status"] == 200
        )
        self.kube.scale("target", "api", 0)
        self.kube.scale("source", "worker", 1)
        self.kube.wait("source", "worker")
        self.restart("source", "worker")
        revision = self.state["revision"]
        self.state = self.empty(scenario, revision)
        self.event(
            "normal",
            "로컬 원본 앱·DB·작업자·경로를 확인했습니다. 이전 기록과 데이터는 보존합니다.",
        )
