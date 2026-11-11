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
from . import registry


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
                == 200,
                "worker_fault_unconfirmed",
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
            self.state["evidence"]["image_scan_before"] = self.image_scan(
                self.container("source", "api")["image"]
            )
        elif s == "scale":
            require(
                self.admin("source", "worker", "fault", {"enabled": True})["status"]
                == 200,
                "worker_fault_unconfirmed",
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
            require(
                self.kube.request("source", "api", "/messages")["status"] == 200,
                "migration_source_unreadable",
            )
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
            with ThreadPoolExecutor(max_workers=1) as pool:
                holder = self.hold_old_session(pool)
                self.rotate()
                receipt = holder.result(timeout=120)
            require(
                receipt.get("opened") and receipt.get("terminated"),
                "pre_rotation_session_not_terminated",
            )
            self.state["evidence"]["pre_rotation_session"] = receipt
        elif s == "patch":
            self.set_image("source", "api", "v2")
            require(
                self.admin("source", "api", "write", {"enabled": True})["status"]
                == 200,
                "patched_write_gate_unconfirmed",
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
                self.admin("source", "api", "write", {"enabled": True})["status"]
                == 200,
                "rolled_back_write_gate_unconfirmed",
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

    def hold_old_session(self, pool):
        """Open an app session with the current (about to be old) credential
        from a neighbour pod that rotation does not restart, and keep it busy.
        Revocation must end it server-side; a login denial alone does not."""
        code = r"""
import json,sys,time,pathlib,psycopg
v=json.load(sys.stdin);p=pathlib.Path('/tmp/sova-session-'+v['run']+'.json')
r={'opened':False,'terminated':False}
try:
 with psycopg.connect(host=v['host'],dbname='workload',user='app',password=v['password'],connect_timeout=3,autocommit=True) as c:
  c.execute('SELECT 1');r.update(opened=True,opened_at=time.time());p.write_text(json.dumps(r))
  end=time.monotonic()+v['seconds']
  while time.monotonic()<end:
   time.sleep(0.5);c.execute('SELECT 1')
  r['reason']='still_open_at_deadline'
except psycopg.OperationalError:r.update(terminated=r['opened'],terminated_at=time.time(),reason='server_ended_session')
except Exception:r['reason']='unconfirmed'
p.write_text(json.dumps(r));print(json.dumps(r))
"""
        value = {
            "run": self.state["run_id"],
            "host": "db." + NAMESPACES["source"],
            "password": self.settings["password"],
            "seconds": 90,
        }
        reader = "import json,pathlib,sys;v=json.load(sys.stdin);p=pathlib.Path('/tmp/sova-session-'+v['run']+'.json');print(p.read_text() if p.exists() else '{}')"
        future = pool.submit(
            lambda: json.loads(self.kube.execute("source", "objects", code, value))
        )
        public = {"run": value["run"]}
        until = time.monotonic() + 20
        while time.monotonic() < until and not future.done():
            if json.loads(self.kube.execute("source", "objects", reader, public)).get(
                "opened"
            ):
                return future
            time.sleep(0.3)
        require(False, "pre_rotation_session_not_established")

    def exit_drill(self):
        """Source independence drill after a completed migration (§20, AT-35).

        Withdraw the only cross-cluster allow (hybrid), start a fresh target
        API, prove it starts with business writes closed (quarantined until
        authority is re-verified), re-verify the single writer, reopen and
        write and read through the entry. The bridge allow is restored after.
        """
        require(
            self.state["scenario"] == "migrate"
            and self.state["phase"] == "complete"
            and self.state["evidence"].get("migration_authority") == "target",
            "exit_drill_requires_completed_migration",
        )
        hybrid = PROFILE["name"] == "hybrid-aws"
        saved = {}
        drill = {"source_path_cut": hybrid, "started_at": now()}
        try:
            if hybrid:
                for side in ("target", "control"):
                    policy = self.kube.get(side, "networkpolicy", "bridge-egress")
                    policy.pop("status", None)
                    saved[side] = policy["spec"]["egress"]
                    policy["spec"]["egress"] = []
                    self.kube.apply(policy, side=side)
                require(
                    self.until_ok(lambda: not self.bridge_reachable("target")),
                    "source_path_cut_unconfirmed",
                )
            before = self.current_uids()["target"]["api"]
            self.restart("target", "api")
            after = self.current_uids()["target"]["api"]
            require(after and after != before, "fresh_target_instance_unconfirmed")
            probe = {
                "id": secrets.token_hex(16),
                "body": "출발지 차단 후 재기동 직후 쓰기",
            }
            quarantined = self.kube.request("control", "edge", "/messages", body=probe)
            require(
                quarantined["status"] == 503, "restarted_instance_opened_writes_early"
            )
            login = {
                side: self.sql(
                    side, "SELECT rolcanlogin FROM pg_roles WHERE rolname='app'"
                )[0][0]
                for side in ("source", "target")
            }
            require(
                login["target"] and not login["source"], "single_writer_unconfirmed"
            )
            require(
                self.admin("target", "api", "write", {"enabled": True})["status"]
                == 200,
                "target_write_gate_unconfirmed",
            )
            canary = {
                "id": secrets.token_hex(16),
                "body": "출발지 차단 상태의 새 업무 쓰기",
            }
            require(
                self.kube.request("control", "edge", "/messages", body=canary)["status"]
                == 200,
                "write_without_source_unconfirmed",
            )
            require(
                self.sql(
                    "target",
                    "SELECT count(*) FROM messages WHERE id=%s",
                    [canary["id"]],
                )
                == [[1]],
                "write_not_in_target_database",
            )
            require(
                self.kube.request("control", "edge", "/messages")["status"] == 200,
                "read_without_source_unconfirmed",
            )
            drill.update(
                fresh_instance=after,
                restart_quarantined=True,
                single_writer=login,
                write_and_read=True,
                states=[
                    "COMPUTE_INDEPENDENT",
                    "DATA_IDENTITY_INDEPENDENT",
                    "RESTART_VERIFIED",
                ]
                if hybrid
                else ["RESTART_VERIFIED"],
                completed_at=now(),
            )
            self.state["evidence"]["exit_drill"] = drill
        finally:
            for side, egress in saved.items():
                policy = self.kube.get(side, "networkpolicy", "bridge-egress")
                policy.pop("status", None)
                policy["spec"]["egress"] = egress
                self.kube.apply(policy, side=side)

    def bridge_reachable(self, side):
        code = (
            "import json,socket,sys;v=json.load(sys.stdin)\n"
            "try:\n socket.create_connection((v['host'],5432),timeout=3).close();print(json.dumps({'reachable':True}))\n"
            "except OSError:print(json.dumps({'reachable':False}))"
        )
        return json.loads(
            self.kube.execute(side, "api", code, {"host": host(side, "db", "source")})
        )["reachable"]

    def image_scan(self, image):
        """Registry findings for a pinned image; NOT_RUN where there is none."""
        if PROFILE["name"] != "hybrid-aws":
            return {"not_run": "no_registry_scan_in_local_topology"}
        try:
            return registry.scan(self.settings, image)
        except registry.ScanUnavailable as error:
            return {"unavailable": str(error)}

    def rescan_patched_image(self, check, image, controlled_closed):
        """A successful rollout is not a resolved finding (P-G5, P-AT-04)."""
        before = self.state["evidence"].get("image_scan_before", {})
        remediation = {
            "controlled_finding": "RESOLVED" if controlled_closed else "NOT_RESOLVED"
        }
        if "not_run" in before:
            remediation["image_findings"] = {"status": "NOT_RUN", **before}
        else:
            after = self.image_scan(image)
            rescanned = "findings" in before and "findings" in after
            check(
                "deployed_image_rescanned",
                rescanned and after["image_digest"] == image.split("@", 1)[1],
                {
                    k: after.get(k)
                    for k in ("image_digest", "completed_at", "unavailable")
                },
            )
            if rescanned:
                comparison = registry.compare(before, after)
                check(
                    "no_findings_introduced_by_patch",
                    not comparison["introduced"],
                    comparison["introduced_names"],
                )
                remediation["image_findings"] = {
                    # Remaining findings are residual risk, never "resolved".
                    "status": "NOT_RESOLVED" if comparison["remaining"] else "RESOLVED",
                    **comparison,
                }
        self.state["evidence"]["remediation"] = remediation

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
with psycopg.connect(host=v['host'],dbname='workload',user='postgres',password=pathlib.Path('/credentials/dbadmin').read_text().strip(),connect_timeout=3,autocommit=True) as c:
 c.execute(sql.SQL('ALTER ROLE app PASSWORD {}').format(sql.Literal(v['password'])))
 # A password change does not end sessions that already authenticated.
 ended=c.execute("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename='app'").fetchone()[0]
print(json.dumps({'rotated':True,'sessions_terminated':ended}))
"""
        ended = {}
        for side in ("source", "target"):
            result = json.loads(
                self.kube.probe(
                    side,
                    code,
                    {"host": "db." + NAMESPACES[side], "password": new},
                )
            )
            require(result.get("rotated"), "credential_rotation_unconfirmed")
            ended[side] = result.get("sessions_terminated")
        self.state["evidence"]["rotation_sessions_terminated"] = ended
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
            self.admin("source", "api", "write", {"enabled": True})["status"] == 200,
            "rotated_write_gate_unconfirmed",
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
            and source != target,
            "copy_direction_invalid",
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
            )["copied"],
            "copy_unconfirmed",
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
            session = self.state["evidence"].get("pre_rotation_session", {})
            check(
                "pre_rotation_session_terminated",
                session.get("opened") is True and session.get("terminated") is True,
                {k: session.get(k) for k in ("opened", "terminated", "reason")},
            )
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
                closed = (
                    self.kube.request("source", "api", "/security-check")
                    .get("body", {})
                    .get("legacy_feature_enabled")
                    is False
                )
                check("controlled_security_regression_closed", closed)
                self.rescan_patched_image(check, image, closed)
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
                or not self.pods("source", "api"),
                "source_write_gate_still_open",
            )
            require(
                self.admin("target", "api", "write", {"enabled": True})["status"]
                == 200,
                "replacement_write_gate_unconfirmed",
            )
            require(
                self.admin("control", "edge", "route", {"route": "target"})["status"]
                == 200,
                "entry_route_unconfirmed",
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
                == 200,
                "entry_route_unconfirmed",
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
        require(
            self.kube.request("source", "api", "/messages")["status"] == 200,
            "recovered_source_api_unconfirmed",
        )
        require(
            self.admin("target", "api", "write", {"enabled": False})["status"]
            in {200, None},
            "replacement_write_gate_unconfirmed",
        )
        require(
            self.admin("source", "api", "write", {"enabled": True})["status"] == 200,
            "source_write_gate_unconfirmed",
        )
        self.policy(())
        require(
            self.admin("control", "edge", "route", {"route": "source"})["status"]
            == 200,
            "entry_route_unconfirmed",
        )
        self.kube.scale("target", "api", 0)
        # The restored allow (including the bridge ingress in hybrid) reaches
        # the dataplane asynchronously; observe the entry, bounded.
        require(
            self.until_ok(
                lambda: (
                    self.kube.request("control", "edge", "/messages")["status"] == 200
                )
            ),
            "entry_to_recovered_source_unconfirmed",
        )
        self.kube.scale("target", "worker", 0)

    def until_ok(self, probe, timeout=45, interval=2):
        """Bounded readback of an effect that propagates asynchronously."""
        until = time.monotonic() + timeout
        while True:
            if probe():
                return True
            if time.monotonic() >= until:
                return False
            time.sleep(interval)

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
                == 200,
                "reset_write_gate_unconfirmed",
            )
        require(
            self.admin("control", "edge", "route", {"route": "source"})["status"]
            == 200,
            "entry_route_unconfirmed",
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
