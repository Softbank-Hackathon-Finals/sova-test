"""Owned demo setup step; invoked by security_demo.py, never from HTTP."""

import sys
import os
import signal
from psycopg.conninfo import make_conninfo
from pathlib import Path
import json
import subprocess
import time
import re
import psycopg
from psycopg import sql

root = Path(sys.argv[1]).resolve()
db = json.loads((root / "control-db.json").read_text())
project = Path(__file__).resolve().parents[2]
with psycopg.connect(db["admin_dsn"], autocommit=True) as conn:
    conn.execute(
        (
            project / "src/sova/adapters/sql/postgres_security_response_v1.sql"
        ).read_text()
    )
    conn.execute(
        (
            project / "src/sova/adapters/sql/postgres_security_response_v2.sql"
        ).read_text()
    )
    for role in ("sova_response_admitter", "sova_response_worker"):
        if not conn.execute(
            "SELECT 1 FROM pg_roles WHERE rolname=%s", (role,)
        ).fetchone():
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
                ).format(sql.Identifier(role))
            )
        conn.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        conn.execute(
            sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        conn.execute(
            sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
    for table in (
        "plans",
        "approvals",
        "lifecycle_audit",
        "operations",
        "operation_outbox",
        "operation_events",
    ):
        conn.execute(
            sql.SQL("GRANT INSERT ON sova_control.{} TO sova_response_admitter").format(
                sql.Identifier(table)
            )
        )
    conn.execute(
        "GRANT UPDATE(revision,revoked_at) ON sova_control.approvals TO sova_response_admitter"
    )
    for table in (
        "app_execution",
        "effects",
        "effect_events",
        "execution_events",
        "operation_events",
        "security_event_log",
        "security_routes",
        "security_response_completions",
    ):
        conn.execute(
            sql.SQL("GRANT INSERT ON sova_control.{} TO sova_response_worker").format(
                sql.Identifier(table)
            )
        )
    for table, columns in [
        (
            "app_execution",
            "operation_id,owner_id,token,epoch,valid_until,mode,proof_digest,proof_valid_until,recovery_effects",
        ),
        ("effects", "status,revision,observation_document"),
        ("operations", "status,revision,updated_at"),
        ("operation_outbox", "suppressed_at,lease_token,lease_until,owner_id"),
        ("security_routes", "target_environment,revision,plan_digest,updated_at"),
    ]:
        conn.execute(
            sql.SQL(
                "GRANT UPDATE({}) ON sova_control.{} TO sova_response_worker"
            ).format(sql.SQL(columns), sql.Identifier(table))
        )
    conn.execute("GRANT SELECT ON sova_control.security_routes TO sova_security_viewer")
    # SELECT FOR SHARE on approval needs UPDATE privilege; scoped worker cannot edit content.
    conn.execute(
        "GRANT UPDATE(lock_guard) ON sova_control.approvals TO sova_response_worker"
    )

for name, role in [
    ("admitter", "sova_response_admitter"),
    ("worker", "sova_response_worker"),
]:
    db[name + "_dsn"] = make_conninfo(db["admin_dsn"], user=role)
(root / "control-db.json").write_text(json.dumps(db, indent=2))
(root / "control-db.json").chmod(0o600)
manifest = json.loads((root / "workloads.json").read_text())
code = next(
    x
    for x in manifest["items"]
    if x["kind"] == "ConfigMap" and x["metadata"]["namespace"] == "sova-live-observer"
)["data"]["main.py"]
needle = (
    "  query=parse_qs(urlsplit(self.path).query);target=query.get('target',['blue'])[0]"
)
replacement = """  if urlsplit(self.path).path=='/health':
   raw=json.dumps({'ok':True,'probe':'alive'}).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
  query=parse_qs(urlsplit(self.path).query);target=query.get('target',['blue'])[0]"""
if needle not in code:
    raise RuntimeError("Pinned probe code does not match preparation contract")
code = code.replace(needle, replacement)
code = code.replace(
    "connection=http.client.HTTPConnection(TARGETS[target],8080,timeout=1)",
    "connection=http.client.HTTPConnection(TARGETS[target],8080,timeout=1);connected=False",
)
code = code.replace(
    "   connection.request('GET','/health'",
    "   connection.connect();connected=True;connection.request('GET','/health'",
)
code = code.replace(
    "'upstream_status':response.status",
    "'connected':connected,'upstream_status':response.status",
)
code = code.replace(
    "'error':'upstream_unreachable'",
    "'error':'upstream_unreachable','connected':connected",
)
cm = {
    "apiVersion": "v1",
    "kind": "ConfigMap",
    "metadata": {"namespace": "sova-live-observer", "name": "probe-code"},
    "data": {"main.py": code},
}
kube = [
    "kubectl",
    "--kubeconfig",
    str(root / "admin-kubeconfig.json"),
    "--request-timeout=15s",
]
for args, body in [
    (["apply", "-f", "-"], json.dumps(cm)),
    (["-n", "sova-live-observer", "rollout", "restart", "deployment/probe"], None),
    (
        [
            "-n",
            "sova-live-observer",
            "rollout",
            "status",
            "deployment/probe",
            "--timeout=60s",
        ],
        None,
    ),
]:
    p = subprocess.run(
        kube + args, input=body, capture_output=True, text=True, timeout=75
    )
    if p.returncode:
        raise RuntimeError("Probe preparation failed")

old = root / "probe-forward.json"
if old.exists():
    previous = json.loads(old.read_text())
    command = subprocess.run(
        ["ps", "-p", str(previous["pid"]), "-o", "command="],
        capture_output=True,
        text=True,
    ).stdout
    if "port-forward" in command and str(root / "admin-kubeconfig.json") in command:
        os.kill(previous["pid"], signal.SIGTERM)
log = (root / "probe-forward.log").open("wb")
p = subprocess.Popen(
    kube
    + [
        "-n",
        "sova-live-observer",
        "port-forward",
        "--address=127.0.0.1",
        "service/probe",
        ":8080",
    ],
    stdin=subprocess.DEVNULL,
    stdout=log,
    stderr=log,
    start_new_session=True,
)
# Register the child before waiting for readiness so failed setup can stop it.
(root / "probe-forward.json").write_text(json.dumps({"pid": p.pid, "port": None}))
for _ in range(100):
    content = (root / "probe-forward.log").read_text()
    match = re.search(r"Forwarding from 127\.0\.0\.1:(\d+) -> 8080", content)
    if match:
        break
    if p.poll() is not None:
        raise RuntimeError("Probe forward stopped")
    time.sleep(0.1)
else:
    raise RuntimeError("Probe forward timeout")
(root / "probe-forward.json").write_text(
    json.dumps(
        {
            "pid": p.pid,
            "port": int(match[1]),
            "url": "http://127.0.0.1:" + match[1],
            "scope": "owned observer only",
        },
        indent=2,
    )
    + "\n"
)
print("Purpose-specific worker roles and independent probe path ready.")
