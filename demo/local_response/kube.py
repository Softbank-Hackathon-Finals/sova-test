"""Pinned cluster adapter. Never uses the caller's current kube context.

Each side of the response (source, target, control) is placed on one pinned
cluster: the local RKE2 VM, or in the hybrid topology the run-owned EKS cluster
reached through a private kubeconfig. Every call names its side, and the
adapter checks the cluster identity and namespace ownership on that cluster.
"""

import json
import re
import subprocess
import time
from . import manifests
from .manifests import NAMESPACES, placement, probe_side

VM = "sova-rke2-target"
CLUSTER_UID = "9de35591-57a3-4759-bd73-6340e2de0b61"
PREFIX = [
    "limactl",
    "shell",
    VM,
    "sudo",
    "/var/lib/rancher/rke2/bin/kubectl",
    "--kubeconfig",
    "/etc/rancher/rke2/rke2.yaml",
    "--request-timeout=15s",
]


class Unconfirmed(RuntimeError):
    """An effect or its observation could not be confirmed; never auto-retry."""


def run(args, value=None, timeout=35, *, prefix=None, label="local"):
    result = subprocess.run(
        (prefix or PREFIX) + args,
        input=value,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode:
        # kubectl stderr may include credential payloads; keep it private.
        error = Unconfirmed(label + "_kubernetes_request_failed")
        error.private_detail = result.stderr
        raise error
    if len(result.stdout) > 2_000_000:
        raise Unconfirmed(label + "_response_too_large")
    return result.stdout


class Cluster:
    """One pinned cluster: a fixed kubectl invocation and its expected UID."""

    def __init__(self, name, prefix, uid):
        self.name, self.prefix, self.uid = name, prefix, uid

    def run(self, args, value=None, timeout=35):
        return run(args, value, timeout, prefix=self.prefix, label=self.name)


def eks_cluster(kubeconfig, context, uid):
    # Private kubeconfig whose user execs `aws eks get-token`; no static token.
    return Cluster(
        "aws",
        [
            "kubectl",
            "--kubeconfig",
            str(kubeconfig),
            "--context",
            context,
            "--request-timeout=15s",
        ],
        uid,
    )


class Kube:
    def __init__(self, clusters=None):
        self.clusters = clusters or {"local": Cluster("local", PREFIX, CLUSTER_UID)}

    @classmethod
    def from_settings(cls, settings):
        if settings.get("topology", "local") == "local":
            return cls()
        aws = settings["clusters"]["aws"]
        return cls(
            {
                "local": Cluster("local", PREFIX, settings["clusters"]["local"]["uid"]),
                "aws": eks_cluster(aws["kubeconfig"], aws["context"], aws["uid"]),
            }
        )

    def cluster(self, side):
        return self.clusters[placement(side)]

    def run(self, side, args, value=None, timeout=35):
        return self.cluster(side).run(args, value, timeout)

    def verify(self, name):
        cluster = self.clusters[name]
        value = json.loads(
            cluster.run(["get", "namespace", "kube-system", "-o", "json"])
        )
        if value["metadata"]["uid"] != cluster.uid:
            raise Unconfirmed(name + "_cluster_identity_mismatch")
        return cluster.uid

    def identity(self):
        found = {name: self.verify(name) for name in self.clusters}
        # The local-only topology keeps its original scalar identity.
        return found["local"] if list(found) == ["local"] else found

    def sides(self):
        return list(NAMESPACES)

    def probe_sides(self):
        return [side for side in NAMESPACES if side in {"control", "source-control"}]

    def owned(self, side):
        ns = NAMESPACES[side]
        value = json.loads(self.run(side, ["get", "namespace", ns, "-o", "json"]))
        if (
            value["metadata"].get("labels", {}).get("sova.io/owner")
            != manifests.PROFILE["owner"]
        ):
            raise Unconfirmed("namespace_ownership_mismatch")
        return value["metadata"]["uid"]

    def side_for(self, namespace, cluster):
        matches = [
            side
            for side, ns in NAMESPACES.items()
            if ns == namespace and placement(side) == cluster
        ]
        if len(matches) != 1:
            raise ValueError("namespace_out_of_scope")
        return matches[0]

    def apply(self, document, *, bootstrap=False, side=None):
        """Apply owned documents to one cluster: `side`'s, or the only one."""
        docs = document if isinstance(document, list) else [document]
        if side is not None:
            cluster = placement(side)
        elif len(self.clusters) == 1:
            cluster = next(iter(self.clusters))
        else:
            namespaces = {item.get("metadata", {}).get("namespace") for item in docs}
            candidates = {
                placement(s) for s, ns in NAMESPACES.items() if ns in namespaces
            }
            if None in namespaces or len(candidates) != 1:
                raise ValueError("cluster_side_required")
            cluster = candidates.pop()
        self.verify(cluster)
        for item in docs:
            metadata = item.get("metadata", {})
            if (
                metadata.get("labels", {}).get("sova.io/owner")
                != manifests.PROFILE["owner"]
            ):
                raise ValueError("owned_manifest_required")
            ns = metadata.get("namespace")
            if ns:
                owner_side = self.side_for(ns, cluster)
                if not bootstrap:
                    self.owned(owner_side)
        return self.clusters[cluster].run(
            ["apply", "-f", "-"],
            json.dumps({"apiVersion": "v1", "kind": "List", "items": docs}),
            timeout=90,
        )

    def get(self, side, kind, name=None):
        return json.loads(
            self.run(
                side,
                [
                    "-n",
                    NAMESPACES[side],
                    "get",
                    kind,
                    *([name] if name else []),
                    "-o",
                    "json",
                ],
            )
        )

    def patch(self, side, kind, name, patch):
        self.verify(placement(side))
        self.owned(side)
        old = self.get(side, kind, name)
        if (
            old["metadata"].get("labels", {}).get("sova.io/owner")
            != manifests.PROFILE["owner"]
        ):
            raise Unconfirmed("resource_ownership_mismatch")

        def merge(original, change):
            if not isinstance(change, dict):
                return change
            result = dict(original) if isinstance(original, dict) else {}
            for key, value in change.items():
                if value is None:
                    result.pop(key, None)
                else:
                    result[key] = merge(result.get(key), value)
            return result

        operations = [
            {"op": "test", "path": "/metadata/uid", "value": old["metadata"]["uid"]},
            {
                "op": "test",
                "path": "/metadata/resourceVersion",
                "value": old["metadata"]["resourceVersion"],
            },
        ]
        for key, value in patch.items():
            if key not in {"spec", "metadata"}:
                raise ValueError("bounded_patch_fields_required")
            operations.append(
                {
                    "op": "replace" if key in old else "add",
                    "path": "/" + key,
                    "value": merge(old.get(key), value),
                }
            )
        return json.loads(
            self.run(
                side,
                [
                    "-n",
                    NAMESPACES[side],
                    "patch",
                    kind,
                    name,
                    "--type=json",
                    "-p",
                    json.dumps(operations),
                    "-o",
                    "json",
                ],
            )
        )

    def scale(self, side, role, replicas):
        if role not in {"api", "worker"} or replicas not in {0, 1, 2}:
            raise ValueError("bounded_scale_required")
        return self.patch(side, "deployment", role, {"spec": {"replicas": replicas}})

    def wait(self, side, role, *, timeout=80):
        # Readiness is observed independently after the desired state write.
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            value = self.get(side, "deployment", role)
            count = value["spec"].get("replicas", 1)
            status = value.get("status", {})
            if (
                status.get("observedGeneration", 0) >= value["metadata"]["generation"]
                and status.get("updatedReplicas", 0) == count
                and status.get("readyReplicas", 0) == count
                and status.get("replicas", 0) == count
            ):
                if count == 0:
                    remaining = [
                        p
                        for p in self.get(side, "pods")["items"]
                        if p["metadata"].get("labels", {}).get("sova.io/role") == role
                    ]
                    if remaining:
                        time.sleep(1)
                        continue
                else:
                    remaining = [
                        p
                        for p in self.get(side, "pods")["items"]
                        if p["metadata"].get("labels", {}).get("sova.io/role") == role
                    ]
                    if len(remaining) != count or any(
                        p["metadata"].get("deletionTimestamp") for p in remaining
                    ):
                        time.sleep(1)
                        continue
                return value
            time.sleep(1)
        raise Unconfirmed("rollout_unconfirmed")

    def execute(self, side, role, code, value=None):
        if side not in NAMESPACES or not re.fullmatch("[a-z-]+", role):
            raise ValueError("registered_workload_required")
        # Check the cluster this call runs on; Runtime.identity() checks both.
        self.verify(placement(side))
        self.owned(side)
        return self.run(
            side,
            [
                "-n",
                NAMESPACES[side],
                "exec",
                "-i",
                "deployment/" + role,
                "--",
                "python",
                "-c",
                code,
            ],
            json.dumps(value),
            timeout=45,
        )

    def request(
        self, side, role, path="/health", *, body=None, admin=None, host_ip=None
    ):
        if not re.fullmatch(r"/[a-z/-]*", path):
            raise ValueError("fixed_path_required")
        host = host_ip or role + "." + NAMESPACES[side]
        value = {"host": host, "path": path, "body": body, "admin": admin}
        return json.loads(self.probe(side, HTTP_PROBE, value))

    def probe(self, side, code, value=None):
        """Run fixed probe code beside `side`, in the same cluster as it."""
        return self.execute(probe_side(side), "probe", code, value)

    def sql(self, side, sql, parameters=None, *, admin=False, password=None):
        # SQL text is generated by the fixed runtime, never accepted by the UI.
        return json.loads(
            self.probe(
                side,
                SQL_PROBE,
                {
                    "host": "db." + NAMESPACES[side],
                    "sql": sql,
                    "parameters": parameters or [],
                    "admin": admin,
                    "password": password,
                },
            )
        )


HTTP_PROBE = r"""
import json,sys,urllib.request,urllib.error,secrets
v=json.load(sys.stdin);nonce=secrets.token_hex(16)
h={'Content-Type':'application/json','X-Request-ID':nonce}
if v['admin']:h['Authorization']='Bearer '+v['admin']
r=urllib.request.Request('http://'+v['host']+':8080'+v['path'],data=None if v['body'] is None else json.dumps(v['body']).encode(),headers=h)
try:
 with urllib.request.urlopen(r,timeout=5) as x:out={'status':x.status,'body':json.loads(x.read(32768)),'nonce':nonce}
except urllib.error.HTTPError as x:out={'status':x.code,'body':json.loads(x.read(32768)),'nonce':nonce}
except (OSError,ValueError,urllib.error.URLError):out={'status':None,'error':'connection_unavailable','nonce':nonce}
print(json.dumps(out))
"""

SQL_PROBE = r"""
import json,sys,psycopg,pathlib
v=json.load(sys.stdin)
try:
 with psycopg.connect(host=v['host'],dbname='workload',user='postgres' if v['admin'] else 'app',password=v['password'] or pathlib.Path('/credentials/'+('dbadmin' if v['admin'] else 'password')).read_text().strip(),connect_timeout=3,options='-c statement_timeout=5000 -c lock_timeout=1000') as c:
  r=c.execute(v['sql'],v['parameters']);rows=r.fetchall() if r.description else []
 print(json.dumps({'ok':True,'rows':rows}))
except Exception:print(json.dumps({'ok':False,'error':'sql_unconfirmed'}))
"""

BATCH_HTTP_PROBE = r"""
import json,sys,secrets,urllib.request,urllib.error,concurrent.futures
values=json.load(sys.stdin)
def one(item):
 key,host=item;nonce=secrets.token_hex(16)
 try:
  with urllib.request.urlopen(urllib.request.Request('http://'+host+':8080/health',headers={'X-Request-ID':nonce}),timeout=2) as r:
   body=json.loads(r.read(8192));return key,{'status':r.status,'body':body,'nonce':nonce,'identity_echo':body.get('request_id')==nonce}
 except urllib.error.HTTPError as r:return key,{'status':r.code,'body':json.loads(r.read(8192)),'nonce':nonce}
 except Exception:return key,{'status':None,'error':'http_probe_unconfirmed','nonce':nonce}
with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:print(json.dumps(dict(pool.map(one,values.items()))))
"""
