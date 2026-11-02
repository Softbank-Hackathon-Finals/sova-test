"""Owned demo setup step; invoked by security_demo.py, never from HTTP."""

import sys
from pathlib import Path
import json
import subprocess

root = Path(sys.argv[1]).resolve()
c = json.loads((root / "cluster.json").read_text())
config = root / "admin-kubeconfig.json"
cmd = ["kubectl", "--kubeconfig", str(config), "--request-timeout=15s"]


def kubectl(*args, input=None):
    p = subprocess.run(
        cmd + list(args), input=input, capture_output=True, text=True, timeout=30
    )
    if p.returncode:
        (root / "workload-error.log").write_text(p.stderr)
        raise RuntimeError("Owned workload preparation failed; private log saved")
    return p.stdout


digests = json.loads(
    subprocess.run(
        [
            "docker",
            "image",
            "inspect",
            "python:3.12-slim",
            "--format",
            "{{json .RepoDigests}}",
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    ).stdout
)
if not any(
    x.endswith(
        "@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a"
    )
    for x in digests
):
    raise RuntimeError("Cached image digest changed")
image = "python:3.12-slim"
source = subprocess.Popen(
    ["docker", "save", image], stdout=subprocess.PIPE, stderr=subprocess.PIPE
)
dest = subprocess.run(
    [
        "docker",
        "exec",
        "-i",
        c["container_id"],
        "ctr",
        "-n",
        "k8s.io",
        "images",
        "import",
        "-",
    ],
    stdin=source.stdout,
    capture_output=True,
    text=True,
    timeout=120,
)
source.stdout.close()
source.wait(timeout=30)
(root / "image-import.log").write_text(dest.stdout + dest.stderr)
if dest.returncode:
    raise RuntimeError("Image import failed")
images = subprocess.run(
    ["docker", "exec", c["container_id"], "ctr", "-n", "k8s.io", "images", "ls"],
    capture_output=True,
    text=True,
    check=True,
    timeout=15,
).stdout
line = next(line for line in images.splitlines() if "python:3.12-slim" in line)
digest = next(part for part in line.split() if part.startswith("sha256:"))
pinned = "docker.io/library/python@" + digest
subprocess.run(
    [
        "docker",
        "exec",
        c["container_id"],
        "ctr",
        "-n",
        "k8s.io",
        "images",
        "tag",
        "docker.io/library/python:3.12-slim",
        pinned,
    ],
    capture_output=True,
    text=True,
    check=True,
    timeout=15,
)

app_code = """import json,os,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  forbidden=self.path.startswith('/admin')
  data={'application':'order-service','environment':os.environ['ENVIRONMENT'],'component':os.environ['COMPONENT'],'request_id':self.headers.get('X-Request-ID'),'at':time.time(),'status':'denied' if forbidden else 'ok'}
  raw=json.dumps(data).encode();self.send_response(403 if forbidden else 200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
"""
probe_code = """import json,http.client,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
TARGETS={'blue':'api.sova-live-blue.svc.cluster.local','green':'api.sova-live-green.svc.cluster.local'}
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  query=parse_qs(urlsplit(self.path).query);target=query.get('target',['blue'])[0]
  if target not in TARGETS:self.send_error(400);return
  request_id=self.headers.get('X-Request-ID');start=time.monotonic();connection=http.client.HTTPConnection(TARGETS[target],8080,timeout=1)
  try:
   connection.request('GET','/health',headers={'X-Request-ID':request_id});response=connection.getresponse();body=json.loads(response.read(65536));result={'ok':response.status==200 and body.get('request_id')==request_id,'target':target,'upstream_status':response.status,'response':body,'duration_ms':round((time.monotonic()-start)*1000,2)}
  except Exception:result={'ok':False,'target':target,'error':'upstream_unreachable','duration_ms':round((time.monotonic()-start)*1000,2)}
  finally:connection.close()
  raw=json.dumps(result).encode();self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
"""
objects = []
for ns in ("sova-live-blue", "sova-live-green", "sova-live-observer"):
    objects.append(
        {
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {
                "name": ns,
                "labels": {
                    "io.sova/session": "security-20261101",
                    "pod-security.kubernetes.io/enforce": "restricted",
                },
            },
        }
    )
for ns, env, component, code in [
    ("sova-live-blue", "blue", "api", app_code),
    ("sova-live-green", "green", "api", app_code),
    ("sova-live-observer", "observer", "probe", probe_code),
]:
    labels = {
        "app.kubernetes.io/part-of": "order-service",
        "app.kubernetes.io/name": component,
        "io.sova/session": "security-20261101",
    }
    objects.append(
        {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {
                "namespace": ns,
                "name": component + "-code",
                "labels": labels,
            },
            "data": {"main.py": code},
        }
    )
    pod = {
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "runAsGroup": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [
            {
                "name": component,
                "image": pinned,
                "imagePullPolicy": "Never",
                "command": ["python", "-B", "/app/main.py"],
                "env": [
                    {"name": "ENVIRONMENT", "value": env},
                    {"name": "COMPONENT", "value": component},
                ],
                "ports": [{"containerPort": 8080}],
                "resources": {
                    "requests": {"cpu": "25m", "memory": "32Mi"},
                    "limits": {"cpu": "200m", "memory": "96Mi"},
                },
                "securityContext": {
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "capabilities": {"drop": ["ALL"]},
                },
                "volumeMounts": [
                    {"name": "code", "mountPath": "/app", "readOnly": True}
                ],
                "readinessProbe": {
                    "tcpSocket": {"port": 8080},
                    "initialDelaySeconds": 1,
                    "periodSeconds": 2,
                },
            }
        ],
        "volumes": [{"name": "code", "configMap": {"name": component + "-code"}}],
    }
    objects.append(
        {
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"namespace": ns, "name": component, "labels": labels},
            "spec": {
                "replicas": 0 if env == "green" else 1,
                "selector": {
                    "matchLabels": {
                        "app.kubernetes.io/name": component,
                        "app.kubernetes.io/part-of": "order-service",
                    }
                },
                "template": {"metadata": {"labels": labels}, "spec": pod},
            },
        }
    )
    objects.append(
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"namespace": ns, "name": component, "labels": labels},
            "spec": {
                "selector": {
                    "app.kubernetes.io/name": component,
                    "app.kubernetes.io/part-of": "order-service",
                },
                "ports": [{"port": 8080, "targetPort": 8080}],
            },
        }
    )
manifest = {"apiVersion": "v1", "kind": "List", "items": objects}
p = root / "workloads.json"
p.write_text(json.dumps(manifest, indent=2))
p.chmod(0o600)
kubectl("apply", "-f", str(p))
for ns, component in [("sova-live-blue", "api"), ("sova-live-observer", "probe")]:
    kubectl("-n", ns, "rollout", "status", "deployment/" + component, "--timeout=60s")
(root / "workload.json").write_text(
    json.dumps(
        {
            "image": pinned,
            "source_namespace": "sova-live-blue",
            "target_namespace": "sova-live-green",
            "probe_namespace": "sova-live-observer",
            "scope": "owned local stateless test only",
        },
        indent=2,
    )
    + "\n"
)
print(
    "Owned stateless Blue and independent probe are ready; Green registered with zero replicas."
)
