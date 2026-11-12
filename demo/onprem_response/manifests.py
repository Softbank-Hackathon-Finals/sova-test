"""Fixed stateless HTTP fixtures. No application DB, credentials or host mounts."""

import json
import re

IMAGE = re.compile(r"docker\.io/library/python@sha256:[a-f0-9]{64}\Z")

APP_CODE = """import json,os
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def do_GET(self):
  body={'application':os.environ['APPLICATION'],'environment':os.environ['ENVIRONMENT'],'component':os.environ['COMPONENT'],'pod_uid':os.environ['POD_UID'],'request_id':self.headers.get('X-Request-ID')}
  raw=json.dumps(body).encode();self.send_response(200 if self.path=='/health' else 404);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
"""

PROBE_CODE = """import http.client,json,os,re,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
TARGETS=json.loads(os.environ['TARGETS']);SOURCE=os.environ['SOURCE_ENV'];TARGET=os.environ['TARGET_ENV'];APP=os.environ['APPLICATION']
ROUTE={'environment_id':SOURCE,'revision':1,'plan_digest':None};LOCK=threading.Lock()
def probe(target,request_id):
 start=time.monotonic();connected=False
 connection=http.client.HTTPConnection(TARGETS[target],8080,timeout=1)
 try:
  connection.connect();connected=True;connection.request('GET','/health',headers={'X-Request-ID':request_id});response=connection.getresponse();body=json.loads(response.read(65536))
  return {'ok':response.status==200 and body.get('request_id')==request_id and body.get('application')==APP,'target':target,'connected':connected,'upstream_status':response.status,'response':body,'duration_ms':round((time.monotonic()-start)*1000,2)}
 except Exception:return {'ok':False,'target':target,'connected':connected,'error':'upstream_unreachable','duration_ms':round((time.monotonic()-start)*1000,2)}
 finally:connection.close()
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,status,body):
  raw=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_GET(self):
  path=urlsplit(self.path).path
  if path=='/health':return self.reply(200,{'ok':True,'probe':'alive'})
  if path=='/route':
   with LOCK:return self.reply(200,dict(ROUTE))
  if path=='/entry':
   with LOCK:target='green' if ROUTE['environment_id']==TARGET else 'blue'
  elif path=='/probe':target=parse_qs(urlsplit(self.path).query).get('target',[''])[0]
  else:return self.reply(404,{'error':'not_found'})
  if target not in TARGETS:return self.reply(400,{'error':'unknown_target'})
  nonce=self.headers.get('X-Request-ID','')
  if not re.fullmatch('[a-f0-9]{32}',nonce):return self.reply(400,{'error':'nonce_required'})
  self.reply(200,probe(target,nonce))
 def do_POST(self):
  if self.path!='/route':return self.reply(404,{'error':'not_found'})
  self.connection.settimeout(3)
  try:
   length=int(self.headers.get('Content-Length','0'))
   if not 0<length<=1024 or self.headers.get('Transfer-Encoding'):raise ValueError()
   body=json.loads(self.rfile.read(length))
   if set(body)!={'source','target','expected_revision','plan_digest'} or body['source']!=SOURCE or body['target']!=TARGET or type(body['expected_revision']) is not int or not re.fullmatch('[a-f0-9]{64}',body['plan_digest']):raise ValueError()
  except Exception:return self.reply(400,{'error':'invalid_request'})
  with LOCK:
   if ROUTE['environment_id']!=SOURCE or ROUTE['revision']!=body['expected_revision']:return self.reply(409,{'error':'revision_conflict'})
   ROUTE.update(environment_id=TARGET,revision=ROUTE['revision']+1,plan_digest=body['plan_digest'])
   return self.reply(200,dict(ROUTE))
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
"""


def validate_names(run_id, image):
    if not re.fullmatch(r"[a-f0-9]{8}", run_id) or not IMAGE.fullmatch(image):
        raise ValueError("Explicit test run and pinned official Python image required")


def names(run_id):
    if not re.fullmatch(r"[a-f0-9]{8}", run_id):
        raise ValueError("Invalid trial run")
    return {side: f"sova-wr-{run_id}-{side}" for side in ("blue", "green", "probe")}


def manifests(run_id, image):
    validate_names(run_id, image)
    ns = names(run_id)
    app = "sova-wr-" + run_id
    objects = []
    for namespace in ns.values():
        objects += [
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace,
                    "labels": {
                        "sova.io/trial": run_id,
                        "app.kubernetes.io/part-of": app,
                        "project": "bravo",
                        "component": "target",
                        "pod-security.kubernetes.io/enforce": "restricted",
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "ResourceQuota",
                "metadata": {"name": "trial-limit", "namespace": namespace},
                "spec": {
                    "hard": {
                        "pods": "3",
                        "requests.cpu": "150m",
                        "requests.memory": "192Mi",
                        "limits.cpu": "600m",
                        "limits.memory": "256Mi",
                    }
                },
            },
        ]
    for side, component, replicas, code in (
        ("blue", "api", 1, APP_CODE),
        ("blue", "neighbor", 1, APP_CODE),
        ("green", "api", 0, APP_CODE),
        ("probe", "probe", 1, PROBE_CODE),
    ):
        namespace = ns[side]
        labels = {"app.kubernetes.io/name": component, "app.kubernetes.io/part-of": app}
        env = [
            {"name": k, "value": v}
            for k, v in {
                "APPLICATION": app,
                "ENVIRONMENT": side,
                "COMPONENT": component,
            }.items()
        ]
        env += [
            {
                "name": "POD_UID",
                "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}},
            }
        ]
        if side == "probe":
            env += [
                {"name": k, "value": v}
                for k, v in {
                    "SOURCE_ENV": ns["blue"],
                    "TARGET_ENV": ns["green"],
                    "TARGETS": json.dumps(
                        {
                            "blue": f"api.{ns['blue']}.svc.cluster.local",
                            "green": f"api.{ns['green']}.svc.cluster.local",
                            "neighbor": f"neighbor.{ns['blue']}.svc.cluster.local",
                        }
                    ),
                }.items()
            ]
        objects += [
            {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "immutable": True,
                "metadata": {
                    "namespace": namespace,
                    "name": component + "-code",
                    "labels": labels,
                },
                "data": {"main.py": code},
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "namespace": namespace,
                    "name": component,
                    "labels": labels,
                },
                "spec": {
                    "replicas": replicas,
                    "selector": {"matchLabels": labels},
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "terminationGracePeriodSeconds": 3,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 65532,
                                "runAsGroup": 65532,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [
                                {
                                    "name": component,
                                    "image": image,
                                    "imagePullPolicy": "IfNotPresent",
                                    "command": [
                                        "python",
                                        "-I",
                                        "-B",
                                        "/workload/main.py",
                                    ],
                                    "env": env,
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "resources": {
                                        "requests": {"cpu": "25m", "memory": "32Mi"},
                                        "limits": {"cpu": "100m", "memory": "64Mi"},
                                    },
                                    "readinessProbe": {
                                        "httpGet": {"path": "/health", "port": 8080},
                                        "periodSeconds": 2,
                                    },
                                    "volumeMounts": [
                                        {
                                            "name": "code",
                                            "mountPath": "/workload",
                                            "readOnly": True,
                                        }
                                    ],
                                }
                            ],
                            "volumes": [
                                {
                                    "name": "code",
                                    "configMap": {"name": component + "-code"},
                                }
                            ],
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {
                    "namespace": namespace,
                    "name": component,
                    "labels": labels,
                },
                "spec": {
                    "type": "ClusterIP",
                    "selector": labels,
                    "ports": [{"port": 8080, "targetPort": 8080}],
                },
            },
        ]
    objects.append(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "probe-no-ingress", "namespace": ns["probe"]},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress"], "ingress": []},
        }
    )
    return objects
