"""Finite, credential-free incident fixtures; never an arbitrary command runner."""

from copy import deepcopy
import json

from .terminal_fixture import terminal_manifests


APP_EXTENSION = r"""
# Separate fixed controls exist only in freshly owned qualification fixtures.
FAILED=False
old_get=Handler.do_GET
old_post=Handler.do_POST
def expanded_get(self):
 path=urlsplit(self.path).path
 if path=='/health' and FAILED:return self.reply(503,{'error':'injected_verification_failure','pod_uid':UID})
 if path=='/health':
  nonce=parse_qs(urlsplit(self.path).query).get('nonce',[''])[0]
  return self.reply(200,{'application':APP,'environment':ENV,'component':COMP,'pod_uid':UID,'pod_ip':os.environ.get('POD_IP'),'request_id':self.headers.get('X-Request-ID'),'probe_nonce':nonce})
 if path=='/stream':
  nonce=self.headers.get('X-Request-ID','')
  if not re.fullmatch('[a-f0-9]{32}',nonce):return self.reply(400,{'error':'nonce_required'})
  self.send_response(200);self.send_header('Content-Type','application/x-ndjson');self.end_headers()
  try:
   for _ in range(300):
    self.wfile.write((json.dumps({'nonce':nonce,'application':APP,'component':COMP,'pod_uid':UID})+'\n').encode());self.wfile.flush();time.sleep(0.5)
  except (OSError,TimeoutError):pass
  return
 return old_get(self)
def expanded_post(self):
 global FAILED
 if self.path=='/fault' and ENV=='green' and COMP in {'api','worker'}:
  try:
   self.connection.settimeout(2);length=int(self.headers.get('Content-Length','0'))
   if self.headers.get('Transfer-Encoding') or not 0<length<=64:raise ValueError()
   body=json.loads(self.rfile.read(length))
   if set(body)!={'failed'} or type(body['failed']) is not bool:raise ValueError()
  except Exception:return self.reply(400,{'error':'invalid_fault'})
  FAILED=body['failed'];return self.reply(200,{'failed':FAILED,'pod_uid':UID,'application':APP})
 if self.path=='/egress-check' and ENV=='blue' and COMP=='worker':return self.egress_check()
 return old_post(self)
Handler.do_GET=expanded_get;Handler.do_POST=expanded_post
"""

PROBE_EXTENSION = r"""
STREAMS={};STREAM_CONNECTIONS={};WORKER_ROUTE={'environment_id':SOURCE,'revision':1,'plan_digest':None}
previous_get=Handler.do_GET;previous_post=Handler.do_POST
def stream_reader(component,nonce,connection,response):
 try:
  while True:
   raw=response.readline(4097)
   if not raw:
    with LOCK:STREAMS[component]['eof']=True
    break
   v=json.loads(raw)
   if v.get('application')!=APP or v.get('component')!=component or v.get('nonce')!=nonce:raise ValueError()
   with LOCK:
    record=STREAMS[component]
    if record['pod_uid'] not in (None,v.get('pod_uid')):raise ValueError()
    record.update(pod_uid=v['pod_uid'],lines=record['lines']+1,last_line=time.monotonic())
 except Exception:
  with LOCK:STREAMS[component]['unconfirmed']=True
 finally:connection.close()
def expanded_probe_get(self):
 path=urlsplit(self.path).path;q=parse_qs(urlsplit(self.path).query)
 component=q.get('component',[''])[0]
 if path in {'/streams','/worker-route','/pipeline'}:
  if path=='/streams':
   with LOCK:return self.reply(200,{'streams':{k:dict(v,alive=v['lines']>0 and not v['eof'] and not v['unconfirmed'] and time.monotonic()-v['last_line']<3) for k,v in STREAMS.items()}})
  if path=='/worker-route':
   with LOCK:return self.reply(200,dict(WORKER_ROUTE))
  nonce=q.get('request_id',[''])[0]
  if not re.fullmatch('[a-f0-9]{32}',nonce):return self.reply(400,{'error':'nonce_required'})
  with LOCK:targets={'api':'green' if ROUTE['environment_id']==TARGET else 'blue','worker':'green-worker' if WORKER_ROUTE['environment_id']==TARGET else 'blue-worker'}
  values={k:probe(v,nonce) for k,v in targets.items()}
  return self.reply(200,{'ok':all(v.get('ok') for v in values.values()),'components':values,'request_id':nonce})
 return previous_get(self)
def expanded_probe_post(self):
 if self.path not in {'/streams/open','/streams/close','/worker-route','/return-route'}:return previous_post(self)
 try:
  self.connection.settimeout(2);length=int(self.headers.get('Content-Length','0'))
  if self.headers.get('Transfer-Encoding') or not 0<length<=1024:raise ValueError()
  body=json.loads(self.rfile.read(length))
 except Exception:return self.reply(400,{'error':'invalid_request'})
 if self.path in {'/streams/open','/streams/close'}:
  if set(body)!={'component','nonce'} or body['component'] not in {'api','worker'} or not re.fullmatch('[a-f0-9]{32}',body['nonce']):return self.reply(400,{'error':'invalid_stream'})
  component=body['component'];nonce=body['nonce']
  if self.path=='/streams/close':
   import socket
   with LOCK:
    record=STREAMS.get(component);sock=STREAM_CONNECTIONS.get(component)
    if not record or record['nonce']!=nonce or not sock:return self.reply(409,{'error':'stream_identity_mismatch'})
    try:sock.shutdown(socket.SHUT_RDWR)
    except OSError:pass
    sock.close();record['client_socket_closed']=True
    return self.reply(200,{'closed':True,'component':component,'nonce':nonce,'pod_uid':record['pod_uid']})
  with LOCK:
   if component in STREAMS:return self.reply(409,{'error':'stream_already_recorded'})
   STREAMS[component]={'nonce':nonce,'pod_uid':None,'lines':0,'last_line':0,'eof':False,'unconfirmed':False}
  c=http.client.HTTPConnection(TARGETS['blue' if component=='api' else 'blue-worker'],8080,timeout=150)
  try:
   c.connect();sock=c.sock;c.request('GET','/stream',headers={'X-Request-ID':nonce});r=c.getresponse()
   if r.status!=200:raise ValueError()
  except Exception:
   c.close()
   with LOCK:STREAMS[component]['unconfirmed']=True
   return self.reply(503,{'error':'stream_unconfirmed'})
  with LOCK:STREAM_CONNECTIONS[component]=sock
  threading.Thread(target=stream_reader,args=(component,nonce,c,r),daemon=True).start()
  return self.reply(200,{'opened':True,'component':component,'nonce':nonce})
 expected={'source','target','expected_revision','plan_digest'}
 if self.path=='/return-route':expected=expected|{'component'}
 if set(body)!=expected or type(body['expected_revision']) is not int or not re.fullmatch('[a-f0-9]{64}',body['plan_digest']):return self.reply(400,{'error':'invalid_route'})
 component=body.get('component','worker')
 if component not in {'api','worker'}:return self.reply(400,{'error':'invalid_component'})
 route=ROUTE if component=='api' else WORKER_ROUTE
 reverse=self.path=='/return-route'
 src,dst=(TARGET,SOURCE) if reverse else (SOURCE,TARGET)
 if body['source']!=src or body['target']!=dst:return self.reply(400,{'error':'invalid_direction'})
 with LOCK:
  if route['environment_id']!=src or route['revision']!=body['expected_revision']:return self.reply(409,{'error':'revision_conflict'})
  route.update(environment_id=dst,revision=route['revision']+1,plan_digest=body['plan_digest'])
  return self.reply(200,dict(route))
Handler.do_GET=expanded_probe_get;Handler.do_POST=expanded_probe_post
"""


def expanded_manifests(run_id, image):
    documents = terminal_manifests(run_id, image)
    api_objects = [
        d for d in documents if d["metadata"].get("name") in {"api", "api-code"}
    ]
    for original in api_objects:
        doc = deepcopy(original)
        doc["metadata"]["name"] = original["metadata"]["name"].replace("api", "worker")
        doc["metadata"]["labels"]["app.kubernetes.io/name"] = "worker"
        if doc["kind"] == "Deployment":
            doc["spec"]["selector"]["matchLabels"]["app.kubernetes.io/name"] = "worker"
            doc["spec"]["template"]["metadata"]["labels"]["app.kubernetes.io/name"] = (
                "worker"
            )
            container = doc["spec"]["template"]["spec"]["containers"][0]
            container["name"] = "worker"
            for env in container["env"]:
                if env["name"] == "COMPONENT":
                    env["value"] = "worker"
            doc["spec"]["template"]["spec"]["volumes"][0]["configMap"]["name"] = (
                "worker-code"
            )
        elif doc["kind"] == "Service":
            doc["spec"]["selector"]["app.kubernetes.io/name"] = "worker"
        documents.append(doc)
    for doc in documents:
        if doc["kind"] == "ConfigMap":
            code = doc["data"]["main.py"]
            marker = "ThreadingHTTPServer("
            pos = code.rindex(marker)
            extension = (
                PROBE_EXTENSION
                if doc["metadata"]["name"] == "probe-code"
                else APP_EXTENSION
            )
            doc["data"]["main.py"] = code[:pos] + extension + "\n" + code[pos:]
        if doc["kind"] == "Deployment" and doc["metadata"]["name"] == "probe":
            envs = doc["spec"]["template"]["spec"]["containers"][0]["env"]
            for env in envs:
                if env["name"] == "TARGETS":
                    value = json.loads(env["value"])
                    value.update(
                        {
                            k + "-worker": v.replace("api.", "worker.", 1)
                            for k, v in tuple(value.items())
                            if k in {"blue", "green"}
                        }
                    )
                    env["value"] = json.dumps(value)
    return documents
