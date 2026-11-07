"""Fixed HTTP authorization-denial exercise. No exploit, secrets or arbitrary targets."""

import json

from .manifests import manifests

APP_CODE = r"""import http.client,json,os,re,threading,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit,parse_qs
APP=os.environ['APPLICATION'];ENV=os.environ['ENVIRONMENT'];COMP=os.environ['COMPONENT'];UID=os.environ['POD_UID']
AUDIT={};ATTEMPTS={};LOCK=threading.Lock()
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args):pass
 def reply(self,status,body):
  raw=json.dumps(body).encode();self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
 def do_GET(self):
  path=urlsplit(self.path).path;nonce=parse_qs(urlsplit(self.path).query).get('nonce',[''])[0]
  base={'application':APP,'environment':ENV,'component':COMP,'pod_uid':UID,'request_id':self.headers.get('X-Request-ID')}
  if path=='/health':return self.reply(200,base)
  if path=='/protected' and COMP=='neighbor':
   nonce=self.headers.get('X-Request-ID','')
   if not re.fullmatch('[a-f0-9]{32}',nonce):return self.reply(400,{'error':'nonce_required'})
   with LOCK:
    if len(AUDIT)>=8 and nonce not in AUDIT:return self.reply(429,{'error':'trial_limit'})
    AUDIT[nonce]={'nonce':nonce,'status':403,'actor_ip':self.client_address[0],'actor_pod_uid':self.headers.get('X-Actor-Pod',''),'target_pod_uid':UID,'application':APP,'observed_at':time.time()}
   return self.reply(403,{'error':'trial_authorization_denied','nonce':nonce,'application':APP})
  if path=='/audit' and COMP=='neighbor' and re.fullmatch('[a-f0-9]{32}',nonce):
   with LOCK:return self.reply(200,{'audit':AUDIT.get(nonce),'application':APP})
  return self.reply(404,{'error':'not_found'})
 def do_POST(self):
  if self.path!='/attempt' or ENV!='blue' or COMP!='api':return self.reply(404,{'error':'not_found'})
  try:
   self.connection.settimeout(3);length=int(self.headers.get('Content-Length','0'))
   if self.headers.get('Transfer-Encoding') or not 0<length<=128:raise ValueError()
   body=json.loads(self.rfile.read(length));nonce=body['nonce']
   if set(body)!={'nonce'} or not re.fullmatch('[a-f0-9]{32}',nonce):raise ValueError()
  except Exception:return self.reply(400,{'error':'invalid_attempt'})
  with LOCK:
   if nonce in ATTEMPTS:return self.reply(409,{'error':'attempt_already_started'})
   if ATTEMPTS:return self.reply(409,{'error':'one_attempt_per_trial'})
   ATTEMPTS[nonce]={'status':'dispatched'}
  connection=http.client.HTTPConnection(os.environ['NEIGHBOR_HOST'],int(os.environ.get('NEIGHBOR_PORT','8080')),timeout=2)
  try:
   connection.request('GET','/protected',headers={'X-Request-ID':nonce,'X-Actor-Pod':UID});r=connection.getresponse();result=json.loads(r.read(4097))
   value={'nonce':nonce,'application':APP,'actor_pod_uid':UID,'upstream_status':r.status,'authorization_denied':r.status==403 and result.get('nonce')==nonce and result.get('application')==APP}
  except Exception:return self.reply(503,{'error':'attempt_result_unknown','nonce':nonce})
  finally:connection.close()
  with LOCK:ATTEMPTS[nonce]=value
  return self.reply(200,value)
ThreadingHTTPServer((os.environ.get('LISTEN_HOST','0.0.0.0'),int(os.environ.get('LISTEN_PORT','8080'))),Handler).serve_forever()
"""

PROBE_EXTENSION = r"""
# The probe has exactly one fixed application target for an attempt. It does not
# accept a URL, command, credential, namespace or destination from callers.
old_get=Handler.do_GET
def get(self):
 path=urlsplit(self.path).path;query=parse_qs(urlsplit(self.path).query)
 if path=='/audit':
  nonce=query.get('nonce',[''])[0]
  if not re.fullmatch('[a-f0-9]{32}',nonce):return self.reply(400,{'error':'nonce_required'})
  c=http.client.HTTPConnection(TARGETS['neighbor'],8080,timeout=3)
  try:
   c.request('GET','/audit?nonce='+nonce);r=c.getresponse();data=json.loads(r.read(8193))
   if r.status!=200:raise ValueError()
   return self.reply(200,data)
  except Exception:return self.reply(503,{'error':'audit_unavailable'})
  finally:c.close()
 nonce=query.get('request_id',[''])[0]
 if nonce:
  if 'X-Request-ID' in self.headers:del self.headers['X-Request-ID']
  self.headers['X-Request-ID']=nonce
 return old_get(self)
def post(self):
 if self.path!='/attempt':return old_post(self)
 try:
  self.connection.settimeout(3);length=int(self.headers.get('Content-Length','0'))
  if self.headers.get('Transfer-Encoding') or not 0<length<=128:raise ValueError()
  body=json.loads(self.rfile.read(length));nonce=body['nonce']
  if set(body)!={'nonce'} or not re.fullmatch('[a-f0-9]{32}',nonce):raise ValueError()
 except Exception:return self.reply(400,{'error':'invalid_attempt'})
 c=http.client.HTTPConnection(TARGETS['blue'],8080,timeout=4)
 try:
  raw=json.dumps(body);c.request('POST','/attempt',body=raw,headers={'Content-Type':'application/json'});r=c.getresponse();data=json.loads(r.read(8193))
  return self.reply(r.status,data)
 except Exception:return self.reply(503,{'error':'attempt_result_unknown'})
 finally:c.close()
old_post=Handler.do_POST
Handler.do_GET=get;Handler.do_POST=post
"""


def terminal_manifests(run_id, image):
    documents = manifests(run_id, image)
    for doc in documents:
        if doc["kind"] == "ConfigMap" and doc["metadata"]["name"] == "api-code":
            doc["data"]["main.py"] = APP_CODE
        elif doc["kind"] == "ConfigMap" and doc["metadata"]["name"] == "neighbor-code":
            doc["data"]["main.py"] = APP_CODE
        elif doc["kind"] == "ConfigMap" and doc["metadata"]["name"] == "probe-code":
            old = doc["data"]["main.py"]
            end = "ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()"
            assert old.count(end) == 1
            doc["data"]["main.py"] = old.replace(end, PROBE_EXTENSION + "\n" + end)
        elif doc["kind"] == "Deployment" and doc["metadata"]["name"] == "api":
            namespace = doc["metadata"]["namespace"]
            blue = namespace.rsplit("-", 1)[0] + "-blue"
            doc["spec"]["template"]["spec"]["containers"][0]["env"].append(
                {"name": "NEIGHBOR_HOST", "value": f"neighbor.{blue}.svc.cluster.local"}
            )
    # Keep manifest code serialization bounded before any external request.
    assert len(json.dumps(documents)) < 65536
    return documents
