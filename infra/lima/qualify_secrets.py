"""Explicit operator trial: Secret ciphertext, key rotation, token revocation.

Only the registered, single-node Sova qualification VM is supported. Encryption
rotation affects its entire cluster. No Secret value, bearer token or encryption
key is written to the report or printed. Not a hosted executor or KMS claim.
"""

import argparse
import base64
from datetime import UTC, datetime
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import ssl
import time

from qualify_target import VM, LABEL, absent, apply, check, guest, kubectl, private_text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("SOVA_QUALIFY_SECRET_ROTATION") != "1":
        parser.error("Explicit SOVA_QUALIFY_SECRET_ROTATION=1 required")
    os.umask(0o077)
    state = args.state_dir.absolute()
    owner = json.loads(private_text(state / "ownership.json"))
    assert owner["name"] == VM and owner["status"] == "ready"
    assert datetime.fromisoformat(owner["expires_at"]) > datetime.now(UTC)
    assert guest("cat", "/etc/machine-id").stdout.strip() == owner["machine_id"]
    assert (
        hashlib.sha256(Path(owner["lima_config_path"]).read_bytes()).hexdigest()
        == owner["lima_config_sha256"]
    )
    node = json.loads(kubectl("get", "node", VM, "-o", "json").stdout)
    assert node["metadata"]["uid"] == owner["node_uid"]
    assert len(json.loads(kubectl("get", "nodes", "-o", "json").stdout)["items"]) == 1
    assert not args.output.exists()
    args.output.mkdir(mode=0o700, parents=True)
    qualification = "secrets-" + secrets.token_hex(6)
    ns = "sova-" + qualification
    uid = None
    results = {}
    failure = None
    started = datetime.now(UTC)
    canary = secrets.token_urlsafe(48)
    encoded = base64.b64encode(canary.encode()).decode()
    ca = (state / "cluster-ca.pem").read_bytes()
    assert hashlib.sha256(ca).hexdigest() == owner["cluster_ca_sha256"]
    context = ssl.create_default_context(cadata=ca.decode())

    def access(token, name="credential"):
        conn = http.client.HTTPSConnection(
            "localhost", 19743, context=context, timeout=5
        )
        try:
            conn.request(
                "GET",
                "/api/v1/namespaces/" + ns + "/secrets/" + name,
                headers={"Authorization": "Bearer " + token},
            )
            response = conn.getresponse()
            body = response.read(65537)
            assert len(body) <= 65536
            return response.status, json.loads(body)
        finally:
            conn.close()

    def ciphertext():
        source = r"""
import base64, hashlib, json, sqlite3, sys
request = json.load(sys.stdin)
assert request['namespace'].startswith('sova-secrets-')
conn = sqlite3.connect('file:/var/lib/rancher/k3s/server/db/state.db?mode=ro', uri=True)
try:
    row = conn.execute('SELECT value FROM kine WHERE name=? ORDER BY id DESC LIMIT 1', ('/registry/secrets/'+request['namespace']+'/credential',)).fetchone()
finally:
    conn.close()
assert row is not None
value = bytes(row[0])
assert value.startswith(b'k8s:enc:aescbc:v1:')
parts = value.split(b':', 5)
assert len(parts) == 6 and len(parts[4]) < 256
assert request['canary'].encode() not in value
assert base64.b64encode(request['canary'].encode()) not in value
print(json.dumps({'ciphertext_sha256':hashlib.sha256(value).hexdigest(),'key_name_sha256':hashlib.sha256(parts[4]).hexdigest(),'encrypted_at_rest':True}))
"""
        raw = guest(
            "sudo",
            "python3",
            "-c",
            source,
            value=json.dumps({"namespace": ns, "canary": canary}),
        ).stdout
        return json.loads(raw)

    try:
        apply(
            [
                {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {"name": ns, "labels": {LABEL: qualification}},
                }
            ]
        )
        uid = json.loads(kubectl("get", "ns", ns, "-o", "json").stdout)["metadata"][
            "uid"
        ]
        apply(
            [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "consumer", "namespace": ns},
                    "automountServiceAccountToken": False,
                },
                {
                    "apiVersion": "v1",
                    "kind": "Secret",
                    "metadata": {"name": "credential", "namespace": ns},
                    "type": "Opaque",
                    "data": {"canary": encoded},
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "Role",
                    "metadata": {"name": "consumer", "namespace": ns},
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["secrets"],
                            "resourceNames": ["credential"],
                            "verbs": ["get"],
                        }
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "RoleBinding",
                    "metadata": {"name": "consumer", "namespace": ns},
                    "subjects": [
                        {"kind": "ServiceAccount", "name": "consumer", "namespace": ns}
                    ],
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "Role",
                        "name": "consumer",
                    },
                },
            ]
        )
        token = kubectl(
            "create", "token", "consumer", "-n", ns, "--duration=10m"
        ).stdout.strip()
        status, value = access(token)
        check(
            status == 200 and value["data"]["canary"] == encoded,
            "exact_secret_authorized_read",
            results,
        )
        check(
            access(token, "not-allowed")[0] == 403,
            "other_secret_name_rbac_denied",
            results,
        )
        before = ciphertext()
        check(
            before["encrypted_at_rest"], "stored_secret_is_aescbc_ciphertext", results
        )
        # Single-server procedure from the pinned K3s documentation. No disable,
        # prepare/legacy steps or manual editing of encryption keys is used.
        guest("sudo", "k3s", "secrets-encrypt", "rotate-keys", timeout=60)
        deadline = time.monotonic() + 180
        while True:
            status_text = guest("sudo", "k3s", "secrets-encrypt", "status").stdout
            if (
                "reencrypt_finished" in status_text
                and "All hashes match" in status_text
            ):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("Encryption rotation completion was not confirmed")
            time.sleep(2)
        after = ciphertext()
        check(
            before["key_name_sha256"] != after["key_name_sha256"]
            and before["ciphertext_sha256"] != after["ciphertext_sha256"],
            "stored_secret_reencrypted_with_new_key",
            results,
        )
        status, value = access(token)
        check(
            status == 200 and value["data"]["canary"] == encoded,
            "secret_value_preserved_after_key_rotation",
            results,
        )
        # Delete/recreate SA to prove token binding includes its UID, not name.
        old_sa = json.loads(
            kubectl("get", "sa/consumer", "-n", ns, "-o", "json").stdout
        )["metadata"]["uid"]
        kubectl("delete", "sa/consumer", "-n", ns)
        apply(
            [
                {
                    "apiVersion": "v1",
                    "kind": "ServiceAccount",
                    "metadata": {"name": "consumer", "namespace": ns},
                    "automountServiceAccountToken": False,
                }
            ]
        )
        new_sa = json.loads(
            kubectl("get", "sa/consumer", "-n", ns, "-o", "json").stdout
        )["metadata"]["uid"]
        check(old_sa != new_sa, "recreated_identity_has_new_uid", results)
        deadline = time.monotonic() + 120
        while access(token)[0] not in (401, 403):
            if time.monotonic() >= deadline:
                raise RuntimeError("Deleted identity credential remained accepted")
            time.sleep(2)
        check(True, "deleted_identity_old_token_denied", results)
        new_token = kubectl(
            "create", "token", "consumer", "-n", ns, "--duration=10m"
        ).stdout.strip()
        status, value = access(new_token)
        check(
            status == 200 and value["data"]["canary"] == encoded,
            "replacement_identity_new_token_works",
            results,
        )
        # Read only bounded audit records for this unique fixture. Never export
        # raw audit files, request/response bodies, client tokens or Secret data.
        audit_source = r"""
import hashlib, json, pathlib, sys, time
request = json.load(sys.stdin)
paths = sorted(pathlib.Path('/var/lib/rancher/k3s/server/logs').glob('audit.log*'))
events = []
for path in paths:
    if not path.is_file() or path.suffix == '.gz':continue
    assert path.stat().st_size <= 12*1024*1024
    for line in path.read_text().splitlines():
        event = json.loads(line)
        if event.get('objectRef',{}).get('namespace') != request['namespace']:continue
        assert 'requestObject' not in event and 'responseObject' not in event
        assert request['canary'] not in line and request['encoded'] not in line
        events.append({'auditID':event['auditID'],'verb':event['verb'],'resource':event.get('objectRef',{}).get('resource'),'code':event.get('responseStatus',{}).get('code'),'user':event.get('user',{}).get('username'),'stage':event['stage']})
assert any(e['resource']=='secrets' and e['code']==200 for e in events)
assert any(e['resource']=='secrets' and e['code']==403 for e in events)
doc=json.dumps(events,sort_keys=True,separators=(',',':')).encode()
print(json.dumps({'event_count':len(events),'selected_metadata_digest':hashlib.sha256(doc).hexdigest(),'secret_body_recorded':False,'external_delivery_verified':False,'tamper_evidence_verified':False}))
"""
        # The apiserver batch audit backend may flush after a short delay.
        audit = None
        for _ in range(12):
            outcome = guest(
                "sudo",
                "python3",
                "-c",
                audit_source,
                value=json.dumps(
                    {"namespace": ns, "canary": canary, "encoded": encoded}
                ),
                check=False,
            )
            if outcome.returncode == 0:
                audit = json.loads(outcome.stdout)
                break
            time.sleep(1)
        check(
            audit is not None,
            "actual_audit_contains_success_and_denial_without_secret_bodies",
            results,
        )
        results["audit"] = audit
        results["encryption"] = {
            "before": before,
            "after": after,
            "kms_external_key_isolation_verified": False,
            "host_root_can_access_keys": True,
        }
    except BaseException as exc:
        failure = type(exc).__name__  # no captured response/credential in reports
        raise
    finally:
        removed = uid is None
        if uid:
            current = kubectl("get", "ns", ns, "-o", "json", check=False)
            if current.returncode == 0:
                metadata = json.loads(current.stdout)["metadata"]
                if (
                    metadata["uid"] == uid
                    and metadata.get("labels", {}).get(LABEL) == qualification
                ):
                    removed = (
                        kubectl(
                            "delete",
                            "ns",
                            ns,
                            "--wait=true",
                            "--timeout=60s",
                            timeout=70,
                            check=False,
                        ).returncode
                        == 0
                    )
        removed &= absent("namespace", ns)
        report = {
            "started_at": started.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "checks": results,
            "failure": failure,
            "owned_namespace_removed": removed,
            "cluster_encryption_keys_rotated": results.get(
                "stored_secret_reencrypted_with_new_key", False
            ),
            "production_protection_profile_qualified": False,
            "operator_admin_setup": True,
        }
        (args.output / "result.json").write_text(json.dumps(report, indent=2) + "\n")
        print(
            json.dumps(
                {
                    "checks_passed": sum(value is True for value in results.values()),
                    "owned_namespace_removed": removed,
                    "failed": failure is not None,
                }
            ),
            flush=True,
        )
        if not removed and failure is None:
            raise RuntimeError("Secret trial namespace cleanup incomplete")


if __name__ == "__main__":
    main()
