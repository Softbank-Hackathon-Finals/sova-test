"""Owned demo setup step; invoked by security_demo.py, never from HTTP."""

import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
import json
import subprocess
import base64
import hashlib
from sova.domain.discovery import KubernetesReadRegistration

root = Path(sys.argv[1]).resolve()
config = json.loads((root / "admin-kubeconfig.json").read_text())
endpoint = json.loads((root / "cluster.json").read_text())["endpoint"]
ca = base64.b64decode(config["clusters"][0]["cluster"]["certificate-authority-data"])
(root / "ca.pem").write_bytes(ca)
cmd = [
    "kubectl",
    "--kubeconfig",
    str(root / "admin-kubeconfig.json"),
    "--request-timeout=10s",
]


def kube(*args, input=None):
    p = subprocess.run(
        cmd + list(args), capture_output=True, text=True, input=input, timeout=20
    )
    if p.returncode:
        (root / "reader-error.log").write_text(p.stderr)
        raise RuntimeError("Local reader setup failed; log saved privately")
    return p.stdout


registrations = []
for env in ("blue", "green"):
    ns = "sova-live-" + env
    reader = "sova-reader-" + env
    objects = [
        {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {"namespace": "sova-live-observer", "name": reader},
            "automountServiceAccountToken": False,
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"namespace": ns, "name": "sova-inventory-reader"},
            "rules": [
                {
                    "apiGroups": ["apps"],
                    "resources": ["deployments", "statefulsets"],
                    "verbs": ["list"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["services", "persistentvolumeclaims"],
                    "verbs": ["list"],
                },
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"namespace": ns, "name": "sova-inventory-reader"},
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "namespace": "sova-live-observer",
                    "name": reader,
                }
            ],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": "sova-inventory-reader",
            },
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "sova-live-namespace-" + env},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["namespaces"],
                    "resourceNames": [ns],
                    "verbs": ["get"],
                }
            ],
        },
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "sova-live-namespace-" + env},
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "namespace": "sova-live-observer",
                    "name": reader,
                }
            ],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": "sova-live-namespace-" + env,
            },
        },
    ]
    kube(
        "apply",
        "-f",
        "-",
        input=json.dumps({"apiVersion": "v1", "kind": "List", "items": objects}),
    )
    token = kube(
        "-n", "sova-live-observer", "create", "token", reader, "--duration=15m"
    ).strip()
    p = root / (env + "-token")
    p.write_text(token)
    p.chmod(0o600)
    namespace = json.loads(kube("get", "namespace", ns, "-o", "json"))
    now = datetime.now(timezone.utc)
    expiry = datetime.fromisoformat(
        json.loads((root / "session.json").read_text())["deadline"]
    )
    registration = KubernetesReadRegistration(
        "local-operator",
        "order-service",
        "local-k3s-" + env,
        "docker-desktop-test",
        endpoint,
        ("127.0.0.1",),
        hashlib.sha256(ca).hexdigest(),
        ns,
        namespace["metadata"]["uid"],
        1,
        now - timedelta(seconds=1),
        expiry,
    )
    p = root / (env + "-registration.json")
    p.write_text(json.dumps(registration.document, indent=2))
    p.chmod(0o600)
    # Test real RBAC using the actual scoped token; no Secret objects are retrieved.
    token_config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "test",
                "cluster": {
                    "server": endpoint,
                    "certificate-authority-data": base64.b64encode(ca).decode(),
                },
            }
        ],
        "users": [{"name": "reader", "user": {"token": token}}],
        "contexts": [
            {"name": "test", "context": {"cluster": "test", "user": "reader"}}
        ],
        "current-context": "test",
    }
    p = root / (env + "-reader-kubeconfig.json")
    p.write_text(json.dumps(token_config))
    p.chmod(0o600)
    checks = {}
    for check in [
        ("list", "deployments", "-n", ns),
        ("list", "secrets", "-n", ns),
        ("create", "deployments", "-n", ns),
        (
            "list",
            "deployments",
            "-n",
            "sova-live-green" if env == "blue" else "sova-live-blue",
        ),
    ]:
        result = subprocess.run(
            ["kubectl", "--kubeconfig", str(p), "auth", "can-i", *check],
            capture_output=True,
            text=True,
            timeout=15,
        )
        checks[" ".join(check)] = result.stdout.strip()
    if list(checks.values()) != ["yes", "no", "no", "no"]:
        raise RuntimeError("Scoped reader RBAC qualification failed")
    registrations.append(
        {
            "environment": env,
            "namespace_uid": namespace["metadata"]["uid"],
            "registration_digest": registration.fingerprint,
            "rbac_checks": checks,
        }
    )
(root / "reader-checks.json").write_text(json.dumps(registrations, indent=2) + "\n")
print(
    "Two scoped readers prepared. Actual RBAC: intended list allowed; Secret/mutation/other environment denied."
)
