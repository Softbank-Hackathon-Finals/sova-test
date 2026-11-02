"""Owned demo setup step; invoked by security_demo.py, never from HTTP."""

import sys
from pathlib import Path
import subprocess
import json
import hashlib
from sova.domain.contracts import canonical_json

r = Path(sys.argv[1]).resolve()
cmd = [
    "kubectl",
    "--kubeconfig",
    str(r / "admin-kubeconfig.json"),
    "--request-timeout=10s",
]
for ns in ("sova-live-blue", "sova-live-green"):
    p = subprocess.run(
        cmd
        + [
            "-n",
            ns,
            "patch",
            "configmap",
            "api-code",
            "--type=merge",
            "-p",
            '{"immutable":true}',
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if p.returncode:
        raise RuntimeError("Owned code freeze failed")


def get(kind, name):
    return json.loads(
        subprocess.run(
            cmd + ["-n", "sova-live-green", "get", kind, name, "-o", "json"],
            capture_output=True,
            text=True,
            check=True,
            timeout=20,
        ).stdout
    )


deployment = get("deployment", "api")
template = deployment["spec"]["template"]
maps = []
for volume in template["spec"].get("volumes", []):
    name = volume["configMap"]["name"]
    data = get("configmap", name)
    if data.get("immutable") is not True:
        raise RuntimeError("Clean target code must be immutable")
    maps.append(
        {
            "name": name,
            "uid": data["metadata"]["uid"],
            "data_digest": hashlib.sha256(
                canonical_json(data.get("data", {}), limit=65536).encode()
            ).hexdigest(),
        }
    )
digest = hashlib.sha256(
    canonical_json({"template": template, "configmaps": maps}, limit=65536).encode()
).hexdigest()
(r / "clean-target-proof.json").write_text(
    json.dumps(
        {
            "configuration_digest": digest,
            "image": deployment["spec"]["template"]["spec"]["containers"][0]["image"],
            "deployment_uid": deployment["metadata"]["uid"],
            "scope": "registered immutable local test fixture",
        },
        indent=2,
    )
    + "\n"
)
print("Clean target image and immutable configuration admitted before fault injection.")
