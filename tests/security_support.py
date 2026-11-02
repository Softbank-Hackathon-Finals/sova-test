"""Sanitized security snapshot fixture; no live collector authority."""

from datetime import timedelta
import hashlib
from sova.adapters.kubernetes.inventory import snapshot_graph
from sova.adapters.kubernetes.posture import posture_projection
from sova.adapters.security_codec import decode_finding
from sova.domain.security_events import SecuritySnapshot


def security_snapshot(scope, now, *, revision="5"):
    namespace = "orders"
    app = scope.application_id
    item = {
        "kind": "Deployment",
        "metadata": {
            "name": "api",
            "namespace": namespace,
            "uid": "uid-api-"
            + hashlib.sha256(scope.environment_id.encode()).hexdigest()[:10],
            "resourceVersion": revision,
            "labels": {"app.kubernetes.io/part-of": app},
        },
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "api"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [
                        {
                            "name": "api",
                            "image": "registry.example/api@sha256:" + "a" * 64,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
                        }
                    ],
                },
            }
        },
    }
    graph = snapshot_graph(
        {"kind": "List", "items": [item]},
        tenant_id=scope.tenant_id,
        application_id=app,
        environment_id=scope.environment_id,
        namespace=namespace,
        location="test",
        observed_at=now,
        valid_until=now + timedelta(minutes=5),
    )
    findings = tuple(
        decode_finding(f) for f in posture_projection((item,), graph)["findings"]
    )
    return SecuritySnapshot(graph, findings, "a" * 64)
