from copy import deepcopy
from datetime import timedelta
import json

import pytest

from sova.adapters.kubernetes.inventory import snapshot_graph
from sova.adapters.kubernetes.posture import posture_projection, workload_projection
from sova.domain.contracts import ContractError


def workload():
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "api",
            "namespace": "orders",
            "uid": "uid-api",
            "resourceVersion": "5",
            "labels": {"app.kubernetes.io/part-of": "orders"},
        },
        "spec": {
            "template": {
                "metadata": {"labels": {"app": "api"}},
                "spec": {
                    "automountServiceAccountToken": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "api",
                            "image": "registry.example/api@sha256:" + "a" * 64,
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
                        }
                    ],
                },
            }
        },
    }


def graph(item, now):
    return snapshot_graph(
        {"kind": "List", "items": [item]},
        tenant_id="tenant",
        application_id="orders",
        environment_id="test",
        namespace="orders",
        location="local-test",
        observed_at=now,
        valid_until=now + timedelta(minutes=5),
    )


def test_safe_config_reports_configuration_not_runtime_proof(now):
    item = workload()
    report = posture_projection((item,), graph(item, now))
    assert len(report["findings"]) == 12
    assert all(
        f["result"] == "pass" and f["basis"] == "configuration"
        for f in report["findings"]
    )
    assert "runtime-enforcement" in report["unverified"]
    assert report["raw_values_included"] is False


@pytest.mark.parametrize(
    "rule,mutation",
    [
        ("no-privileged", lambda p, c: c["securityContext"].update(privileged=True)),
        ("non-root", lambda p, c: p["securityContext"].update(runAsNonRoot=False)),
        (
            "no-escalation",
            lambda p, c: c["securityContext"].update(allowPrivilegeEscalation=True),
        ),
        (
            "read-only-root",
            lambda p, c: c["securityContext"].update(readOnlyRootFilesystem=False),
        ),
        (
            "drop-capabilities",
            lambda p, c: c["securityContext"]["capabilities"].update(add=["SYS_ADMIN"]),
        ),
        (
            "runtime-seccomp",
            lambda p, c: p["securityContext"]["seccompProfile"].update(
                type="Unconfined"
            ),
        ),
        ("no-host-namespaces", lambda p, c: p.update(hostNetwork=True)),
        (
            "no-host-mounts",
            lambda p, c: p.update(
                volumes=[{"name": "host", "hostPath": {"path": "/"}}]
            ),
        ),
        ("no-auto-token", lambda p, c: p.update(automountServiceAccountToken=True)),
        ("digest-pinned-images", lambda p, c: c.update(image="api:latest")),
        ("bounded-resources", lambda p, c: c["resources"]["limits"].update(cpu="-1")),
        (
            "no-literal-sensitive-env",
            lambda p, c: c.update(
                env=[{"name": "OPENAI_API_KEY", "value": "never-persist-me"}]
            ),
        ),
    ],
)
def test_actual_unsafe_fields_fail_the_corresponding_config_rule(rule, mutation):
    item = workload()
    pod = item["spec"]["template"]["spec"]
    mutation(pod, pod["containers"][0])
    assert workload_projection(item)[rule] == "fail"


def test_literal_secret_values_and_keys_not_in_output_or_artifact(now):
    item = workload()
    item["spec"]["template"]["spec"]["containers"][0]["env"] = [
        {"name": "MY_SECRET_TOKEN", "value": "never-persist-me"}
    ]
    report = posture_projection((item,), graph(item, now))
    raw = json.dumps(report)
    assert "never-persist-me" not in raw and "MY_SECRET_TOKEN" not in raw
    assert any(
        f["control_id"] == "no-literal-sensitive-env" and f["result"] == "fail"
        for f in report["findings"]
    )
    changed = deepcopy(item)
    changed["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] = (
        "another-sensitive-value"
    )
    assert posture_projection((changed,), graph(changed, now)) == report


@pytest.mark.parametrize("quantity", ["nonsense", "infinity", True, None])
def test_unrecognized_quantity_is_unknown(quantity):
    item = workload()
    item["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"]["cpu"] = (
        quantity
    )
    assert workload_projection(item)["bounded-resources"] == "unknown"


def test_missing_explicit_non_root_and_token_controls_are_unknown():
    item = workload()
    pod = item["spec"]["template"]["spec"]
    pod.pop("automountServiceAccountToken")
    pod.pop("securityContext")
    result = workload_projection(item)
    assert result["non-root"] == "unknown" and result["no-auto-token"] == "unknown"


def test_posture_cannot_join_other_uid_or_changed_resource_version(now):
    item = workload()
    registered = graph(item, now)
    item["metadata"]["resourceVersion"] = "6"
    with pytest.raises(ContractError):
        posture_projection((item,), registered)


def test_init_container_is_part_of_security_evaluation():
    item = workload()
    pod = item["spec"]["template"]["spec"]
    bad = deepcopy(pod["containers"][0])
    bad["securityContext"]["privileged"] = True
    pod["initContainers"] = [bad]
    assert workload_projection(item)["no-privileged"] == "fail"
