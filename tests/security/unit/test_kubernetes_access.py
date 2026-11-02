"""Credential scope construction; actual RBAC/CEL effects have separate live evidence."""

from dataclasses import replace
import json
import pytest
from kubernetes_access import KubernetesAccessProfile
from sova.domain.contracts import ContractError


def profile():
    return KubernetesAccessProfile(
        "operation-1",
        "a" * 64,
        "orders",
        "executors",
        "source",
        "ns-source",
        "target",
        "ns-target",
        "deployment-source",
        "deployment-target",
        "api",
        "api",
        ("code",),
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_namespace", "*"),
        ("target_name", "api/scale"),
        ("account_namespace", "../../system"),
        ("application_id", 'x" || true || "x'),
        ("application_id", "x" * 64),
        ("target_configmaps", ("*",)),
        ("target_configmaps", ()),
        ("target_configmaps", ("code", "code")),
        ("plan_digest", "not-a-digest"),
    ],
)
def test_unbounded_or_injected_access_profile_is_rejected(field, value):
    with pytest.raises(ContractError):
        replace(profile(), **{field: value})


def test_aliases_rejected_and_operation_text_is_not_cel_source():
    p = profile()
    with pytest.raises(ContractError):
        replace(p, target_namespace=p.source_namespace)
    with pytest.raises(ContractError):
        replace(p, target_namespace_uid=p.source_namespace_uid)
    quoted = replace(p, operation_id='operator" || true || "injection')
    docs = quoted.manifests()
    assert quoted.operation_id not in json.dumps(docs)
    policies = [o for o in docs if o["kind"] == "ValidatingAdmissionPolicy"]
    assert all(o["spec"]["failurePolicy"] == "Fail" for o in policies)
    assert all(
        quoted.subject in o["spec"]["matchConditions"][0]["expression"]
        for o in policies
    )


def test_worker_has_no_secret_role_or_admission_administration_grant():
    p = profile()
    roles = [o for o in p.manifests() if o["kind"] in ("Role", "ClusterRole")]
    for role in roles:
        for rule in role["rules"]:
            assert not {
                "*",
                "secrets",
                "roles",
                "rolebindings",
                "pods",
                "pods/exec",
                "serviceaccounts/token",
                "validatingadmissionpolicies",
            } & set(rule["resources"])
            assert "*" not in rule["verbs"]
    target = next(
        o
        for o in roles
        if o["kind"] == "Role" and o["metadata"]["namespace"] == "target"
    )
    assert all("resourceNames" in r for r in target["rules"])
