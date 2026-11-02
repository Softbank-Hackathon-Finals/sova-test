"""Qualification-only per-plan Kubernetes access manifests.

Apply through a separate trusted administrator, never through the worker token.
RBAC cannot constrain CREATE by resourceNames, so a fail-closed admission policy
also binds the quarantine name, selector, operator-pinned namespace labels and approved plan.
This is not a remote credential broker or a substitute for runtime plan expiry.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from sova.domain.contracts import ContractError, digest, identifier


def literal(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"))


@dataclass(frozen=True, slots=True)
class KubernetesAccessProfile:
    operation_id: str
    plan_digest: str
    application_id: str
    account_namespace: str
    source_namespace: str
    source_namespace_uid: str
    target_namespace: str
    target_namespace_uid: str
    source_deployment_uid: str
    target_deployment_uid: str
    source_name: str
    target_name: str
    target_configmaps: tuple[str, ...]

    def __post_init__(self):
        identifier(self.operation_id)
        digest(self.plan_digest)
        identifier(self.application_id)
        if not re.fullmatch(
            r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,61}[A-Za-z0-9])?", self.application_id
        ):
            raise ContractError("Application identity must fit a Kubernetes label")
        for key in (
            "account_namespace",
            "source_namespace",
            "target_namespace",
            "source_name",
            "target_name",
        ):
            if type(getattr(self, key)) is not str or not re.fullmatch(
                r"[a-z][a-z0-9-]{0,62}", getattr(self, key)
            ):
                raise ContractError("Named scoped Kubernetes access required")
        for key in (
            "source_namespace_uid",
            "target_namespace_uid",
            "source_deployment_uid",
            "target_deployment_uid",
        ):
            identifier(getattr(self, key))
        if (
            self.source_namespace == self.target_namespace
            or self.source_namespace_uid == self.target_namespace_uid
        ):
            raise ContractError("Distinct access namespaces required")
        if (
            type(self.target_configmaps) is not tuple
            or not 1 <= len(self.target_configmaps) <= 8
            or len(set(self.target_configmaps)) != len(self.target_configmaps)
        ):
            raise ContractError("Explicit bounded immutable ConfigMaps required")
        for name in self.target_configmaps:
            if type(name) is not str or not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name):
                raise ContractError("Named ConfigMap access required")

    @property
    def name(self):
        return (
            "sova-response-"
            + hashlib.sha256(
                (self.operation_id + "\0" + self.plan_digest).encode()
            ).hexdigest()[:20]
        )

    @property
    def subject(self):
        return "system:serviceaccount:" + self.account_namespace + ":" + self.name

    def manifests(self):
        name = self.name
        account = {
            "kind": "ServiceAccount",
            "namespace": self.account_namespace,
            "name": name,
        }

        def role(ns, rules):
            return {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {"name": name, "namespace": ns},
                "rules": rules,
            }

        def binding(ns):
            return {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": name, "namespace": ns},
                "subjects": [account],
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": name,
                },
            }

        objects = [
            {
                "apiVersion": "v1",
                "kind": "ServiceAccount",
                "metadata": {"name": name, "namespace": self.account_namespace},
                "automountServiceAccountToken": False,
            }
        ]
        objects.extend(
            [
                role(
                    self.source_namespace,
                    [
                        {
                            "apiGroups": ["apps"],
                            "resources": ["deployments"],
                            "resourceNames": [self.source_name],
                            "verbs": ["get"],
                        },
                        {
                            "apiGroups": [""],
                            "resources": ["services"],
                            "resourceNames": [self.source_name],
                            "verbs": ["get"],
                        },
                        {
                            "apiGroups": ["networking.k8s.io"],
                            "resources": ["networkpolicies"],
                            "verbs": ["get", "list", "create"],
                        },
                    ],
                ),
                binding(self.source_namespace),
                role(
                    self.target_namespace,
                    [
                        {
                            "apiGroups": ["apps"],
                            "resources": ["deployments"],
                            "resourceNames": [self.target_name],
                            "verbs": ["get", "patch"],
                        },
                        {
                            "apiGroups": [""],
                            "resources": ["services"],
                            "resourceNames": [self.target_name],
                            "verbs": ["get"],
                        },
                        {
                            "apiGroups": [""],
                            "resources": ["configmaps"],
                            "resourceNames": list(self.target_configmaps),
                            "verbs": ["get"],
                        },
                    ],
                ),
                binding(self.target_namespace),
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRole",
                    "metadata": {"name": name},
                    "rules": [
                        {
                            "apiGroups": [""],
                            "resources": ["namespaces"],
                            "resourceNames": [
                                self.source_namespace,
                                self.target_namespace,
                            ],
                            "verbs": ["get"],
                        }
                    ],
                },
                {
                    "apiVersion": "rbac.authorization.k8s.io/v1",
                    "kind": "ClusterRoleBinding",
                    "metadata": {"name": name},
                    "subjects": [account],
                    "roleRef": {
                        "apiGroup": "rbac.authorization.k8s.io",
                        "kind": "ClusterRole",
                        "name": name,
                    },
                },
            ]
        )
        policies = [
            (
                "quarantine",
                "networking.k8s.io",
                "networkpolicies",
                ["CREATE"],
                [
                    "request.namespace == " + literal(self.source_namespace),
                    'has(namespaceObject.metadata.labels) && namespaceObject.metadata.labels["io.sova/access-instance"] == '
                    + literal(self.source_namespace_uid),
                    "object.metadata.name == "
                    + literal("sova-quarantine-" + self.plan_digest[:20]),
                    'has(object.metadata.annotations) && object.metadata.annotations["io.sova/plan-digest"] == '
                    + literal(self.plan_digest),
                    'has(object.metadata.annotations) && object.metadata.annotations["io.sova/source-uid"] == '
                    + literal(self.source_deployment_uid),
                    "has(object.spec.podSelector.matchLabels) && object.spec.podSelector.matchLabels == "
                    + literal(
                        {
                            "app.kubernetes.io/name": self.source_name,
                            "app.kubernetes.io/part-of": self.application_id,
                        }
                    ),
                    "!has(object.spec.podSelector.matchExpressions) || size(object.spec.podSelector.matchExpressions)==0",
                    'size(object.spec.policyTypes)==2 && "Ingress" in object.spec.policyTypes && "Egress" in object.spec.policyTypes',
                    "!has(object.spec.ingress) || size(object.spec.ingress)==0",
                    "!has(object.spec.egress) || size(object.spec.egress)==0",
                ],
            ),
            (
                "replacement",
                "apps",
                "deployments",
                ["UPDATE"],
                [
                    "request.namespace == " + literal(self.target_namespace),
                    'has(namespaceObject.metadata.labels) && namespaceObject.metadata.labels["io.sova/access-instance"] == '
                    + literal(self.target_namespace_uid),
                    "object.metadata.name == " + literal(self.target_name),
                    'has(oldObject.metadata.labels) && oldObject.metadata.labels["io.sova/access-instance"] == '
                    + literal(self.target_deployment_uid),
                    'has(oldObject.metadata.labels) && oldObject.metadata.labels["app.kubernetes.io/part-of"] == '
                    + literal(self.application_id),
                    "oldObject.spec.replicas == 0 && object.spec.replicas == 1",
                    "object.spec.template == oldObject.spec.template",
                    "object.spec.selector == oldObject.spec.selector",
                ],
            ),
        ]
        # Pin all other apps/v1 DeploymentSpec fields. This qualified version's
        # scope is fixed; schema upgrades require requalification.
        for field in (
            "strategy",
            "minReadySeconds",
            "revisionHistoryLimit",
            "progressDeadlineSeconds",
            "paused",
        ):
            policies[1][4].append(
                "has(object.spec."
                + field
                + ") == has(oldObject.spec."
                + field
                + ") && (!has(oldObject.spec."
                + field
                + ") || object.spec."
                + field
                + " == oldObject.spec."
                + field
                + ")"
            )
        for field in ("labels", "annotations", "ownerReferences", "finalizers"):
            policies[1][4].append(
                "has(object.metadata."
                + field
                + ") == has(oldObject.metadata."
                + field
                + ") && (!has(oldObject.metadata."
                + field
                + ") || object.metadata."
                + field
                + " == oldObject.metadata."
                + field
                + ")"
            )
        for suffix, group, resource, operations, validations in policies:
            policy_name = name + "-" + suffix
            objects.append(
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicy",
                    "metadata": {"name": policy_name},
                    "spec": {
                        "failurePolicy": "Fail",
                        "matchConstraints": {
                            "resourceRules": [
                                {
                                    "apiGroups": [group],
                                    "apiVersions": ["v1"],
                                    "operations": operations,
                                    "resources": [resource],
                                }
                            ]
                        },
                        "matchConditions": [
                            {
                                "name": "exact-worker",
                                "expression": "request.userInfo.username == "
                                + literal(self.subject),
                            }
                        ],
                        "validations": [
                            {
                                "expression": expression,
                                "message": "Approved Sova response scope or immutable configuration differs",
                            }
                            for expression in validations
                        ],
                    },
                }
            )
            objects.append(
                {
                    "apiVersion": "admissionregistration.k8s.io/v1",
                    "kind": "ValidatingAdmissionPolicyBinding",
                    "metadata": {"name": policy_name},
                    "spec": {"policyName": policy_name, "validationActions": ["Deny"]},
                }
            )
        return tuple(objects)
