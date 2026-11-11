"""Finite, local-only resources. No host mounts, privileged pods or cloud calls."""

import re

OWNER = "sova-local-response-20261112"
NAMESPACES = {
    "source": "sova-response-source",
    "target": "sova-response-target",
    "control": "sova-response-control",
}
ROLES = {
    "source": ["api", "worker", "auth", "objects", "external"],
    "target": ["api", "worker"],
    "control": ["edge", "probe"],
}


def labels(role=None):
    value = {"sova.io/owner": OWNER}
    if role:
        value["sova.io/role"] = role
    return value


def meta(name, namespace=None):
    return {
        "name": name,
        "labels": labels(),
        **({"namespace": namespace} if namespace else {}),
    }


def workload(role, side, image):
    ns = NAMESPACES[side]
    env = {
        "ROLE": role,
        "ENVIRONMENT": "local-" + side,
        "DB_HOST": "db." + NAMESPACES[side if side != "control" else "source"],
        "AUTH_HOST": "auth." + NAMESPACES["source"],
        "EXTERNAL_HOST": "external." + NAMESPACES["source"],
        "SOURCE_API": "api." + NAMESPACES["source"],
        "TARGET_API": "api." + NAMESPACES["target"],
    }
    replicas = 0 if side == "target" and role in {"api", "worker"} else 1
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": meta(role, ns),
        "spec": {
            "replicas": replicas,
            "revisionHistoryLimit": 3,
            "selector": {"matchLabels": labels(role)},
            "strategy": {
                "type": "RollingUpdate",
                "rollingUpdate": {"maxSurge": 1, "maxUnavailable": 0},
            },
            "template": {
                "metadata": {"labels": labels(role)},
                "spec": {
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "terminationGracePeriodSeconds": 5,
                    "securityContext": {
                        "runAsUser": 10001,
                        "runAsGroup": 10001,
                        "fsGroup": 10001,
                        "runAsNonRoot": True,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "workload",
                            "image": image,
                            "imagePullPolicy": "Never",
                            "env": [{"name": k, "value": v} for k, v in env.items()]
                            + [
                                {
                                    "name": "POD_UID",
                                    "valueFrom": {
                                        "fieldRef": {"fieldPath": "metadata.uid"}
                                    },
                                }
                            ],
                            "ports": [{"containerPort": 8080}],
                            "resources": {
                                "requests": {"cpu": "10m", "memory": "32Mi"},
                                "limits": {"cpu": "250m", "memory": "128Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "readinessProbe": {
                                "httpGet": {"path": "/ready", "port": 8080},
                                "periodSeconds": 2,
                                "timeoutSeconds": 1,
                            },
                            "volumeMounts": [
                                {
                                    "name": "credentials",
                                    "mountPath": "/credentials",
                                    "readOnly": True,
                                },
                                {"name": "tmp", "mountPath": "/tmp"},
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "credentials",
                            "secret": {
                                "secretName": "workload-credentials",
                                "defaultMode": 288,
                                "items": [
                                    {"key": key, "path": key}
                                    for key in (
                                        ["password", "admin", "dbadmin"]
                                        if role == "probe"
                                        else ["password", "admin"]
                                    )
                                ],
                            },
                        },
                        {"name": "tmp", "emptyDir": {"sizeLimit": "8Mi"}},
                    ],
                },
            },
        },
    }


def database(side, image):
    ns = NAMESPACES[side]
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": meta("db", ns),
        "spec": {
            "replicas": 1,
            "strategy": {"type": "Recreate"},
            "selector": {"matchLabels": labels("db")},
            "template": {
                "metadata": {"labels": labels("db")},
                "spec": {
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 999,
                        "runAsGroup": 999,
                        "fsGroup": 999,
                        "seccompProfile": {"type": "RuntimeDefault"},
                    },
                    "containers": [
                        {
                            "name": "postgres",
                            "image": image,
                            "imagePullPolicy": "Never",
                            "env": [
                                {
                                    "name": "PGDATA",
                                    "value": "/var/lib/postgresql/data/pgdata",
                                },
                                {"name": "POSTGRES_DB", "value": "workload"},
                                {
                                    "name": "POSTGRES_PASSWORD_FILE",
                                    "value": "/credentials/dbadmin",
                                },
                                {"name": "POSTGRES_USER", "value": "postgres"},
                            ],
                            "resources": {
                                "requests": {"cpu": "20m", "memory": "96Mi"},
                                "limits": {"cpu": "500m", "memory": "256Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                            "ports": [{"containerPort": 5432}],
                            "readinessProbe": {
                                "exec": {
                                    "command": [
                                        "pg_isready",
                                        "-U",
                                        "postgres",
                                        "-d",
                                        "workload",
                                    ]
                                },
                                "periodSeconds": 2,
                            },
                            "volumeMounts": [
                                {
                                    "name": "data",
                                    "mountPath": "/var/lib/postgresql/data",
                                },
                                {"name": "run", "mountPath": "/var/run/postgresql"},
                                {"name": "tmp", "mountPath": "/tmp"},
                                {
                                    "name": "credentials",
                                    "mountPath": "/credentials",
                                    "readOnly": True,
                                },
                            ],
                        }
                    ],
                    "volumes": [
                        {
                            "name": "data",
                            "persistentVolumeClaim": {"claimName": "workload-data"},
                        },
                        {"name": "run", "emptyDir": {"sizeLimit": "8Mi"}},
                        {"name": "tmp", "emptyDir": {"sizeLimit": "8Mi"}},
                        {
                            "name": "credentials",
                            "secret": {
                                "secretName": "workload-credentials",
                                "defaultMode": 288,
                                "items": [{"key": "dbadmin", "path": "dbadmin"}],
                            },
                        },
                    ],
                },
            },
        },
    }


def documents(image, pg_image, password, admin, dbadmin):
    if not all(
        re.fullmatch(r"localhost/sova-response/(app|db)@sha256:[a-f0-9]{64}", item)
        for item in (image, pg_image)
    ):
        raise ValueError("Imported, immutable local images required")
    docs = [
        {
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": meta("sova-response-local"),
            "provisioner": "kubernetes.io/no-provisioner",
            "volumeBindingMode": "WaitForFirstConsumer",
            "reclaimPolicy": "Retain",
        }
    ]
    for side, ns in NAMESPACES.items():
        namespace = meta(ns)
        namespace["labels"].update({"pod-security.kubernetes.io/enforce": "restricted"})
        docs += [
            {"apiVersion": "v1", "kind": "Namespace", "metadata": namespace},
            {
                "apiVersion": "v1",
                "kind": "ResourceQuota",
                "metadata": meta("bounds", ns),
                "spec": {
                    "hard": {
                        "pods": "16",
                        "requests.cpu": "1",
                        "requests.memory": "1Gi",
                        "limits.cpu": "6",
                        "limits.memory": "3Gi",
                        "requests.storage": "2Gi",
                    }
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": meta("workload-credentials", ns),
                "stringData": {
                    "password": password,
                    "admin": admin,
                    "dbadmin": dbadmin,
                },
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": meta("namespace-boundary", ns),
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [
                        {"from": [{"namespaceSelector": {"matchLabels": labels()}}]}
                    ],
                    "egress": [
                        {"to": [{"namespaceSelector": {"matchLabels": labels()}}]},
                        {
                            "to": [
                                {
                                    "namespaceSelector": {
                                        "matchLabels": {
                                            "kubernetes.io/metadata.name": "kube-system"
                                        }
                                    },
                                    "podSelector": {
                                        "matchLabels": {"k8s-app": "kube-dns"}
                                    },
                                }
                            ],
                            "ports": [
                                {"protocol": "UDP", "port": 53},
                                {"protocol": "TCP", "port": 53},
                            ],
                        },
                    ],
                },
            },
        ]
        if side != "control":
            docs.append(
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolume",
                    "metadata": meta("sova-response-" + side),
                    "spec": {
                        "capacity": {"storage": "512Mi"},
                        "accessModes": ["ReadWriteOnce"],
                        "persistentVolumeReclaimPolicy": "Retain",
                        "storageClassName": "sova-response-local",
                        "local": {"path": "/var/lib/sova-local-response/" + side},
                        "claimRef": {"namespace": ns, "name": "workload-data"},
                        "nodeAffinity": {
                            "required": {
                                "nodeSelectorTerms": [
                                    {
                                        "matchExpressions": [
                                            {
                                                "key": "kubernetes.io/hostname",
                                                "operator": "In",
                                                "values": ["sova-rke2-target"],
                                            }
                                        ]
                                    }
                                ]
                            }
                        },
                    },
                }
            )
            docs.append(
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": meta("workload-data", ns),
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "storageClassName": "sova-response-local",
                        "resources": {"requests": {"storage": "512Mi"}},
                    },
                }
            )
            docs.append(database(side, pg_image))
            docs.append(service("db", ns, 5432))
        for role in ROLES[side]:
            docs += [workload(role, side, image), service(role, ns)]
    return docs


def service(role, ns, port=8080):
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": meta(role, ns),
        "spec": {
            "selector": labels(role),
            "ports": [{"port": port, "targetPort": port}],
        },
    }


def isolation(role, *, egress_only=False):
    # Kubernetes policies are additive. Match isolated Pods out of the broad
    # namespace-boundary allow policy before this policy is installed.
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": meta("isolate-" + role, NAMESPACES["source"]),
        "spec": {
            "podSelector": {"matchLabels": labels(role)},
            "policyTypes": ["Egress"] if egress_only else ["Ingress", "Egress"],
            "ingress": [],
            "egress": [],
        },
    }
