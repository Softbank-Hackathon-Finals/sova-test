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

# One process serves one topology. `local` keeps every side on the pinned
# local RKE2 VM. `hybrid-aws` places the source workload (and a probe beside it)
# on the run-owned EKS cluster, and keeps the target, the entry edge and the
# operator probe on local RKE2. Local pods reach the EKS source API and DB only
# through the supervised SSM bridge on this Mac (see bridge.py).
LOCAL_PROFILE = {
    "name": "local",
    "owner": OWNER,
    "prefix": "sova-response",
    "namespaces": dict(NAMESPACES),
    "placement": {"source": "local", "target": "local", "control": "local"},
    "roles": {side: list(roles) for side, roles in ROLES.items()},
}
HYBRID_PROFILE = {
    "name": "hybrid-aws",
    "owner": "sova-hybrid-response-20261112",
    "prefix": "sova-hybrid",
    "namespaces": {
        "source": "sova-hybrid-source",
        "target": "sova-hybrid-target",
        "control": "sova-hybrid-control",
        "source-control": "sova-hybrid-control",
    },
    "placement": {
        "source": "aws",
        "source-control": "aws",
        "target": "local",
        "control": "local",
    },
    "roles": {
        **{side: list(roles) for side, roles in ROLES.items()},
        "source-control": ["probe"],
    },
}
# Lima forwards guest connections for this gateway address to the Mac's
# loopback, where the SSM port forwards listen.
LIMA_HOST = "192.168.5.2"
BRIDGE = {
    "api": {"service": "source-api", "port": 8080, "local_port": 18180},
    "db": {"service": "source-db", "port": 5432, "local_port": 15432},
}
PROFILE = dict(LOCAL_PROFILE)


def configure(name):
    """Select the topology for this process before any manifest or adapter use."""
    profile = {"local": LOCAL_PROFILE, "hybrid-aws": HYBRID_PROFILE}[name]
    PROFILE.clear()
    PROFILE.update(profile)
    NAMESPACES.clear()
    NAMESPACES.update(profile["namespaces"])
    ROLES.clear()
    ROLES.update({side: list(roles) for side, roles in profile["roles"].items()})
    return PROFILE


def placement(side):
    return PROFILE["placement"][side]


def probe_side(side):
    """The side whose probe runs in the same cluster as `side`."""
    return "source-control" if placement(side) == "aws" else "control"


def host(client, role, side):
    """DNS name a pod on `client` uses to reach `role` on `side`."""
    if placement(client) == placement(side):
        return role + "." + NAMESPACES[side]
    if side != "source" or role not in BRIDGE or placement(client) != "local":
        raise ValueError("no_cross_cluster_path")
    return BRIDGE[role]["service"] + "." + NAMESPACES["control"]


def pull_policy(side):
    # Local images are imported into containerd; EKS pulls pinned ECR digests.
    return "Never" if placement(side) == "local" else "IfNotPresent"


def labels(role=None):
    value = {"sova.io/owner": PROFILE["owner"]}
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
        "ENVIRONMENT": ("aws-" if placement(side) == "aws" else "local-")
        + ("control" if side == "source-control" else side),
        "DB_HOST": host(side, "db", side if side in {"source", "target"} else "source"),
        # Only source workers call these, inside the source cluster.
        "AUTH_HOST": "auth." + NAMESPACES["source"],
        "EXTERNAL_HOST": "external." + NAMESPACES["source"],
        # The entry edge reaches the source API across clusters via the bridge.
        "SOURCE_API": host(side, "api", "source"),
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
                            "imagePullPolicy": pull_policy(side),
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
                            "imagePullPolicy": pull_policy(side),
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


IMAGE_PATTERNS = {
    "local": r"localhost/sova-response/(app|db)@sha256:[a-f0-9]{64}",
    "aws": r"[0-9]{12}\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/sova-response-[a-z0-9]+@sha256:[a-f0-9]{64}",
}


def storage_class(cluster):
    if cluster == "local":
        return {
            "apiVersion": "storage.k8s.io/v1",
            "kind": "StorageClass",
            "metadata": meta(PROFILE["prefix"] + "-local"),
            "provisioner": "kubernetes.io/no-provisioner",
            "volumeBindingMode": "WaitForFirstConsumer",
            "reclaimPolicy": "Retain",
        }
    # Run-owned EBS: deleted with its claim, encrypted at rest.
    return {
        "apiVersion": "storage.k8s.io/v1",
        "kind": "StorageClass",
        "metadata": meta(PROFILE["prefix"] + "-gp3"),
        "provisioner": "ebs.csi.aws.com",
        "parameters": {"type": "gp3", "encrypted": "true"},
        "volumeBindingMode": "WaitForFirstConsumer",
        "reclaimPolicy": "Delete",
        "allowVolumeExpansion": False,
    }


def host_path(side):
    name = (
        "sova-local-response"
        if PROFILE["prefix"] == "sova-response"
        else "sova-hybrid-response"
    )
    return "/var/lib/" + name + "/" + side


def documents(
    image, pg_image, password, admin, dbadmin, *, cluster="local", node_ips=None
):
    """Owned resources for every side placed on `cluster` in the active topology."""
    if not all(
        re.fullmatch(IMAGE_PATTERNS[cluster], item) for item in (image, pg_image)
    ):
        raise ValueError("Pinned, immutable images required")
    sclass = storage_class(cluster)
    docs = [sclass]
    for side, ns in NAMESPACES.items():
        if placement(side) != cluster:
            continue
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
        if side in {"source", "target"} and cluster == "local":
            docs.append(
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolume",
                    "metadata": meta(PROFILE["prefix"] + "-" + side),
                    "spec": {
                        "capacity": {"storage": "512Mi"},
                        "accessModes": ["ReadWriteOnce"],
                        "persistentVolumeReclaimPolicy": "Retain",
                        "storageClassName": sclass["metadata"]["name"],
                        "local": {"path": host_path(side)},
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
        if side in {"source", "target"}:
            docs.append(
                {
                    "apiVersion": "v1",
                    "kind": "PersistentVolumeClaim",
                    "metadata": meta("workload-data", ns),
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "storageClassName": sclass["metadata"]["name"],
                        "resources": {
                            "requests": {
                                "storage": "512Mi" if cluster == "local" else "1Gi"
                            }
                        },
                    },
                }
            )
            docs.append(database(side, pg_image))
            docs.append(service("db", ns, 5432))
        for role in ROLES[side]:
            docs += [workload(role, side, image), service(role, ns)]
    if PROFILE["name"] == "hybrid-aws":
        docs += bridge_documents(cluster, node_ips)
    return docs


def bridge_ingress_from(node_ips):
    """Only the source nodes' own addresses. Pods share the node subnet under
    the VPC CNI, so a subnet range would admit every pod in the cluster."""
    if not node_ips or not all(
        re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", ip) for ip in node_ips
    ):
        raise ValueError("node_addresses_required")
    return [{"ipBlock": {"cidr": ip + "/32"}} for ip in sorted(node_ips)]


def bridge_documents(cluster, node_ips=None):
    """Explicit cross-cluster path: local pods -> Mac loopback -> SSM -> EKS."""
    if cluster == "aws":
        # The SSM agent on the source nodes forwards to the Service ClusterIP,
        # so bridged traffic arrives from a node address. Admit only that range,
        # only to the bridged roles; policy() narrows it when a role is isolated.
        return [
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": meta("bridge-ingress", NAMESPACES["source"]),
                "spec": {
                    "podSelector": {
                        "matchExpressions": [
                            {
                                "key": "sova.io/role",
                                "operator": "In",
                                "values": ["api", "db"],
                            }
                        ]
                    },
                    "policyTypes": ["Ingress"],
                    "ingress": [
                        {
                            "from": bridge_ingress_from(node_ips),
                            "ports": [
                                {"protocol": "TCP", "port": item["port"]}
                                for item in BRIDGE.values()
                            ],
                        }
                    ],
                },
            }
        ]
    ns = NAMESPACES["control"]
    docs = []
    for item in BRIDGE.values():
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": meta(item["service"], ns),
                "spec": {
                    "ports": [
                        {
                            "protocol": "TCP",
                            "port": item["port"],
                            "targetPort": item["local_port"],
                        }
                    ]
                },
            }
        )
        docs.append(
            {
                "apiVersion": "discovery.k8s.io/v1",
                "kind": "EndpointSlice",
                "metadata": {
                    "name": item["service"] + "-bridge",
                    "namespace": ns,
                    "labels": {
                        **labels(),
                        "kubernetes.io/service-name": item["service"],
                        "endpointslice.kubernetes.io/managed-by": "sova-hybrid-bridge",
                    },
                },
                "addressType": "IPv4",
                "ports": [{"protocol": "TCP", "port": item["local_port"]}],
                "endpoints": [
                    {"addresses": [LIMA_HOST], "conditions": {"ready": True}}
                ],
            }
        )
    for side in ("target", "control"):
        docs.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": meta("bridge-egress", NAMESPACES[side]),
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Egress"],
                    "egress": [
                        {
                            "to": [{"ipBlock": {"cidr": LIMA_HOST + "/32"}}],
                            "ports": [
                                {"protocol": "TCP", "port": item["local_port"]}
                                for item in BRIDGE.values()
                            ],
                        }
                    ],
                },
            }
        )
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
