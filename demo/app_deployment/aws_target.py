"""Registered AWS EKS deployment. Uses only the configured personal SSO profile."""

import base64
import json
import os
import re
import tempfile
import time

from .builder import run


def manifests(app_id, image, health, source_digest):
    if (
        not re.fullmatch(r"[a-f0-9]{16}", app_id)
        or "@sha256:" not in image
        or not re.fullmatch(r"/[A-Za-z0-9/_-]*", health)
    ):
        raise ValueError("invalid_registered_app")
    ns = "sova-app-" + app_id
    labels = {
        "app.kubernetes.io/name": "app",
        "app.kubernetes.io/part-of": "sova-upload",
        "sova.dev/app": app_id,
        "component": "source",
    }
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": ns,
                    "labels": {
                        "sova.dev/app": app_id,
                        "component": "source",
                        "pod-security.kubernetes.io/enforce": "restricted",
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "ResourceQuota",
                "metadata": {"name": "budget", "namespace": ns},
                "spec": {
                    "hard": {
                        "pods": "6",
                        "requests.cpu": "1",
                        "limits.cpu": "3",
                        "requests.memory": "512Mi",
                        "limits.memory": "2Gi",
                    }
                },
            },
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {"name": "app-boundary", "namespace": ns},
                "spec": {
                    "podSelector": {},
                    "policyTypes": ["Ingress", "Egress"],
                    "ingress": [{"from": [{"podSelector": {}}]}],
                    "egress": [
                        {"to": [{"podSelector": {}}]},
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
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {
                    "name": "app",
                    "namespace": ns,
                    "labels": labels,
                    "annotations": {"sova.dev/source-sha256": source_digest},
                },
                "spec": {
                    "replicas": 2,
                    "selector": {"matchLabels": {"sova.dev/app": app_id}},
                    "strategy": {
                        "type": "RollingUpdate",
                        "rollingUpdate": {"maxUnavailable": 0, "maxSurge": 1},
                    },
                    "template": {
                        "metadata": {"labels": labels},
                        "spec": {
                            "automountServiceAccountToken": False,
                            "securityContext": {
                                "runAsNonRoot": True,
                                "runAsUser": 10001,
                                "runAsGroup": 10001,
                                "seccompProfile": {"type": "RuntimeDefault"},
                            },
                            "containers": [
                                {
                                    "name": "app",
                                    "image": image,
                                    "ports": [{"containerPort": 8080}],
                                    "env": [{"name": "PORT", "value": "8080"}],
                                    "resources": {
                                        "requests": {"cpu": "50m", "memory": "64Mi"},
                                        "limits": {"cpu": "500m", "memory": "256Mi"},
                                    },
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "readinessProbe": {
                                        "httpGet": {"path": health, "port": 8080},
                                        "periodSeconds": 3,
                                    },
                                    "volumeMounts": [
                                        {"name": "tmp", "mountPath": "/tmp"}
                                    ],
                                }
                            ],
                            "volumes": [
                                {"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}
                            ],
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "app", "namespace": ns, "labels": labels},
                "spec": {
                    "selector": {"sova.dev/app": app_id},
                    "ports": [{"port": 8080, "targetPort": 8080}],
                },
            },
        ],
    }


class AwsTarget:
    def __init__(self, settings):
        self.settings = settings
        if settings["profile"] != "bravo-personal":
            raise ValueError("personal_profile_required")
        self.env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("AWS_")
            and k.lower() not in {"http_proxy", "https_proxy", "all_proxy"}
        }
        self.env.update(
            AWS_PROFILE="bravo-personal",
            AWS_REGION="ap-northeast-2",
            AWS_EC2_METADATA_DISABLED="true",
            AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true",
            AWS_PAGER="",
        )

    def aws(self, *args):
        return json.loads(
            run(
                [
                    "aws",
                    "--profile",
                    "bravo-personal",
                    "--region",
                    "ap-northeast-2",
                    *args,
                    "--output",
                    "json",
                ],
                env=self.env,
                timeout=60,
            )
        )

    def kube(self, *args, data=None):
        return run(
            [
                "kubectl",
                "--kubeconfig",
                self.settings["source_kubeconfig"],
                "--request-timeout=20s",
                *args,
            ],
            env=self.env,
            stdin=json.dumps(data) if data is not None else None,
            timeout=240,
        )

    def verify(self):
        who = self.aws("sts", "get-caller-identity")
        if who["Account"] != self.settings["account"] or not who["Arn"].endswith(
            self.settings["operator_arn_suffix"]
        ):
            raise ValueError("operator_identity_mismatch")
        uid = self.kube("get", "ns", "kube-system", "-o", "jsonpath={.metadata.uid}")
        if uid != self.settings["source_cluster_uid"]:
            raise ValueError("source_cluster_mismatch")

    def publish(self, built, app_id):
        self.verify()
        repo = "sova/apps"
        all_repos = self.aws("ecr", "describe-repositories")["repositories"]
        found = next((r for r in all_repos if r["repositoryName"] == repo), None)
        if found is None:
            found = self.aws(
                "ecr",
                "create-repository",
                "--repository-name",
                repo,
                "--image-tag-mutability",
                "IMMUTABLE",
                "--image-scanning-configuration",
                "scanOnPush=true",
                "--tags",
                "Key=component,Value=source",
                "Key=project,Value=bravo",
                "Key=managed-by,Value=sova-app-deployment",
            )["repository"]
        tags = self.aws(
            "ecr", "list-tags-for-resource", "--resource-arn", found["repositoryArn"]
        )["tags"]
        if {t["Key"]: t["Value"] for t in tags}.get(
            "managed-by"
        ) != "sova-app-deployment":
            raise ValueError("repository_owner_mismatch")
        tag = app_id + "-" + built["source_digest"][:16]
        image = found["repositoryUri"] + ":" + tag
        auth = self.aws("ecr", "get-authorization-token")["authorizationData"][0]
        username, password = (
            base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
        )
        endpoint = json.loads(
            run(
                [
                    "docker",
                    "context",
                    "inspect",
                    "--format",
                    "{{json .Endpoints.docker.Host}}",
                ]
            )
        )
        with tempfile.TemporaryDirectory(prefix="sova-registry-") as private:
            env = {**self.env, "DOCKER_HOST": endpoint, "DOCKER_CONFIG": private}
            run(
                [
                    "docker",
                    "login",
                    "--username",
                    username,
                    "--password-stdin",
                    auth["proxyEndpoint"],
                ],
                env=env,
                stdin=password,
                timeout=45,
            )
            run(["docker", "tag", built["local_image"], image], env=env)
            run(["docker", "push", image], env=env)
        details = self.aws(
            "ecr",
            "describe-images",
            "--repository-name",
            repo,
            "--image-ids",
            "imageTag=" + tag,
        )["imageDetails"][0]
        return found["repositoryUri"] + "@" + details["imageDigest"]

    def deploy(self, app_id, image, health, source_digest):
        self.verify()
        ns = "sova-app-" + app_id
        # CREATE, not apply/upsert: an existing namespace must never be adopted.
        spec = manifests(app_id, image, health, source_digest)
        for item in spec["items"]:
            self.kube("create", "-f", "-", "-o", "json", data=item)
        self.kube("-n", ns, "rollout", "status", "deployment/app", "--timeout=180s")
        pods = json.loads(
            self.kube(
                "-n", ns, "get", "pods", "-l", "sova.dev/app=" + app_id, "-o", "json"
            )
        )["items"]
        if len(pods) != 2 or any(
            not p["status"].get("containerStatuses", [{}])[0].get("ready") for p in pods
        ):
            raise ValueError("deployment_not_ready")
        expected = image.split("@")[1]
        if any(
            expected not in p["status"]["containerStatuses"][0].get("imageID", "")
            for p in pods
        ):
            raise ValueError("runtime_digest_mismatch")
        service = json.loads(self.kube("-n", ns, "get", "service", "app", "-o", "json"))
        # API proxy is a read-only health check, never the application's public URL.
        response = self.kube(
            "get", "--raw", f"/api/v1/namespaces/{ns}/services/app:8080/proxy" + health
        )
        return {
            "namespace": ns,
            "service_uid": service["metadata"]["uid"],
            "pod_uids": [p["metadata"]["uid"] for p in pods],
            "image": image,
            "ready_replicas": 2,
            "http_verified": True,
            "health_response_digest": __import__("hashlib")
            .sha256(response.encode())
            .hexdigest(),
            "environment": "AWS EKS",
            "migration_complete": False,
        }

    def publish_url(self, app_id, tunnel_image):
        if not re.fullmatch(
            r"cloudflare/cloudflared@sha256:[a-f0-9]{64}", tunnel_image
        ):
            raise ValueError("pinned_tunnel_image_required")
        self.verify()
        ns = "sova-app-" + app_id
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": "public-edge",
                "namespace": ns,
                "labels": {"sova.dev/edge": app_id, "component": "source"},
            },
            "spec": {
                "automountServiceAccountToken": False,
                "securityContext": {
                    "runAsNonRoot": True,
                    "runAsUser": 65532,
                    "runAsGroup": 65532,
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                "containers": [
                    {
                        "name": "tunnel",
                        "image": tunnel_image,
                        "args": [
                            "tunnel",
                            "--no-autoupdate",
                            "--protocol",
                            "http2",
                            "--url",
                            "http://app:8080",
                        ],
                        "securityContext": {
                            "allowPrivilegeEscalation": False,
                            "readOnlyRootFilesystem": True,
                            "capabilities": {"drop": ["ALL"]},
                        },
                        "resources": {
                            "requests": {"cpu": "25m", "memory": "32Mi"},
                            "limits": {"cpu": "250m", "memory": "128Mi"},
                        },
                    }
                ],
            },
        }
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "public-edge-egress", "namespace": ns},
            "spec": {
                "podSelector": {"matchLabels": {"sova.dev/edge": app_id}},
                "policyTypes": ["Egress"],
                "egress": [
                    {
                        "to": [
                            {
                                "ipBlock": {
                                    "cidr": "0.0.0.0/0",
                                    "except": [
                                        "0.0.0.0/8",
                                        "10.0.0.0/8",
                                        "100.64.0.0/10",
                                        "127.0.0.0/8",
                                        "169.254.0.0/16",
                                        "172.16.0.0/12",
                                        "192.168.0.0/16",
                                        "224.0.0.0/4",
                                    ],
                                }
                            }
                        ],
                        "ports": [
                            {"protocol": "TCP", "port": 443},
                            {"protocol": "TCP", "port": 7844},
                        ],
                    }
                ],
            },
        }
        self.kube("create", "-f", "-", data=policy)
        self.kube("create", "-f", "-", data=pod)
        self.kube(
            "-n",
            ns,
            "wait",
            "--for=condition=Ready",
            "pod/public-edge",
            "--timeout=90s",
        )
        for _ in range(25):
            logs = self.kube("-n", ns, "logs", "public-edge", "--tail=100")
            match = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", logs)
            if match:
                from .intake import download

                url = match.group()
                try:
                    download(url, 2 * 1024 * 1024)
                except Exception:
                    time.sleep(2)
                    continue
                return url
            time.sleep(2)
        raise ValueError("public_http_not_verified")
