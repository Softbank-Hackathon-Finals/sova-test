"""Deploy only the run-owned stateless fixture to registered EKS and RKE2."""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import subprocess

import boto3


def run(args, *, input=None, timeout=60):
    result = subprocess.run(
        args, input=input, capture_output=True, text=True, timeout=timeout
    )
    if result.returncode:
        raise RuntimeError("Owned workload command refused: " + Path(args[0]).name)
    return result.stdout


def manifest(namespace, image, instance, environment, run_id):
    labels = {
        "app.kubernetes.io/name": "quote",
        "app.kubernetes.io/part-of": "sova-relocation",
        "sova.run": run_id,
    }
    return {
        "apiVersion": "v1",
        "kind": "List",
        "items": [
            {
                "apiVersion": "v1",
                "kind": "Namespace",
                "metadata": {
                    "name": namespace,
                    "labels": {
                        "sova.run": run_id,
                        "pod-security.kubernetes.io/enforce": "restricted",
                    },
                },
            },
            {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": "quote", "namespace": namespace, "labels": labels},
                "spec": {
                    "replicas": 2,
                    "selector": {"matchLabels": labels},
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
                            "terminationGracePeriodSeconds": 20,
                            "containers": [
                                {
                                    "name": "quote",
                                    "image": image,
                                    "imagePullPolicy": "Never"
                                    if environment == "vm"
                                    else "IfNotPresent",
                                    "ports": [{"containerPort": 8080}],
                                    "env": [
                                        {"name": "INSTANCE_ID", "value": instance},
                                        {"name": "ENVIRONMENT", "value": environment},
                                        {
                                            "name": "POD_UID",
                                            "valueFrom": {
                                                "fieldRef": {
                                                    "fieldPath": "metadata.uid"
                                                }
                                            },
                                        },
                                    ],
                                    "resources": {
                                        "requests": {"cpu": "25m", "memory": "32Mi"},
                                        "limits": {"cpu": "200m", "memory": "96Mi"},
                                    },
                                    "securityContext": {
                                        "allowPrivilegeEscalation": False,
                                        "readOnlyRootFilesystem": True,
                                        "capabilities": {"drop": ["ALL"]},
                                    },
                                    "readinessProbe": {
                                        "httpGet": {"path": "/health", "port": 8080},
                                        "periodSeconds": 2,
                                    },
                                }
                            ],
                        },
                    },
                },
            },
            {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": "quote", "namespace": namespace, "labels": labels},
                "spec": {
                    "type": "NodePort" if environment == "vm" else "ClusterIP",
                    "selector": labels,
                    "ports": [
                        {
                            "port": 8080,
                            "targetPort": 8080,
                            **({"nodePort": 30080} if environment == "vm" else {}),
                        }
                    ],
                },
            },
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    owner = json.loads((root / "ownership.json").read_text())
    if datetime.now(UTC) >= datetime.fromisoformat(owner["cleanup_at"]):
        raise RuntimeError("Qualification registration expired")
    session = boto3.Session(region_name=owner["region"])
    if session.client("sts").get_caller_identity()["Account"] != owner["account_id"]:
        raise RuntimeError("Wrong AWS account")
    cluster = session.client("eks").describe_cluster(name=owner["cluster_name"])[
        "cluster"
    ]
    if cluster["status"] != "ACTIVE" or cluster["tags"].get("RunId") != owner["run_id"]:
        raise RuntimeError("Owned EKS is not active")
    outputs = json.loads(
        run(["terraform", "-chdir=" + owner["terraform_dir"], "output", "-json"])
    )
    repository = outputs["repository_url"]["value"]
    image = json.loads((root / "image.json").read_text())
    if not image["image"].startswith(repository + "@sha256:"):
        raise RuntimeError("Owned immutable repository image required")
    namespace = "sova-relocation-" + owner["run_id"]
    records = {}
    for side in ("aws", "vm"):
        config = root / (side + "-kubeconfig.json")
        instance = "sova-probe-" + image["instance_id"] + "-" + side
        doc = manifest(namespace, image["image"], instance, side, owner["run_id"])
        run(
            [
                "kubectl",
                "--kubeconfig",
                str(config),
                "--request-timeout=15s",
                "create",
                "-f",
                "-",
            ],
            input=json.dumps(doc),
        )
        run(
            [
                "kubectl",
                "--kubeconfig",
                str(config),
                "-n",
                namespace,
                "rollout",
                "status",
                "deployment/quote",
                "--timeout=180s",
            ],
            timeout=200,
        )
        deployment = json.loads(
            run(
                [
                    "kubectl",
                    "--kubeconfig",
                    str(config),
                    "-n",
                    namespace,
                    "get",
                    "deployment/quote",
                    "-o",
                    "json",
                ]
            )
        )
        pods = json.loads(
            run(
                [
                    "kubectl",
                    "--kubeconfig",
                    str(config),
                    "-n",
                    namespace,
                    "get",
                    "pods",
                    "-l",
                    "sova.run=" + owner["run_id"],
                    "-o",
                    "json",
                ]
            )
        )["items"]
        if len(pods) != 2 or any(
            not p["status"].get("containerStatuses", [{}])[0].get("ready") for p in pods
        ):
            raise RuntimeError("Owned Pod readback incomplete")
        expected = image["image"].split("@", 1)[1]
        if any(
            expected not in p["status"]["containerStatuses"][0]["imageID"] for p in pods
        ):
            raise RuntimeError("Running image digest mismatch")
        records[side] = {
            "instance": instance,
            "runtime": "AWS EKS 1.35" if side == "aws" else "Linux VM / RKE2 1.35.9",
            "database": False,
            "namespace": namespace,
            "deployment_uid": deployment["metadata"]["uid"],
            "pod_uids": [p["metadata"]["uid"] for p in pods],
            "image": image["image"],
        }
    (root / "workload-registration.json").write_text(
        json.dumps(
            {
                "registered_at": datetime.now(UTC).isoformat(),
                "expires_at": owner["cleanup_at"],
                "workloads": records,
                "code_digest": image["code_digest"],
                "profile": "eks-rke2-stateless-v1",
            },
            indent=2,
        )
        + "\n"
    )
    print("Two real clusters have the run-owned, digest-verified stateless workload.")


if __name__ == "__main__":
    main()
