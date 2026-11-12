"""Prepare the hybrid topology: EKS source (run-owned) and local RKE2 target.

Reads the run's Terraform outputs, writes a private kubeconfig, pushes the same
ARM64 images to the run's ECR repository by digest, registers both cluster
identities and creates only new, owned namespaces. The local target reuses the
images already imported into RKE2. Credentials stay in private state.
"""

import argparse
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys

from . import manifests
from .kube import CLUSTER_UID, VM, Kube, Unconfirmed
from .manifests import NAMESPACES, ROLES, configure, documents, placement
from .provision import initialize, private_json

PG_BASE = (
    "postgres@sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636"
)


def command(args, *, timeout=300, input=None, env=None):
    result = subprocess.run(
        args, capture_output=True, text=True, timeout=timeout, input=input, env=env
    )
    if result.returncode:
        error = Unconfirmed("hybrid_prepare_failed: " + " ".join(args[:3]))
        error.private_detail = result.stderr[-2000:]
        raise error
    return result.stdout


def terraform_outputs(state):
    values = json.loads(
        command(["terraform", "output", "-state=" + str(state), "-json"])
    )
    return {key: value["value"] for key, value in values.items()}


def node_cidr(region, vpc_id):
    """The node group's subnet (zone a); SSM-bridged traffic arrives from it."""
    subnets = json.loads(
        command(
            [
                "aws",
                "ec2",
                "describe-subnets",
                "--region",
                region,
                "--filters",
                "Name=vpc-id,Values=" + vpc_id,
                "Name=availability-zone,Values=" + region + "a",
                "--output",
                "json",
            ]
        )
    )["Subnets"]
    if len(subnets) != 1:
        raise ValueError("node_subnet_unconfirmed")
    return subnets[0]["CidrBlock"]


def write_kubeconfig(root, path, context, cluster_name, region):
    """Private kubeconfig pinned to the run's cluster; tokens via eks_token."""
    cluster = json.loads(
        command(
            [
                "aws",
                "eks",
                "describe-cluster",
                "--region",
                region,
                "--name",
                cluster_name,
                "--output",
                "json",
            ]
        )
    )["cluster"]
    if cluster["status"] != "ACTIVE":
        raise ValueError("eks_cluster_not_active")
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": context,
                "cluster": {
                    "server": cluster["endpoint"],
                    "certificate-authority-data": cluster["certificateAuthority"][
                        "data"
                    ],
                },
            }
        ],
        "users": [
            {
                "name": context,
                "user": {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1beta1",
                        "command": sys.executable,
                        "args": [
                            "-m",
                            "local_response.eks_token",
                            "--cache",
                            str(root / "eks-token.private.json"),
                            "--cluster-name",
                            cluster_name,
                            "--region",
                            region,
                        ],
                        "env": [
                            {
                                "name": "PYTHONPATH",
                                "value": str(Path(__file__).parents[1]),
                            }
                        ],
                        "interactiveMode": "Never",
                    }
                },
            }
        ],
        "contexts": [
            {"name": context, "context": {"cluster": context, "user": context}}
        ],
        "current-context": context,
    }
    private_json(path, config)


def node_addresses(kube, cidr):
    """InternalIP of every Ready source node, all inside the node subnet."""
    import ipaddress

    network = ipaddress.ip_network(cidr)
    nodes = json.loads(kube.clusters["aws"].run(["get", "nodes", "-o", "json"]))[
        "items"
    ]
    found = []
    for node in nodes:
        ready = any(
            c["type"] == "Ready" and c["status"] == "True"
            for c in node.get("status", {}).get("conditions", [])
        )
        address = next(
            a["address"]
            for a in node["status"]["addresses"]
            if a["type"] == "InternalIP"
        )
        if ready and ipaddress.ip_address(address) in network:
            found.append(address)
    if not found:
        raise ValueError("ready_source_nodes_required")
    return sorted(found)


def refresh_bridge(root):
    """Re-admit the current source nodes on the bridge policy, e.g. after a
    node replacement. Keeps the policy's pod selector (isolation state)."""
    settings = json.loads((root / "settings.private.json").read_text())
    configure("hybrid-aws")
    kube = Kube.from_settings(settings)
    kube.identity()
    ips = node_addresses(kube, settings["aws"]["node_cidr"])
    policy = kube.get("source", "networkpolicy", "bridge-ingress")
    for key in ("status",):
        policy.pop(key, None)
    policy["metadata"] = {
        key: policy["metadata"][key] for key in ("name", "namespace", "labels")
    }
    policy["spec"]["ingress"][0]["from"] = manifests.bridge_ingress_from(ips)
    kube.apply(policy)
    settings["aws"]["node_ips"] = ips
    private_json(root / "settings.private.json", settings)
    print("Bridge ingress admits source nodes: " + ", ".join(ips), flush=True)


def push_images(root, repository, region, local_bundle):
    registry = repository.split("/", 1)[0]
    password = command(["aws", "ecr", "get-login-password", "--region", region])
    command(
        ["docker", "login", "--username", "AWS", "--password-stdin", registry],
        input=password,
    )
    pushed = {}
    for release in ("v1", "v2", "bad"):
        tag = repository + ":" + release
        command(["docker", "tag", "localhost/sova-response/app:" + release, tag])
        command(["docker", "push", tag], timeout=600)
        pushed[release] = tag
    # The upstream digest is a multi-arch index; publish only the ARM64 image.
    context = root / "db-image"
    context.mkdir(mode=0o700, exist_ok=True)
    (context / "Dockerfile").write_text("FROM " + PG_BASE + "\n")
    tag = repository + ":db-18.4"
    command(
        [
            "docker",
            "build",
            "--platform=linux/arm64",
            "--provenance=false",
            "-t",
            tag,
            str(context),
        ],
        timeout=600,
    )
    command(["docker", "push", tag], timeout=600)
    pushed["db"] = tag
    name = repository.split("/", 1)[1]
    refs = {}
    for key, tag in pushed.items():
        detail = json.loads(
            command(
                [
                    "aws",
                    "ecr",
                    "describe-images",
                    "--region",
                    region,
                    "--repository-name",
                    name,
                    "--image-ids",
                    "imageTag=" + tag.rsplit(":", 1)[1],
                    "--output",
                    "json",
                ]
            )
        )["imageDetails"][0]
        refs[key] = repository + "@" + detail["imageDigest"]
    local = {key: local_bundle[key]["image"] for key in ("v1", "v2", "bad", "db")}
    return {"aws": refs, "local": local}


def prepare(root, *, terraform_state, local_state):
    os.umask(0o077)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_mode & 0o077:
        raise ValueError("private_state_directory_required")
    if (root / "settings.private.json").exists():
        raise ValueError("already_registered_use_resume")
    configure("hybrid-aws")
    out = terraform_outputs(terraform_state)
    tfvars = json.loads((terraform_state.parent / "run.auto.tfvars.json").read_text())
    region, account = tfvars.get("region", "ap-northeast-2"), tfvars["account_id"]
    identity = json.loads(
        command(["aws", "sts", "get-caller-identity", "--output", "json"])
    )
    if identity["Account"] != account:
        raise ValueError("wrong_aws_account")
    kubeconfig = root / "kubeconfig.private"
    context = "sova-hybrid-source"
    write_kubeconfig(root, kubeconfig, context, out["cluster_name"], region)
    aws_uid = json.loads(
        command(
            [
                "kubectl",
                "--kubeconfig",
                str(kubeconfig),
                "--context",
                context,
                "get",
                "namespace",
                "kube-system",
                "-o",
                "json",
            ],
            timeout=60,
        )
    )["metadata"]["uid"]
    local_bundle = json.loads((local_state / "images.json").read_text())
    images = push_images(root, out["repository_url"], region, local_bundle)
    for cluster, refs in images.items():
        for ref in refs.values():
            if not re.fullmatch(manifests.IMAGE_PATTERNS[cluster], ref):
                raise ValueError("pinned_image_required")
    password, admin, dbadmin = (
        secrets.token_hex(24),
        secrets.token_hex(32),
        secrets.token_hex(32),
    )
    settings = {
        "topology": "hybrid-aws",
        "owner": manifests.PROFILE["owner"],
        "cluster_uid": {"aws": aws_uid, "local": CLUSTER_UID},
        "clusters": {
            "aws": {"uid": aws_uid, "kubeconfig": str(kubeconfig), "context": context},
            "local": {"uid": CLUSTER_UID},
        },
        "aws": {
            "account_id": account,
            "region": region,
            "cluster_name": out["cluster_name"],
            "repository_url": out["repository_url"],
            "vpc_id": out["vpc_id"],
            "node_cidr": node_cidr(region, out["vpc_id"]),
            "node_ips": None,
        },
        "images_by_cluster": images,
        "images": {key: {"image": ref} for key, ref in images["local"].items()},
        "workload_sha256": local_bundle["workload_sha256"],
        "password": password,
        "admin": admin,
        "dbadmin": dbadmin,
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "run-owned EKS source in the operator's own AWS account; local RKE2 target on this Mac",
    }
    kube = Kube.from_settings(settings)
    kube.identity()
    settings["aws"]["node_ips"] = node_addresses(kube, settings["aws"]["node_cidr"])
    private_json(root / "settings.private.json", settings)
    # No adoption of pre-existing names on either cluster.
    for side, ns in NAMESPACES.items():
        found = kube.run(
            side, ["get", "namespace", ns, "--ignore-not-found", "-o", "json"]
        )
        if found.strip():
            raise ValueError("namespace_exists_explicit_recovery_required")
    command(
        [
            "limactl",
            "shell",
            VM,
            "sudo",
            "install",
            "-d",
            "-o",
            "999",
            "-g",
            "999",
            "-m",
            "0700",
            manifests.host_path("target"),
        ]
    )
    for cluster, side in (("aws", "source"), ("local", "target")):
        kube.apply(
            documents(
                images[cluster]["v1"],
                images[cluster]["db"],
                password,
                admin,
                dbadmin,
                cluster=cluster,
                node_ips=settings["aws"]["node_ips"],
            ),
            bootstrap=True,
            side=side,
        )
    settings["namespace_uids"] = {side: kube.owned(side) for side in NAMESPACES}
    private_json(root / "settings.private.json", settings)
    resume(root)


def resume(root):
    """Wait for registered, owned resources and initialize both databases."""
    settings = json.loads((root / "settings.private.json").read_text())
    configure("hybrid-aws")
    kube = Kube.from_settings(settings)
    kube.identity()
    for side, uid in settings["namespace_uids"].items():
        if kube.owned(side) != uid:
            raise ValueError("namespace_identity_changed")
    for side in ("source", "target"):
        kube.wait(side, "db", timeout=300)
    for side in NAMESPACES:
        for role in ROLES[side]:
            kube.wait(side, role, timeout=300)
    initialize(kube, settings["password"])
    print(
        "Hybrid prepared: EKS source "
        + settings["aws"]["cluster_name"]
        + ", local RKE2 target. Placement: "
        + json.dumps({side: placement(side) for side in NAMESPACES}),
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--terraform-state", type=Path)
    parser.add_argument("--local-state", type=Path)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--refresh-bridge", action="store_true")
    args = parser.parse_args()
    if args.refresh_bridge:
        refresh_bridge(args.state.resolve())
    elif args.resume:
        resume(args.state.resolve())
    else:
        if not args.terraform_state or not args.local_state:
            parser.error("--terraform-state and --local-state are required")
        prepare(
            args.state.resolve(),
            terraform_state=args.terraform_state.resolve(),
            local_state=args.local_state.resolve(),
        )


if __name__ == "__main__":
    main()
