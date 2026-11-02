"""Owner-local, CA-verified access to the run's private EKS API via SSM."""

import argparse
import json
import os
import pty
import select
import signal
import sys
from datetime import UTC, datetime
from pathlib import Path
import subprocess
import socket
import time
from urllib.parse import urlsplit

import boto3


def start_private_tunnel(arguments, *, env, log):
    # The plugin needs a controlling terminal, not just an inherited TTY FD.
    # A deadline-bound supervisor keeps that terminal and drains its output.
    return subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--root",
            str(Path(log.name).parent),
            "--tunnel-arguments",
            json.dumps(arguments),
        ],
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
    )


def supervise_tunnel(arguments, owner):
    if (
        len(arguments) != 11
        or arguments[:4] != ["aws", "ssm", "start-session", "--region"]
        or arguments[4] != owner["region"]
        or arguments[5] != "--target"
        or arguments[7:10]
        != [
            "--document-name",
            "AWS-StartPortForwardingSessionToRemoteHost",
            "--parameters",
        ]
    ):
        raise RuntimeError("Fixed private tunnel command required")
    deadline = datetime.fromisoformat(owner["cleanup_at"])
    pid, master = pty.fork()
    if pid == 0:
        os.execvp(arguments[0], arguments)
    stopped = False

    def stop(*_):
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopped and datetime.now(UTC) < deadline:
            readable, _, _ = select.select([master], [], [], 1)
            if readable:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                sys.stdout.buffer.write(chunk)
                sys.stdout.buffer.flush()
            if os.waitpid(pid, os.WNOHANG)[0]:
                break
    finally:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        os.close(master)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--tunnel-arguments", help=argparse.SUPPRESS)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    owner = json.loads((root / "ownership.json").read_text())
    if args.tunnel_arguments is not None:
        supervise_tunnel(json.loads(args.tunnel_arguments), owner)
        return
    aws = boto3.Session(region_name=owner["region"])
    if aws.client("sts").get_caller_identity()["Account"] != owner["account_id"]:
        raise RuntimeError("Wrong AWS account")
    eks = aws.client("eks")
    cluster = eks.describe_cluster(name=owner["cluster_name"])["cluster"]
    if cluster["status"] != "ACTIVE" or cluster["tags"].get("RunId") != owner["run_id"]:
        raise RuntimeError("Registered EKS identity unavailable")
    group = eks.describe_nodegroup(
        clusterName=owner["cluster_name"], nodegroupName="qualification"
    )["nodegroup"]
    asg = aws.client("autoscaling").describe_auto_scaling_groups(
        AutoScalingGroupNames=[group["resources"]["autoScalingGroups"][0]["name"]]
    )["AutoScalingGroups"][0]
    if len(asg["Instances"]) != 1:
        raise RuntimeError("Expected one qualification node")
    instance = asg["Instances"][0]["InstanceId"]
    nodes = aws.client("ssm").describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": [instance]}]
    )["InstanceInformationList"]
    if not nodes or nodes[0]["PingStatus"] != "Online":
        raise RuntimeError("Owned node SSM is not online yet")
    host = urlsplit(cluster["endpoint"]).hostname
    plugin = root / "ssm-plugin/sessionmanager-bundle/bin"
    env = {**os.environ, "PATH": str(plugin) + os.pathsep + os.environ["PATH"]}
    with socket.socket() as check:
        check.bind(("127.0.0.1", 17443))
    with (root / "ssm-tunnel.log").open("w") as log:
        p = start_private_tunnel(
            [
                "aws",
                "ssm",
                "start-session",
                "--region",
                owner["region"],
                "--target",
                instance,
                "--document-name",
                "AWS-StartPortForwardingSessionToRemoteHost",
                "--parameters",
                json.dumps(
                    {
                        "host": [host],
                        "portNumber": ["443"],
                        "localPortNumber": ["17443"],
                    }
                ),
            ],
            env=env,
            log=log,
        )
    (root / "ssm-tunnel.json").write_text(
        json.dumps(
            {"pid": p.pid, "instance_id": instance, "host": host, "local_port": 17443}
        )
        + "\n"
    )
    config = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [
            {
                "name": "source",
                "cluster": {
                    "server": "https://127.0.0.1:17443",
                    "tls-server-name": host,
                    "certificate-authority-data": cluster["certificateAuthority"][
                        "data"
                    ],
                },
            }
        ],
        "users": [
            {
                "name": "operator",
                "user": {
                    "exec": {
                        "apiVersion": "client.authentication.k8s.io/v1beta1",
                        "command": "aws",
                        "args": [
                            "eks",
                            "get-token",
                            "--region",
                            owner["region"],
                            "--cluster-name",
                            owner["cluster_name"],
                        ],
                        "interactiveMode": "Never",
                    }
                },
            }
        ],
        "contexts": [
            {"name": "source", "context": {"cluster": "source", "user": "operator"}}
        ],
        "current-context": "source",
    }
    path = root / "aws-kubeconfig.json"
    path.write_text(json.dumps(config))
    path.chmod(0o600)
    for _ in range(30):
        if p.poll() is not None:
            raise RuntimeError("SSM tunnel exited; inspect private log")
        result = subprocess.run(
            [
                "kubectl",
                "--kubeconfig",
                str(path),
                "--request-timeout=5s",
                "get",
                "nodes",
                "-o",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            if len(data["items"]) != 1 or not any(
                c["type"] == "Ready" and c["status"] == "True"
                for c in data["items"][0]["status"]["conditions"]
            ):
                raise RuntimeError("Owned EKS node is not Ready")
            (root / "eks-node-proof.json").write_text(
                json.dumps(
                    {
                        "cluster_arn": cluster["arn"],
                        "node_uid": data["items"][0]["metadata"]["uid"],
                        "version": data["items"][0]["status"]["nodeInfo"][
                            "kubeletVersion"
                        ],
                        "private_api": not cluster["resourcesVpcConfig"][
                            "endpointPublicAccess"
                        ],
                        "ca_and_server_name_verified": True,
                    },
                    indent=2,
                )
                + "\n"
            )
            print(
                "Private EKS API verified over SSM; node Ready; CA and hostname verification enabled."
            )
            return
        time.sleep(1)
    raise RuntimeError("Private EKS connectivity unverified")


if __name__ == "__main__":
    main()
