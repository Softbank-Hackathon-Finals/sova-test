"""Build/publish only this fixed operator-owned qualification fixture."""

import argparse
import base64
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess

import boto3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    owner = json.loads((root / "ownership.json").read_text())
    if datetime.now(UTC) >= datetime.fromisoformat(owner["cleanup_at"]):
        raise RuntimeError("Run registration expired")
    session = boto3.Session(region_name=owner["region"])
    if session.client("sts").get_caller_identity()["Account"] != owner["account_id"]:
        raise RuntimeError("Wrong AWS account")
    ecr = session.client("ecr")
    repo = ecr.describe_repositories(repositoryNames=[owner["cluster_name"]])[
        "repositories"
    ][0]
    tags = ecr.list_tags_for_resource(resourceArn=repo["repositoryArn"])["tags"]
    if {t["Key"]: t["Value"] for t in tags}.get("RunId") != owner["run_id"]:
        raise RuntimeError("Repository ownership mismatch")
    image = repo["repositoryUri"] + ":" + owner["run_id"]
    project = Path(__file__).resolve().parents[2]
    context = project / "examples/relocation"
    with (root / "image-build.log").open("w") as log:
        subprocess.run(
            [
                "docker",
                "build",
                "--platform=linux/arm64",
                "--provenance=false",
                "--network=none",
                "-t",
                image,
                str(context),
            ],
            stdout=log,
            stderr=log,
            timeout=300,
            check=True,
        )
    auth = ecr.get_authorization_token()["authorizationData"][0]
    username, password = (
        base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
    )
    private = root / "docker-auth"
    private.mkdir(mode=0o700, exist_ok=False)
    endpoint = json.loads(
        subprocess.run(
            [
                "docker",
                "context",
                "inspect",
                "--format",
                "{{json .Endpoints.docker.Host}}",
            ],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    env = {**os.environ, "DOCKER_HOST": endpoint, "DOCKER_CONFIG": str(private)}
    try:
        subprocess.run(
            [
                "docker",
                "login",
                "--username",
                username,
                "--password-stdin",
                auth["proxyEndpoint"],
            ],
            input=password,
            capture_output=True,
            text=True,
            env=env,
            check=True,
            timeout=45,
        )
        with (root / "image-push.log").open("w") as log:
            subprocess.run(
                ["docker", "push", image],
                env=env,
                stdout=log,
                stderr=log,
                check=True,
                timeout=300,
            )
    finally:
        # No registry login is left in the user's global Docker configuration.
        shutil.rmtree(private)
    detail = ecr.describe_images(
        repositoryName=owner["cluster_name"], imageIds=[{"imageTag": owner["run_id"]}]
    )["imageDetails"][0]
    document = {
        "image": repo["repositoryUri"] + "@" + detail["imageDigest"],
        "tag": image,
        "architecture": "arm64",
        "code_digest": hashlib.sha256(
            (context / "service.py").read_bytes()
        ).hexdigest(),
        "instance_id": secrets.token_hex(6),
        "built_at": datetime.now(UTC).isoformat(),
    }
    (root / "image.json").write_text(json.dumps(document, indent=2) + "\n")
    print("Owned immutable ARM64 application published. Registry credentials removed.")


if __name__ == "__main__":
    main()
