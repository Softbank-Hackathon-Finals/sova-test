"""Build/import bounded ARM64 images and prepare the owned local namespaces."""

import argparse
from datetime import UTC, datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess

from .kube import Kube, NAMESPACES, OWNER, VM, Unconfirmed
from .manifests import documents, ROLES

PG_BASE = (
    "postgres@sha256:a02db8cac496f15b094798a38254f14d6e00741f709360e5e00bb6668ea31636"
)


def private_json(path, value):
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    with open(
        temporary, "w", opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)
    ) as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    temporary.replace(path)


def command(args, *, log=None, timeout=300):
    result = subprocess.run(args, capture_output=True, timeout=timeout)
    if log:
        log.write_bytes(result.stdout + result.stderr)
    if result.returncode:
        raise Unconfirmed("local_image_prepare_failed")
    return result.stdout.decode()


def images(root):
    context = Path(__file__).parent
    bundle = {}
    for release in ("v1", "v2", "bad"):
        tag = "localhost/sova-response/app:" + release
        command(
            [
                "docker",
                "build",
                "--platform=linux/arm64",
                "--provenance=false",
                "--build-arg",
                "RELEASE=" + release,
                "-t",
                tag,
                str(context),
            ],
            log=root / ("build-" + release + ".log"),
        )
        image = json.loads(command(["docker", "image", "inspect", tag]))[0]
        bundle[release] = {
            "tag": tag,
            "config_digest": image["Id"],
            "architecture": image["Architecture"],
        }
    command(["docker", "tag", PG_BASE, "localhost/sova-response/db:18.4"])
    path = root / "images.tar"
    command(
        [
            "docker",
            "save",
            "-o",
            str(path),
            *[v["tag"] for v in bundle.values()],
            "localhost/sova-response/db:18.4",
        ],
        timeout=300,
    )
    command(["limactl", "copy", str(path), VM + ":/tmp/sova-response-images.tar"])
    command(
        [
            "limactl",
            "shell",
            VM,
            "sudo",
            "/var/lib/rancher/rke2/bin/ctr",
            "--address",
            "/run/k3s/containerd/containerd.sock",
            "-n",
            "k8s.io",
            "images",
            "import",
            "/tmp/sova-response-images.tar",
        ],
        log=root / "import.log",
    )
    inventory = json.loads(
        command(
            [
                "limactl",
                "shell",
                VM,
                "sudo",
                "/var/lib/rancher/rke2/bin/crictl",
                "--runtime-endpoint",
                "unix:///run/k3s/containerd/containerd.sock",
                "images",
                "-o",
                "json",
            ]
        )
    )
    image_table = command(
        [
            "limactl",
            "shell",
            VM,
            "sudo",
            "/var/lib/rancher/rke2/bin/ctr",
            "--address",
            "/run/k3s/containerd/containerd.sock",
            "-n",
            "k8s.io",
            "images",
            "list",
        ]
    )
    manifests = {
        line.split()[0]: line.split()[2]
        for line in image_table.splitlines()[1:]
        if len(line.split()) >= 3
    }
    for key, tag in [
        *[(key, value["tag"]) for key, value in bundle.items()],
        ("db", "localhost/sova-response/db:18.4"),
    ]:
        item = next(
            item for item in inventory["images"] if tag in (item.get("repoTags") or [])
        )
        digest = tag.rsplit(":", 1)[0] + "@" + manifests[tag]
        command(
            [
                "limactl",
                "shell",
                VM,
                "sudo",
                "/var/lib/rancher/rke2/bin/ctr",
                "--address",
                "/run/k3s/containerd/containerd.sock",
                "-n",
                "k8s.io",
                "images",
                "tag",
                "--force",
                tag,
                digest,
            ]
        )
        if key == "db":
            bundle[key] = {
                "tag": tag,
                "config_digest": item["id"],
                "architecture": "arm64",
            }
        bundle[key]["image"] = digest
    bundle["workload_sha256"] = hashlib.sha256(
        (context / "workload.py").read_bytes()
    ).hexdigest()
    private_json(root / "images.json", bundle)
    return bundle


def initialize(kube, password):
    # Admin access stays only on the control probe. Application role is not a
    # PostgreSQL superuser and cannot create roles, DBs or schemas.
    code = r"""
import json,sys,psycopg,pathlib
from psycopg import sql
v=json.load(sys.stdin)
with psycopg.connect(host=v['host'],dbname='workload',user='postgres',password=pathlib.Path('/credentials/dbadmin').read_text().strip(),connect_timeout=3) as c:
 if not c.execute("SELECT 1 FROM pg_roles WHERE rolname='app'").fetchone():
  c.execute(sql.SQL('CREATE ROLE app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}').format(sql.Literal(v['password'])))
 c.execute('CREATE TABLE IF NOT EXISTS messages(id text PRIMARY KEY,body text NOT NULL)')
 c.execute('CREATE TABLE IF NOT EXISTS jobs(id text PRIMARY KEY,body text NOT NULL,completed boolean NOT NULL DEFAULT false,worker_uid text)')
 c.execute('REVOKE CREATE ON SCHEMA public FROM PUBLIC')
 c.execute('GRANT USAGE ON SCHEMA public TO app')
 c.execute('GRANT SELECT,INSERT,UPDATE ON messages,jobs TO app')
print(json.dumps({'initialized':True}))
"""
    for side in ("source", "target"):
        value = json.loads(
            kube.execute(
                "control",
                "probe",
                code,
                {"host": "db." + NAMESPACES[side], "password": password},
            )
        )
        if not value.get("initialized"):
            raise Unconfirmed("database_initialize_unconfirmed")


def prepare(root, *, build=True):
    os.umask(0o077)
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    if root.is_symlink() or root.stat().st_mode & 0o077:
        raise ValueError("private_state_directory_required")
    kube = Kube()
    cluster_uid = kube.identity()
    if (root / "settings.private.json").exists():
        raise ValueError("already_registered_use_existing_settings")
    # No adoption or reset of pre-existing names, even if their labels look similar.
    for ns in NAMESPACES.values():
        from .kube import run

        if json.loads(
            run(["get", "namespace", ns, "--ignore-not-found", "-o", "json"]) or "null"
        ):
            raise ValueError("namespace_exists_explicit_recovery_required")
    bundle = images(root) if build else json.loads((root / "images.json").read_text())
    password, admin, dbadmin = (
        secrets.token_hex(24),
        secrets.token_hex(32),
        secrets.token_hex(32),
    )
    settings = {
        "cluster_uid": cluster_uid,
        "owner": OWNER,
        "images": bundle,
        "password": password,
        "admin": admin,
        "dbadmin": dbadmin,
        "created_at": datetime.now(UTC).isoformat(),
        "scope": "owned local RKE2; two namespaces on one Mac; not AWS migration",
    }
    private_json(root / "settings.private.json", settings)
    for side in ("source", "target"):
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
                "/var/lib/sova-local-response/" + side,
            ]
        )
    kube.apply(
        documents(
            bundle["v1"]["image"], bundle["db"]["image"], password, admin, dbadmin
        ),
        bootstrap=True,
    )
    settings["namespace_uids"] = {side: kube.owned(side) for side in NAMESPACES}
    private_json(root / "settings.private.json", settings)
    complete_preparation(root)


def complete_preparation(root):
    """Resume only registered, owned local resources; never rebuild or replace DBs."""
    settings = json.loads((root / "settings.private.json").read_text())
    kube = Kube()
    if kube.identity() != settings["cluster_uid"]:
        raise ValueError("cluster_identity_changed")
    for side in NAMESPACES:
        uid = kube.owned(side)
        recorded = settings.get("namespace_uids", {}).get(side)
        if recorded is not None and recorded != uid:
            raise ValueError("namespace_identity_changed")
        if recorded is None:
            # First bootstrap wrote settings before resource creation. Accept
            # only namespaces created after that registration, with exact owner.
            created = kube.get(side, "namespace", NAMESPACES[side])["metadata"][
                "creationTimestamp"
            ]
            if datetime.fromisoformat(
                created.replace("Z", "+00:00")
            ) < datetime.fromisoformat(settings["created_at"]):
                raise ValueError("preexisting_namespace_cannot_be_adopted")
            settings.setdefault("namespace_uids", {})[side] = uid
    private_json(root / "settings.private.json", settings)
    for side in NAMESPACES:
        if side != "control":
            kube.wait(side, "db", timeout=120)
        for role in ROLES[side]:
            kube.wait(side, role, timeout=120)
    initialize(kube, settings["password"])
    print(
        "Local RKE2 owned workload prepared. Credentials retained only in private state.",
        flush=True,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--reuse-images", action="store_true")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.resume:
        complete_preparation(args.state.resolve())
    else:
        prepare(args.state.resolve(), build=not args.reuse_images)


if __name__ == "__main__":
    main()
