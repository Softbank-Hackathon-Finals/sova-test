"""Generated build recipes; uploaded Dockerfiles/scripts never execute on the host."""

import base64
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
from urllib.parse import urlsplit

from .intake import download


def run(args, *, env=None, timeout=600, stdin=None):
    result = subprocess.run(
        args, input=stdin, capture_output=True, text=True, env=env, timeout=timeout
    )
    if result.returncode:
        # Build output may contain source-provided secrets. Do not publish it.
        raise RuntimeError("deployment_command_failed:" + Path(args[0]).name)
    return result.stdout


def node_vendor(source, destination, fetch=download):
    lock = json.loads((source / "package-lock.json").read_text())
    if lock.get("lockfileVersion") not in (2, 3) or not isinstance(
        lock.get("packages"), dict
    ):
        raise ValueError("npm_lock_v2_or_v3_required")
    dependencies = [v for k, v in lock["packages"].items() if k and not v.get("dev")]
    if len(dependencies) > 200:
        raise ValueError("dependency_count_limit")
    destination.mkdir(mode=0o700)
    total = 0
    for i, p in enumerate(dependencies):
        url = p.get("resolved", "")
        parts = urlsplit(url)
        integrity = p.get("integrity", "")
        if (
            parts.scheme != "https"
            or parts.netloc != "registry.npmjs.org"
            or parts.query
            or parts.fragment
            or not parts.path.endswith(".tgz")
            or ".." in parts.path.split("/")
            or not re.fullmatch(r"sha512-[A-Za-z0-9+/]+=*", integrity)
        ):
            raise ValueError("registry_npm_sha512_lock_required")
        content = fetch(url, 20 * 1024 * 1024)
        total += len(content)
        if total > 100 * 1024 * 1024:
            raise ValueError("dependency_bytes_limit")
        if hashlib.sha512(content).digest() != base64.b64decode(
            integrity[7:], validate=True
        ):
            raise ValueError("dependency_integrity_mismatch")
        (destination / f"{i}.tgz").write_bytes(content)
    return len(dependencies)


def build(source, state, *, base, platform):
    if not re.fullmatch(
        r"[a-zA-Z0-9./_-]+@sha256:[a-f0-9]{64}", base
    ) or platform not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("pinned_runtime_and_architecture_required")
    h = hashlib.sha256()
    for path in sorted(p for p in source.root.rglob("*") if p.is_file()):
        if path.is_symlink():
            raise ValueError("source_link_after_intake")
        h.update(path.relative_to(source.root).as_posix().encode() + b"\0")
        h.update(hashlib.sha256(path.read_bytes()).digest())
    if h.hexdigest() != source.digest:
        raise ValueError("source_changed_after_intake")
    context = state / "build-context"
    shutil.copytree(source.root, context)
    if (context / ".sova-vendor").exists():
        raise ValueError("reserved_source_path")
    if source.runtime == "node":
        count = node_vendor(source.root, context / ".sova-vendor")
        recipe = f"FROM {base}\nWORKDIR /app\nCOPY package*.json ./\n"
        if count:
            recipe += "COPY .sova-vendor /vendor\nRUN npm cache add /vendor/*.tgz --offline --ignore-scripts && npm ci --offline --omit=dev --ignore-scripts --no-audit --no-fund && npm cache clean --force\n"
        recipe += (
            "COPY --chown=10001:10001 . .\nENV NODE_ENV=production PORT=8080\nUSER 10001:10001\nEXPOSE 8080\nCMD "
            + json.dumps(["node", source.entry])
            + "\n"
        )
    else:
        recipe = f'FROM {base}\nWORKDIR /app\nCOPY --chown=10001:10001 . .\nUSER 10001:10001\nEXPOSE 8080\nCMD ["python", "-m", "http.server", "8080", "--bind", "0.0.0.0"]\n'
    (context / "Dockerfile").write_text(recipe)
    (context / ".dockerignore").write_text(".git\n.env\n.env.*\nnode_modules\n")
    image = "sova-app:" + source.digest[:24]
    run(
        [
            "docker",
            "build",
            "--platform",
            platform,
            "--network=none",
            "--provenance=false",
            "--label",
            "sova.source=" + source.digest,
            "-t",
            image,
            str(context),
        ]
    )
    meta = json.loads(run(["docker", "image", "inspect", image]))[0]
    if meta["Os"] + "/" + meta["Architecture"] != platform:
        raise ValueError("built_architecture_mismatch")
    return {
        "local_image": image,
        "image_id": meta["Id"],
        "platform": platform,
        "source_digest": source.digest,
        "generated_recipe": True,
        "build_network": "none",
        "dependency_scripts": False,
    }
