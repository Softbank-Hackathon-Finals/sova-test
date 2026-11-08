"""Bounded source intake. Source contents are data, never host instructions."""

from dataclasses import dataclass
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import urllib.request
import zipfile

MAX_UPLOAD = 20 * 1024 * 1024
MAX_EXPANDED = 100 * 1024 * 1024
IGNORED = {".git", "node_modules", ".venv", "venv", "__pycache__", "__MACOSX"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError("source_redirect_not_allowed")


def download(url, limit):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Sova-source-intake",
            "Accept": "application/vnd.github+json",
        },
    )
    with opener.open(req, timeout=30) as response:
        data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("source_size_limit")
        return data


def github_archive(repository, ref, fetch=download):
    match = re.fullmatch(
        r"https://github\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(?:\.git)?/?",
        repository,
    )
    if (
        not match
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", ref)
        or ref in {".", ".."}
    ):
        raise ValueError("public_github_repository_and_simple_ref_required")
    owner, repo = match.groups()
    metadata = json.loads(
        fetch(
            f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}",
            2 * 1024 * 1024,
        )
    )
    sha = metadata.get("sha")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("github_commit_unresolved")
    data = fetch(f"https://codeload.github.com/{owner}/{repo}/zip/{sha}", MAX_UPLOAD)
    return data, {
        "kind": "github",
        "repository": f"https://github.com/{owner}/{repo}",
        "commit": sha,
    }


@dataclass(frozen=True)
class Source:
    root: Path
    digest: str
    file_count: int
    runtime: str
    entry: str


def unpack(data, destination):
    if not data or len(data) > MAX_UPLOAD or destination.exists():
        raise ValueError("new_bounded_source_required")
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        entries = bundle.infolist()
        if len(entries) > 5000 or sum(i.file_size for i in entries) > MAX_EXPANDED:
            raise ValueError("expanded_source_limit")
        selected, names, dirs = [], set(), set()
        for item in entries:
            raw = item.filename.rstrip("/")
            path = PurePosixPath(raw)
            mode = item.external_attr >> 16
            if (
                not raw
                or path.is_absolute()
                or ".." in path.parts
                or "\\" in raw
                or path.as_posix() != raw
                or any(ord(c) < 32 for c in raw)
            ):
                raise ValueError("unsafe_source_path")
            if mode and stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("source_links_or_special_files_denied")
            if item.flag_bits & 1:
                raise ValueError("encrypted_archive_denied")
            if any(part in IGNORED for part in path.parts):
                continue
            if any(
                part == ".env"
                or (
                    part.startswith(".env.")
                    and part not in {".env.example", ".env.sample"}
                )
                or part.endswith((".pem", ".key", ".p12"))
                for part in path.parts
            ):
                raise ValueError("remove_local_secrets_before_upload")
            parents = {p.as_posix() for p in path.parents if str(p) != "."}
            key = raw.casefold()
            if (
                key in names
                or any(
                    p.casefold() in names and p.casefold() not in dirs for p in parents
                )
                or (not item.is_dir() and key in dirs)
            ):
                raise ValueError("duplicate_or_conflicting_source_path")
            names.add(key)
            dirs.update(p.casefold() for p in parents)
            if item.is_dir():
                dirs.add(key)
            selected.append((item, path))
        destination.mkdir(mode=0o700, parents=True)
        total = 0
        for item, path in selected:
            out = destination.joinpath(*path.parts)
            if item.is_dir():
                out.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                content = bundle.read(item)
                total += len(content)
                if total > MAX_EXPANDED:
                    raise ValueError("actual_expanded_source_limit")
                out.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                out.write_bytes(content)
                out.chmod(0o600)
    markers = ("package.json", "index.html")
    roots = (
        [destination]
        if any((destination / m).is_file() for m in markers)
        else list({p.parent for m in markers for p in destination.glob("*/" + m)})
    )
    if len(roots) != 1:
        raise ValueError("one_static_or_node_app_root_required")
    root = roots[0]
    files = sorted(p for p in destination.rglob("*") if p.is_file())
    if not files or any(not p.is_relative_to(root) for p in files):
        raise ValueError("source_outside_app_root")
    h = hashlib.sha256()
    for p in files:
        h.update(p.relative_to(root).as_posix().encode() + b"\0")
        h.update(hashlib.sha256(p.read_bytes()).digest())
    if any(p.suffix.lower() in {".db", ".sqlite", ".sqlite3"} for p in files):
        raise ValueError("persistent_database_profile_required")
    runtime, entry = "static", "index.html"
    if (root / "package.json").is_file():
        package = json.loads((root / "package.json").read_text())
        runtime = "node"
        entry = package.get("main", "server.js")
        if (
            not isinstance(entry, str)
            or not re.fullmatch(r"[A-Za-z0-9_./-]+\.m?js", entry)
            or ".." in PurePosixPath(entry).parts
            or entry.startswith("/")
            or not (root / entry).is_file()
        ):
            raise ValueError("node_main_file_required")
        if not (root / "package-lock.json").is_file():
            raise ValueError("node_lockfile_required")
    return Source(root, h.hexdigest(), len(files), runtime, entry)
