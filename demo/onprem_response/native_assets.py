"""Load the team's console from an immutable local Git revision.

Reuse its plan model, SSE parser, bindings and recovery UI. Only absolute static
URL prefixes and a transport-scope banner are adapted for this local host.
"""

import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from starlette.responses import Response

from .native_bridge import HEADERS

PREFIX = "services/console/src/bravo_console/static/"
MIMES = {
    ".html": "text/html",
    ".js": "text/javascript",
    ".css": "text/css",
    ".jpg": "image/jpeg",
    ".txt": "text/plain",
}


class NativeConsoleAssets:
    def __init__(self, app, *, repository, revision, origin):
        parsed = urlsplit(origin)
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise ValueError("immutable_platform_revision_required")
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or not parsed.port
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username
        ):
            raise ValueError("fixed_loopback_origin_required")
        self.app, self.origin = app, origin
        self.host = origin.removeprefix("http://")
        self.assets = {}
        repo = Path(repository)
        paths = subprocess.check_output(
            [
                "git",
                "-C",
                str(repo),
                "ls-tree",
                "-r",
                "--name-only",
                revision,
                "--",
                PREFIX,
            ],
            text=True,
        ).splitlines()
        for path in paths:
            suffix = Path(path).suffix
            if suffix not in MIMES:
                continue
            relative = path.removeprefix(PREFIX)
            if not path.startswith(PREFIX) or ".." in Path(relative).parts:
                raise ValueError("invalid_asset_path")
            data = subprocess.check_output(
                ["git", "-C", str(repo), "show", revision + ":" + path]
            )
            if suffix in {".html", ".js", ".css"}:
                data = data.replace(b"/console/", b"/__native/console/")
            key = "/__native/console/" + relative
            if relative == "index.html":
                key = "/__native/console/"
                data = data.replace(
                    b"</head>",
                    b'<script type="module" src="/__native/guard.js"></script></head>',
                )
                data = data.replace(
                    b'<main id="workspace-main">',
                    b'<main id="workspace-main"><section class="card"><a href="/console/">Sova live workspace</a><p id="native-transport-status" role="status"></p></section>',
                )
            self.assets[key] = (data, MIMES[suffix])
            if relative == "network/index.html":
                self.assets["/__native/console/network/"] = (data, MIMES[suffix])
        if "/__native/console/" not in self.assets:
            raise ValueError("native_console_missing")
        self.assets["/__native/guard.js"] = (
            Path(__file__).with_name("native_guard.js").read_bytes(),
            "text/javascript",
        )

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") not in self.assets:
            return await self.app(scope, receive, send)
        headers = scope.get("headers", [])
        hosts = [v.decode() for k, v in headers if k.lower() == b"host"]
        if (
            scope["method"] not in {"GET", "HEAD"}
            or hosts != [self.host]
            or scope.get("query_string")
        ):
            return await Response(status_code=403, headers=HEADERS)(
                scope, receive, send
            )
        data, mime = self.assets[scope["path"]]
        security = HEADERS | {
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'"
        }
        return await Response(
            data if scope["method"] == "GET" else b"", media_type=mime, headers=security
        )(scope, receive, send)
