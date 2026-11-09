"""Serve the mock UI on loopback, using only a fixed list of public assets."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parent
PREFIX = "/__mock/response/"
CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'none'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
)


def assets():
    """An explicit asset table; request paths never become filesystem paths."""
    entries = {
        "index.html": (ROOT / "index.html", "text/html; charset=utf-8"),
        "model.mjs": (ROOT / "model.mjs", "text/javascript; charset=utf-8"),
        "motion.mjs": (ROOT / "motion.mjs", "text/javascript; charset=utf-8"),
        "view.mjs": (ROOT / "view.mjs", "text/javascript; charset=utf-8"),
        "styles.css": (ROOT / "styles.css", "text/css; charset=utf-8"),
        "base.css": (
            ROOT.parents[1] / "console" / "src" / "styles.css",
            "text/css; charset=utf-8",
        ),
    }
    result = {
        PREFIX + name: (path.read_bytes(), mime)
        for name, (path, mime) in entries.items()
    }
    for name in ("/", "/console", "/console/", PREFIX):
        result[name] = result[PREFIX + "index.html"]
    return result


def handler(public_assets):
    class MockHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.respond()

        def do_HEAD(self):
            self.respond(head=True)

        def do_POST(self):
            self.respond(status=405)

        do_PUT = do_POST
        do_PATCH = do_POST
        do_DELETE = do_POST

        def respond(self, *, head=False, status=None):
            path = urlsplit(self.path).path
            found = public_assets.get(path)
            code = status or (200 if found else 404)
            body, mime = found if code == 200 else (b"Mock assets only. No API.\n", "text/plain")
            self.send_response(code)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            if code == 405:
                self.send_header("Allow", "GET, HEAD")
            self.end_headers()
            if not head:
                self.wfile.write(body)

        def log_message(self, format, *args):
            # Avoid logging arbitrary request paths or query strings.
            pass

    return MockHandler


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=18132)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        parser.error("Use an unprivileged loopback port")
    with ThreadingHTTPServer(("127.0.0.1", args.port), handler(assets())) as server:
        print(f"Sova Response Workspace: http://127.0.0.1:{args.port}/console/", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
