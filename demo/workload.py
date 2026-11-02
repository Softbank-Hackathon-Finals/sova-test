"""Small stateless HTTPS workload. No DB, cloud SDK, shell or credentials."""

import hashlib
import json
import os
import ssl
import tempfile
import threading
import time
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main():
    config = json.loads(os.environ.pop("SOVA_PROBE_CONFIG"))
    lifetime = 7200
    if "expires_at" in config:
        deadline = datetime.fromisoformat(config["expires_at"])
        if deadline.tzinfo is None:
            raise ValueError("Timezone-aware workload deadline required")
        lifetime = (deadline - datetime.now(UTC)).total_seconds()
        if not 0 < lifetime <= 7200:
            raise ValueError("Bounded workload deadline required")
    identity = {k: config[k] for k in ("environment", "instance", "revision", "run_id")}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def reply(self, status, body):
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Sova-Environment", identity["environment"])
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self):
            if self.path != "/health":
                return self.reply(404, {"error": "not_found"})
            self.reply(200, {**identity, "alive": True, "time": time.time()})

        def do_POST(self):
            if self.path != "/action":
                return self.reply(404, {"error": "not_found"})
            try:
                self.connection.settimeout(4)
                length = int(self.headers.get("Content-Length", "0"))
                if self.headers.get("Transfer-Encoding") or not 0 < length <= 512:
                    raise ValueError()
                body = json.loads(self.rfile.read(length))
                if set(body) != {"request_id", "message"}:
                    raise ValueError()
                if not isinstance(body["message"], str) or len(body["message"]) > 80:
                    raise ValueError()
                if (
                    not isinstance(body["request_id"], str)
                    or len(body["request_id"]) != 32
                ):
                    raise ValueError()
            except (ValueError, TypeError, OSError):
                return self.reply(400, {"error": "invalid_request"})
            self.reply(
                200,
                {
                    **identity,
                    **body,
                    "time": time.time(),
                    "message_sha256": hashlib.sha256(
                        body["message"].encode()
                    ).hexdigest(),
                },
            )

    # Keys live in a memory-backed directory, not in the image/root filesystem.
    with tempfile.TemporaryDirectory(prefix="sova-", dir="/dev/shm") as folder:
        for name in ("cert", "key"):
            path = folder + "/" + name
            with open(path, "w") as f:
                f.write(config.pop(name))
            os.chmod(path, 0o600)
        server = ThreadingHTTPServer(("0.0.0.0", 8443), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(folder + "/cert", folder + "/key")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        print("Sova stateless HTTPS probe ready", flush=True)
        timer = threading.Timer(lifetime, server.shutdown)
        timer.daemon = True
        timer.start()
        server.serve_forever()
        server.server_close()


if __name__ == "__main__":
    main()
