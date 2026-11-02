"""Fixed stateless price calculation used to qualify an EKS/RKE2 route change."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

CODE_DIGEST = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.connection.settimeout(3)
        path = urlsplit(self.path)
        if path.path not in {"/health", "/quote"}:
            self.send_error(404)
            return
        query = parse_qs(path.query)
        try:
            quantity = int(query.get("quantity", ["2"])[0])
            if not 1 <= quantity <= 100 or len(query.get("quantity", [])) > 1:
                raise ValueError()
        except ValueError:
            self.send_error(400)
            return
        document = {
            "application": "sova-stateless-quote",
            "instance": os.environ["INSTANCE_ID"],
            "environment": os.environ["ENVIRONMENT"],
            "pod_uid": os.environ["POD_UID"],
            "code_digest": CODE_DIGEST,
            "request_id": self.headers.get("X-Request-ID", "")[:64],
            "quantity": quantity,
            "unit_price": 100,
            "total": quantity * 110,
            "database": False,
        }
        raw = json.dumps(document).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.daemon_threads = True
    server.serve_forever()
