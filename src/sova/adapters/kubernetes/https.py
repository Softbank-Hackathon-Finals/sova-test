"""Direct pinned HTTPS GETs only: no proxies, redirects, kubeconfig exec or logs."""

import hashlib
import http.client
import os
import socket
import ssl
import stat
import time
from threading import Timer
from urllib.parse import urlencode, urlsplit

from sova.adapters.kubernetes.api_json import decode_api_json
from sova.domain.contracts import ContractError

MAX_RESPONSE = 2 * 1024 * 1024


def private_text(path, *, limit=65536):
    """Operator-only POSIX credential/config input; never echo content in errors."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise ContractError("Private operator file permissions required")
            data = source.read(limit + 1)
            if len(data) > limit:
                raise ContractError("Operator file too large")
            return data.decode("utf-8")
    except (OSError, UnicodeError) as exc:
        raise ContractError("Unreadable private operator file") from exc


class KubernetesHTTPS:
    def __init__(self, registration, *, ca_pem: bytes, token_provider):
        if hashlib.sha256(ca_pem).hexdigest() != registration.ca_digest:
            raise ContractError("Registered CA digest mismatch")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        try:
            context.load_verify_locations(cadata=ca_pem.decode("ascii"))
        except (ValueError, UnicodeError, ssl.SSLError) as exc:
            raise ContractError("Invalid registered CA") from exc
        self.registration = registration
        self.context = context
        self.token_provider = token_provider

    @property
    def registration_digest(self):
        return self.registration.fingerprint

    def get(self, path, query, *, timeout):
        reg = self.registration
        allowed = {"/api/v1/namespaces/" + reg.namespace}
        for base, plural in (
            ("/apis/apps/v1", "deployments"),
            ("/apis/apps/v1", "statefulsets"),
            ("/api/v1", "services"),
            ("/api/v1", "persistentvolumeclaims"),
        ):
            allowed.add(base + "/namespaces/" + reg.namespace + "/" + plural)
        if path not in allowed or set(query) - {"labelSelector", "limit", "continue"}:
            raise ContractError("Unregistered Kubernetes read path")
        if path == "/api/v1/namespaces/" + reg.namespace:
            if query:
                raise ContractError("Namespace query not allowed")
        elif (
            query.get("labelSelector")
            != "app.kubernetes.io/part-of=" + reg.application_id
            or query.get("limit") != "32"
        ):
            raise ContractError("Unregistered application query")
        if type(timeout) not in (int, float) or not 0 < timeout <= 5:
            raise ContractError("Invalid read timeout")
        token = self.token_provider()
        if (
            not isinstance(token, str)
            or not 1 <= len(token) <= 16384
            or any(c.isspace() or ord(c) < 33 or ord(c) > 126 for c in token)
        ):
            raise ContractError("Invalid credential format")
        endpoint = urlsplit(reg.endpoint)
        connection = http.client.HTTPSConnection(
            endpoint.hostname,
            endpoint.port or 443,
            timeout=timeout,
            context=self.context,
        )
        deadline = time.monotonic() + timeout
        timer = None

        # TLS SNI/hostname verification still uses endpoint.hostname. Socket uses
        # only registered numeric IPs; DNS, environment proxies and redirects cannot change it.
        def connect_peer(address, timeout, source_address=None):
            peer = socket.create_connection(
                (reg.approved_addresses[0], endpoint.port or 443), timeout=timeout
            )
            left = deadline - time.monotonic()
            if left <= 0:
                peer.close()
                raise ContractError("Kubernetes connect deadline exceeded")
            peer.settimeout(left)
            return peer

        connection._create_connection = connect_peer
        try:
            connection.connect()
            left = deadline - time.monotonic()
            if left <= 0:
                raise ContractError("Kubernetes read deadline exceeded")
            peer = connection.sock

            def interrupt():
                try:
                    peer.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            # Socket inactivity timeout alone does not bound a trickling response.
            timer = Timer(left, interrupt)
            timer.daemon = True
            timer.start()
            connection.request(
                "GET",
                path + ("?" + urlencode(query) if query else ""),
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            )
            response = connection.getresponse()
            if (
                response.status != 200
                or response.getheader("Content-Encoding", "identity") != "identity"
            ):
                raise ContractError("Kubernetes read refused or unsupported response")
            body = response.read(MAX_RESPONSE + 1)
            if time.monotonic() >= deadline:
                raise ContractError("Kubernetes read deadline exceeded")
            if len(body) > MAX_RESPONSE:
                raise ContractError("Kubernetes response limit exceeded")
            return decode_api_json(body, limit=MAX_RESPONSE)
        except (OSError, http.client.HTTPException, UnicodeError, ValueError) as exc:
            raise ContractError("Kubernetes secure read failed") from exc
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            connection.close()
