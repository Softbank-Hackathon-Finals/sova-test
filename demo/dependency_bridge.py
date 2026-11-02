"""Fixed loopback Dependency Lab bridge behind the operator console boundary.

This does not merge the process demo with Kubernetes execution. Upstream cookies
are never returned to the browser; operator cookies/proofs are never forwarded.
"""

import http.client
from http.cookies import SimpleCookie, CookieError
import threading

from sova.adapters.registration.graph_codec import json_document
from sova.domain.contracts import ContractError, canonical_json, identifier


class DependencyBridge:
    def __init__(self, port):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ContractError("Fixed local dependency port required")
        self.port = port
        self.origin = "http://127.0.0.1:" + str(port)
        self._cookie = None
        self._session_lock = threading.Lock()
        self._action_lock = threading.Lock()

    def _exchange(self, method, path, body=None, *, cookie=None):
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=15 if body is not None else 4
        )
        headers = {"Accept": "application/json"}
        if cookie is not None:
            headers["Cookie"] = cookie
        if body is not None:
            headers.update({"Content-Type": "application/json", "Origin": self.origin})
        try:
            connection.request(
                method, path, None if body is None else canonical_json(body), headers
            )
            response = connection.getresponse()
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024 or response.status != 200:
                raise ContractError("Dependency result unverified; no automatic retry")
            return raw, response.getheader("Set-Cookie")
        except (OSError, http.client.HTTPException) as exc:
            raise ContractError(
                "Dependency transport unverified; no automatic retry"
            ) from exc
        finally:
            connection.close()

    def _session(self):
        with self._session_lock:
            if self._cookie is None:
                _, raw = self._exchange("GET", "/")
                try:
                    cookie = SimpleCookie(raw or "")
                except CookieError as exc:
                    raise ContractError("Invalid dependency session") from exc
                if (
                    set(cookie) != {"sova_graph"}
                    or not 32 <= len(cookie["sova_graph"].value) <= 128
                ):
                    raise ContractError("Registered dependency session required")
                self._cookie = "sova_graph=" + cookie["sova_graph"].value
            return self._cookie

    def _call(self, path, body=None):
        raw, _ = self._exchange(
            "GET" if body is None else "POST", path, body, cookie=self._session()
        )
        state = json_document(raw.decode(), limit=1024 * 1024)
        if (
            type(state) is not dict
            or type(state.get("nodes")) is not list
            or not 1 <= len(state["nodes"]) <= 32
            or type(state.get("revision")) is not int
            or not str(state.get("scope", "")).startswith("registered local demo;")
        ):
            raise ContractError("Registered dependency state required")
        return state

    def state(self):
        return self._call("/api/state")

    def action(self, body):
        if (
            type(body) is not dict
            or set(body) != {"action", "nodes"}
            or type(body["action"]) is not str
            or body["action"]
            not in {"fault", "clear_fault", "isolate", "restore", "probe"}
            or type(body["nodes"]) is not list
            or len(body["nodes"]) > 32
        ):
            raise ContractError("Exact dependency action required")
        for node in body["nodes"]:
            identifier(node)
        if len(set(body["nodes"])) != len(body["nodes"]):
            raise ContractError("Unique dependency subjects required")
        return self._mutate("/api/action", body)

    def application(self, body):
        if type(body) is not dict or set(body) != {"application_id"}:
            raise ContractError("Exact dependency application required")
        identifier(body["application_id"])
        return self._mutate("/api/application", body)

    def _mutate(self, path, body):
        if not self._action_lock.acquire(blocking=False):
            raise ContractError("Dependency action already in progress")
        try:
            return self._call(path, body)
        finally:
            self._action_lock.release()
