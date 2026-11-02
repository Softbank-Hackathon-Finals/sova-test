"""Fixed AWS/VM preview bridge. No cloud provisioning or implicit renewal.

Operator credentials stay at the console. The legacy upstream session is separate.
Only an exact, current registration can authorize a route change; never retry POST.
"""

from datetime import UTC, datetime
from datetime import timedelta
import hashlib
import http.client
from http.cookies import CookieError, SimpleCookie
import re
import threading
import time

from sova.adapters.registration.graph_codec import json_document
from sova.domain.contracts import ContractError, ResourceScope, canonical_json
from sova.domain.evidence import EvidenceRecord, Gate, RevisionSet, VerificationResult
from sova.domain.migration_program import six_area_catalog, six_area_program


class MigrationBridge:
    def __init__(self, port=8790, *, bootstrap_token_provider=None):
        if type(port) is not int or not 1 <= port <= 65535:
            raise ContractError("Fixed migration port required")
        self.port = port
        self.origin = f"http://127.0.0.1:{port}"
        self._cookie = None
        self._session_lock = threading.Lock()
        self._action_lock = threading.Lock()
        self._bootstrap_token_provider = bootstrap_token_provider

    def _exchange(self, method, path, body=None):
        conn = http.client.HTTPConnection(
            "127.0.0.1", self.port, timeout=20 if method == "POST" else 4
        )
        headers = {"Accept": "application/json"}
        if path == "/" and self._bootstrap_token_provider is not None:
            secret = self._bootstrap_token_provider()
            if type(secret) is not str or not re.fullmatch(
                r"[A-Za-z0-9_-]{32,128}", secret
            ):
                raise ContractError("Owner bridge credential required")
            headers["X-Sova-Bridge"] = secret
        if self._cookie:
            headers["Cookie"] = self._cookie
        if body is not None:
            headers.update({"Origin": self.origin, "Content-Type": "application/json"})
        try:
            conn.request(
                method,
                path,
                None if body is None else canonical_json(body).encode("utf-8"),
                headers,
            )
            response = conn.getresponse()
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024 or response.status not in {200, 202}:
                raise ContractError("Migration response unverified; no automatic retry")
            return raw, response.getheader("Set-Cookie")
        except (OSError, http.client.HTTPException) as exc:
            raise ContractError(
                "Migration backend unavailable; no automatic retry"
            ) from exc
        finally:
            conn.close()

    def _session(self):
        with self._session_lock:
            if self._cookie is not None:
                return
            _, raw = self._exchange("GET", "/")
            try:
                cookies = SimpleCookie(raw or "")
            except CookieError as exc:
                raise ContractError("Invalid migration session") from exc
            if (
                set(cookies) != {"sova_preview"}
                or not 32 <= len(cookies["sova_preview"].value) <= 128
            ):
                raise ContractError("Registered migration session required")
            self._cookie = "sova_preview=" + cookies["sova_preview"].value

    def _state(self):
        self._session()
        raw, _ = self._exchange("GET", "/api/state")
        state = json_document(raw.decode(), limit=1024 * 1024)
        if (
            type(state) is not dict
            or state.get("route") not in {"aws", "vm"}
            or type(state.get("route_revision")) is not int
            or state["route_revision"] < 1
            or not re.fullmatch(r"[a-f0-9]{64}", str(state.get("revision", "")))
            or type(state.get("now")) not in {int, float}
            or not -5 <= time.time() - state["now"] <= 15
            or type(state.get("workloads")) is not dict
            or set(state["workloads"]) != {"aws", "vm"}
            or not all(
                type(v) is dict and v.get("database") is False
                for v in state["workloads"].values()
            )
            or type(state.get("observations")) is not dict
            or type(state.get("events")) is not list
            or type(state.get("workflows")) is not list
            or not str(state.get("scope", "")).startswith("실제 AWS·VM 요청 /")
        ):
            raise ContractError("Registered migration state required")
        try:
            expiry = datetime.fromisoformat(state["expires_at"])
            if expiry.tzinfo is None or datetime.now(UTC) >= expiry:
                raise ValueError("expired")
        except (KeyError, ValueError, TypeError) as exc:
            raise ContractError("Migration registration expired or unverified") from exc
        return state

    def state(self):
        try:
            return {"status": "connected", "state": self._state()}
        except (ContractError, ValueError, TypeError, UnicodeError):
            with self._session_lock:
                self._cookie = None
            return {
                "status": "unavailable",
                "state": None,
                "reason": "AWS·VM 실행 서버가 꺼져 있거나 등록이 만료·미검증 상태입니다. 자동으로 자원을 생성하지 않습니다.",
            }

    def readiness(self):
        catalog = six_area_catalog()
        try:
            state = self._state()
            issued = datetime.fromisoformat(state["registered_at"])
            expiry = datetime.fromisoformat(state["expires_at"])
            a = state["workloads"]["aws"]["instance"]
            b = state["workloads"]["vm"]["instance"]
            if (
                not re.fullmatch(r"sova-probe-[0-9a-f]{12}-aws", a)
                or b != a.removesuffix("-aws") + "-vm"
            ):
                raise ContractError("Exact owned preview application required")
            app = a.removesuffix("-aws")
            source = ResourceScope("local-operator", app, "aws-preview", a)
            target = ResourceScope("local-operator", app, "lima-preview", b)

            def hashed(value):
                return hashlib.sha256(
                    canonical_json(value, limit=65536).encode()
                ).hexdigest()

            revisions = RevisionSet(
                state["revision"],
                hashed(state["workloads"]),
                hashed({"catalog": catalog}),
                hashed({"source": a, "target": b, "expires_at": state["expires_at"]}),
            )
            program = six_area_program(
                source, target, revisions, issued_at=issued, valid_until=expiry
            )
            now = datetime.now(UTC)
            observation = state["observations"].get("vm", {})
            evidence = ()
            at = observation.get("observed_at")
            if (
                observation.get("available") is True
                and observation.get("instance") == b
                and type(at) in {int, float}
                and 0 <= now.timestamp() - at < 8
            ):
                observed_at = datetime.fromtimestamp(at, UTC)
                evidence = (
                    EvidenceRecord(
                        "preview-vm-health",
                        "migration:target-http",
                        target,
                        revisions,
                        "migration-http-readback-v1",
                        observed_at,
                        min(expiry, observed_at + timedelta(seconds=8)),
                        VerificationResult.PASS,
                        "owned-https-observation",
                        hashed(observation),
                    ),
                )
            report = program.assess(evidence, Gate.PREFLIGHT, now=now)
            return {
                "status": "connected",
                "catalog": catalog,
                "report": report,
                "evidence_boundary": "local registered fixture health only; no signed production qualification",
                "observed_at": now.isoformat(),
                "expires_at": min(
                    [expiry, *(e.valid_until for e in evidence)]
                ).isoformat(),
            }
        except (
            ContractError,
            KeyError,
            ValueError,
            TypeError,
            UnicodeError,
            OverflowError,
        ):
            return {
                "status": "unavailable",
                "catalog": catalog,
                "report": None,
                "reason": "현재 실행에 결합된 검증 근거를 확인할 수 없습니다.",
            }

    def action(self, body):
        if type(body) is not dict or set(body) != {
            "action",
            "environment",
            "revision",
            "route_revision",
        }:
            raise ContractError("Exact migration action required")
        if (
            type(body["action"]) is not str
            or body["action"] not in {"switch", "probe"}
            or type(body["environment"]) is not str
            or body["environment"] not in {"aws", "vm"}
            or type(body["revision"]) is not str
            or type(body["route_revision"]) is not int
        ):
            raise ContractError("Registered migration action required")
        if not self._action_lock.acquire(blocking=False):
            raise ContractError("Migration action in progress")
        try:
            state = self._state()
            if (body["revision"], body["route_revision"]) != (
                state["revision"],
                state["route_revision"],
            ):
                raise ContractError("Migration approval binding changed")
            if body["action"] == "switch":
                raw, _ = self._exchange(
                    "POST",
                    "/api/switch-checked",
                    {
                        "environment": body["environment"],
                        "revision": body["revision"],
                        "route_revision": body["route_revision"],
                    },
                )
            else:
                if body["environment"] != state["route"]:
                    raise ContractError("Probe must use current route")
                raw, _ = self._exchange(
                    "POST",
                    "/api/action",
                    {
                        "message": "Sova 통합 콘솔 업무 요청",
                        "automatic": False,
                    },
                )
            result = json_document(raw.decode(), limit=1024 * 1024)
            if type(result) is not dict:
                raise ContractError("Migration result unverified; no automatic retry")
            return {"status": "accepted-not-complete", "result": result}
        finally:
            self._action_lock.release()
