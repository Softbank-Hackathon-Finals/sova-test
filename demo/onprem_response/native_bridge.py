"""Bounded transport for the existing T10 console, not a second approval engine.

T10 verifies personal identity, plan permissions, evidence and idempotency. The
local window adds an operational coordination limit; it never grants T10 rights.
No shared mutation is enabled unless the host explicitly supplies that window.
"""

import asyncio
import json
import re
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse

ID = r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}"
PLAN = re.compile(rf"/v1/plans/({ID})(?:/(.*))?\Z")
READ = re.compile(
    rf"(?:events|workspace|observations|controls|security|audit|workload|delivery|"
    rf"network-status|network-stream|run-state|operation-receipts/{ID}|"
    rf"approvals/{ID}|infra-approvals/{ID}|cutover/{ID}|failback/{ID}|"
    rf"rehearsals/{ID}|iac/plans/{ID})\Z"
)
HEADERS = {
    "Cache-Control": "no-store",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}


@dataclass(frozen=True)
class OperationWindow:
    plan_id: str
    expires_at: datetime
    routes: frozenset[str]
    approval_kinds: frozenset[str]
    coordination_ref: str

    def valid(self, now):
        return (
            isinstance(self.plan_id, str)
            and re.fullmatch(ID, self.plan_id)
            and isinstance(self.expires_at, datetime)
            and self.expires_at.tzinfo is not None
            and 0 < (self.expires_at - now).total_seconds() <= 3600
            and type(self.routes) is frozenset
            and bool(self.routes)
            and self.routes <= {"approvals", "cutover", "failback"}
            and type(self.approval_kinds) is frozenset
            and self.approval_kinds <= {"change", "cutover", "shift", "failback"}
            and isinstance(self.coordination_ref, str)
            and 1 <= len(self.coordination_ref) <= 256
        )


class NativePlanBridge:
    def __init__(
        self,
        app,
        *,
        origin,
        upstream,
        tls,
        tls_name,
        authorize,
        proof,
        window=lambda: None,
        transport=None,
        clock=None,
    ):
        local, target = urlsplit(origin), urlsplit(upstream)
        if (
            local.scheme != "http"
            or local.hostname != "127.0.0.1"
            or not local.port
            or local.path
            or local.query
            or local.fragment
            or local.username
            or target.scheme != "https"
            or not target.hostname
            or target.path
            or target.query
            or target.fragment
            or target.username
            or not isinstance(tls, ssl.SSLContext)
            or not tls.check_hostname
            or tls.verify_mode != ssl.CERT_REQUIRED
            or not isinstance(tls_name, str)
            or not tls_name
            or len(tls_name) > 253
            or any(
                not re.fullmatch(
                    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label
                )
                for label in tls_name.split(".")
            )
            or not all(callable(f) for f in (authorize, proof, window))
        ):
            raise ValueError("verified_fixed_native_transport_required")
        self.app, self.origin, self.host = app, origin, local.netloc
        self.upstream, self.tls, self.tls_name = upstream, tls, tls_name
        self.authorize, self.proof, self.window = authorize, proof, window
        self.transport = transport
        self.clock = clock or (lambda: datetime.now(UTC))
        self.slots = asyncio.Semaphore(4)

    def allowed_window(self):
        value = self.window()
        return (
            value
            if type(value) is OperationWindow and value.valid(self.clock())
            else None
        )

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not (
            scope["path"].startswith("/v1/plans/")
            or scope["path"]
            in {"/v1/plans", "/v1/environments", "/v1/workloads", "/__native/status"}
        ):
            return await self.app(scope, receive, send)
        request = Request(scope, receive)

        async def error(code, status=403):
            await JSONResponse(
                {"detail": {"code": code}}, status_code=status, headers=HEADERS
            )(scope, receive, send)

        try:
            raw = scope.get("raw_path", scope["path"].encode())
            if (
                request.headers.getlist("host") != [self.host]
                or request.headers.getlist("sec-fetch-site")
                not in ([], ["same-origin"], ["none"])
                or (
                    "origin" in request.headers
                    and request.headers.getlist("origin") != [self.origin]
                )
                or "authorization" in request.headers
                or "transfer-encoding" in request.headers
                or not raw.isascii()
                or raw.decode() != scope["path"]
                or any(x in raw for x in (b"%", b"\\", b"//"))
                or any(x in (b".", b"..") for x in raw.split(b"/"))
                or self.authorize(scope) is not True
            ):
                return await error("native_session_required")
            if scope["path"] == "/__native/status":
                if request.method != "GET" or scope.get("query_string"):
                    return await error("native_read_only_status")
                w = self.allowed_window()
                return await JSONResponse(
                    {
                        "kind": "native-console-transport.v1",
                        "native_authorization_required": True,
                        "window": None
                        if w is None
                        else {
                            "plan_id": w.plan_id,
                            "expires_at": w.expires_at.isoformat(),
                            "routes": sorted(w.routes),
                            "approval_kinds": sorted(w.approval_kinds),
                        },
                    },
                    headers=HEADERS,
                )(scope, receive, send)
            match = PLAN.fullmatch(scope["path"])
            if match is None:
                return await error("registration_not_enabled")
            plan, suffix = match[1], match[2] or ""
            query = scope.get("query_string", b"")
            is_stream = suffix in {"events", "network-stream"}
            if query and not (suffix == "events" and query == b"follow=false"):
                return await error("native_query_not_allowed", 400)
            method = request.method
            # Same fixed host boundary used by the qualified native OperatorBridge.
            headers = {
                "Host": self.host,
                "Accept": "text/event-stream" if is_stream else "application/json",
            }
            body = None
            if method == "GET":
                if suffix and READ.fullmatch(suffix) is None:
                    return await error("native_read_route_not_allowed", 404)
                if request.headers.getlist("content-length") not in ([], ["0"]):
                    return await error("get_body_not_allowed", 400)
                cursor = request.headers.getlist("last-event-id")
                if cursor:
                    if (
                        len(cursor) != 1
                        or not is_stream
                        or re.fullmatch(re.escape(plan) + r":[0-9]{1,18}", cursor[0])
                        is None
                    ):
                        return await error("native_cursor_invalid", 400)
                    headers["Last-Event-ID"] = cursor[0]
            elif method == "POST":
                w = self.allowed_window()
                if w is None or plan != w.plan_id or suffix not in w.routes:
                    return await error("operation_window_required")
                key = request.headers.getlist("idempotency-key")
                if (
                    request.headers.getlist("origin") != [self.origin]
                    or request.headers.getlist("x-bravo-console") != ["1"]
                    or request.headers.getlist("content-type") != ["application/json"]
                    or len(key) != 1
                    or re.fullmatch(ID, key[0]) is None
                ):
                    return await error("native_change_boundary")
                data = bytearray()
                async for chunk in request.stream():
                    data.extend(chunk)
                    if len(data) > 65536:
                        return await error("request_too_large", 413)
                value = json.loads(data)
                if type(value) is not dict:
                    return await error("native_body_invalid", 400)
                if (
                    suffix == "approvals"
                    and value.get("approval_kind", "cutover") not in w.approval_kinds
                ):
                    return await error("approval_kind_outside_window")
                body = bytes(data)
                headers.update(
                    {
                        "Content-Type": "application/json",
                        "X-Bravo-Console": "1",
                        "Origin": self.origin,
                        "Idempotency-Key": key[0],
                    }
                )
            else:
                return await error("native_method_not_allowed", 405)
        except Exception:
            return await error("native_request_unconfirmed", 400)

        async with self.slots:
            client = upstream = None
            try:
                if self.authorize(scope) is not True:
                    return await error("native_session_required")
                proof_started = asyncio.get_running_loop().time()
                proof = await asyncio.to_thread(self.proof)
                if self.authorize(scope) is not True:
                    return await error("native_session_required")
                if method == "POST" and self.allowed_window() != w:
                    return await error("operation_window_changed")
                headers["Authorization"] = "Bearer " + proof
                client = httpx.AsyncClient(
                    verify=self.tls,
                    transport=self.transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(15, read=40),
                )
                url = self.upstream + scope["path"] + ("?follow=false" if query else "")
                upstream = await client.send(
                    client.build_request(
                        method,
                        url,
                        headers=headers,
                        content=body,
                        extensions={"sni_hostname": self.tls_name},
                    ),
                    stream=True,
                )
                if 300 <= upstream.status_code < 400:
                    return await error("upstream_redirect_refused", 502)
                if self.authorize(scope) is not True:
                    return await error("native_session_required")
                mime = upstream.headers.get("content-type", "")
                if is_stream and upstream.status_code == 200:
                    if not mime.startswith("text/event-stream"):
                        return await error("native_stream_invalid", 502)

                    async def events():
                        iterator = upstream.aiter_bytes()
                        end = proof_started + 45
                        try:
                            while self.authorize(scope) is True:
                                left = end - asyncio.get_running_loop().time()
                                if left <= 0:
                                    return
                                try:
                                    chunk = await asyncio.wait_for(
                                        anext(iterator), left
                                    )
                                except (StopAsyncIteration, TimeoutError):
                                    return
                                if self.authorize(scope) is not True:
                                    return
                                yield chunk
                        except Exception:
                            # Headers are already sent; terminate the stream rather
                            # than attempting a second JSON response after a fault.
                            return

                    return await StreamingResponse(
                        events(), media_type="text/event-stream", headers=HEADERS
                    )(scope, receive, send)
                data = bytearray()
                async for chunk in upstream.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > 131072:
                        return await error("native_response_limit", 502)
                if self.authorize(scope) is not True:
                    return await error("native_session_required")
                if not mime.startswith("application/json"):
                    return await error("native_response_invalid", 502)
                return await Response(
                    bytes(data),
                    status_code=upstream.status_code,
                    media_type="application/json",
                    headers=HEADERS,
                )(scope, receive, send)
            except Exception:
                # Never retry POST, return credentials, or infer an effect from a timeout.
                return await error("native_result_unconfirmed", 503)
            finally:
                if upstream is not None:
                    await upstream.aclose()
                if client is not None:
                    await client.aclose()
