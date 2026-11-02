"""Minimal consultation workload: actual PG, WebSocket, private files and OTel.

Synthetic invites are not financial enterprise authentication. The app never
executes schema migrations, invents an AI summary or exposes an admin endpoint.
"""

import asyncio
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict
import hashlib
from http.cookies import SimpleCookie, CookieError
import json
import os
from pathlib import Path
import re
import threading
import time
from urllib.parse import urlsplit, quote, unquote_to_bytes

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from opentelemetry.trace import SpanKind
from fastapi.responses import FileResponse, JSONResponse, Response
import psycopg

from .private_files import private_text
from .objects import LocalObjects, S3Objects
from .storage import AccessDenied, AppError, ConsultationStore
from .telemetry import WorkloadTelemetry


class TooLarge(AppError):
    status = 413
    code = "body_too_large"


async def body_bytes(request, maximum):
    result = bytearray()
    async for chunk in request.stream():
        if len(result) + len(chunk) > maximum:
            raise TooLarge()
        result.extend(chunk)
    return bytes(result)


async def document(request, keys):
    if request.headers.get("content-type") != "application/json":
        raise AppError()

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        value = json.loads(
            (await body_bytes(request, 16384)).decode("utf-8"), object_pairs_hook=pairs
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise AppError() from exc
    if type(value) is not dict or set(value) != set(keys):
        raise AppError()
    return value


def attachment_filename(headers):
    encoded = headers.getlist("x-filename-encoded")
    legacy = headers.getlist("x-filename")
    if len(encoded) > 1 or len(legacy) > 1 or encoded and legacy:
        raise AppError()
    if not encoded:
        return legacy[0] if legacy else "attachment.bin"
    value = encoded[0]
    if (
        not value.isascii()
        or len(value) > 1536
        or re.search(r"%(?![a-fA-F0-9]{2})", value)
    ):
        raise AppError()
    try:
        return unquote_to_bytes(value).decode("utf-8")
    except UnicodeError as exc:
        raise AppError() from exc


def cookie(headers):
    values = headers.getlist("cookie")
    if len(values) != 1 or values[0].count("consultation_session=") != 1:
        raise AccessDenied()
    try:
        jar = SimpleCookie(values[0])
        return jar["consultation_session"].value
    except (CookieError, KeyError) as exc:
        raise AccessDenied() from exc


def configured_objects():
    backend = os.environ.get("CONSULTATION_OBJECT_BACKEND", "local")
    if backend == "local":
        return LocalObjects(os.environ.get("CONSULTATION_OBJECT_DIR", "/data/objects"))
    if backend != "s3":
        raise ValueError("Explicit local or S3 object backend required")
    if any(
        key.startswith("AWS_ENDPOINT_URL") and value
        for key, value in os.environ.items()
    ):
        raise ValueError("Custom AWS endpoints require separate qualification")
    import boto3
    from botocore.config import Config

    client = boto3.client(
        "s3",
        region_name=os.environ["CONSULTATION_S3_REGION"],
        config=Config(
            connect_timeout=2,
            read_timeout=3,
            retries={"total_max_attempts": 1, "mode": "standard"},
            signature_version="s3v4",
        ),
    )
    try:
        return S3Objects(
            client,
            bucket=os.environ["CONSULTATION_S3_BUCKET"],
            prefix=os.environ["CONSULTATION_S3_PREFIX"],
            kms_key_id=os.environ["CONSULTATION_S3_KMS_KEY_ARN"],
            account_id=os.environ["CONSULTATION_S3_OWNER_ACCOUNT"],
        )
    except Exception:
        client.close()
        raise


def create_app(
    store=None, *, origin=None, objects=None, telemetry=None, summarize=None
):
    origin = origin or os.environ.get("CONSULTATION_ORIGIN", "http://127.0.0.1:8794")
    parsed = urlsplit(origin)
    if (
        parsed.path
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.hostname
        or parsed.scheme not in {"http", "https"}
        or parsed.scheme == "http"
        and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
    ):
        raise ValueError("Exact HTTPS origin or loopback development origin required")
    if store is None:
        path = os.environ["DATABASE_URL_FILE"]
        store = ConsultationStore(
            lambda: psycopg.connect(
                private_text(path),
                connect_timeout=5,
                options="-c statement_timeout=5000 -c lock_timeout=1000",
            ),
            environment=os.environ["CONSULTATION_ENVIRONMENT"],
        )
    owns_objects = objects is None
    objects = objects if objects is not None else configured_objects()
    telemetry = telemetry or WorkloadTelemetry(
        application_id="consultation",
        environment=store.environment,
        deployment_revision=os.environ.get(
            "CONSULTATION_REVISION", "unregistered-development"
        ),
    )

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await asyncio.to_thread(telemetry.close)
        if owns_objects and hasattr(objects, "close"):
            await asyncio.to_thread(objects.close)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store, app.state.telemetry = store, telemetry
    login_attempts, login_lock = deque(maxlen=64), threading.Lock()

    @app.exception_handler(AppError)
    async def rejected(_request, exc):
        return JSONResponse(
            {"error": exc.code},
            status_code=exc.status,
            headers={"Retry-After": "2"} if exc.status == 503 else {},
        )

    @app.exception_handler(psycopg.Error)
    async def database_unavailable(_request, _exc):
        return JSONResponse(
            {"error": "database_unavailable"},
            status_code=503,
            headers={"Retry-After": "2"},
        )

    @app.middleware("http")
    async def boundary(request, call_next):
        if request.headers.getlist("host") != [
            parsed.netloc
        ] or request.headers.getlist("origin") not in ([], [origin]):
            return JSONResponse({"error": "origin_denied"}, status_code=403)
        if request.method not in {"GET", "HEAD"} and request.headers.getlist(
            "origin"
        ) != [origin]:
            return JSONResponse({"error": "origin_required"}, status_code=403)
        if request.method in {"POST", "PUT"}:
            lengths = request.headers.getlist("content-length")
            if (
                len(lengths) != 1
                or not lengths[0].isdigit()
                or int(lengths[0]) > 1048576
            ):
                return JSONResponse({"error": "bounded_body_required"}, status_code=413)
        with telemetry.tracer.start_as_current_span(
            "HTTP",
            kind=SpanKind.SERVER,
            record_exception=False,
            set_status_on_exception=False,
        ) as span:
            response = await call_next(request)
            route = getattr(request.scope.get("route"), "path", None)
            if route is not None:
                span.set_attribute("http.route", route)
                span.set_attribute("http.request.method", request.method)
                span.set_attribute("http.response.status_code", response.status_code)
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        return response

    def actor(request):
        values = request.headers.getlist("x-consultation-csrf")
        if len(values) != 1:
            raise AccessDenied()
        return store.authenticate(cookie(request.headers), values[0])

    async def traced(request, route, function, *args, **kwargs):
        return await asyncio.to_thread(function, *args, **kwargs)

    @app.get("/")
    async def index():
        return FileResponse(Path(__file__).parent / "web/index.html")

    @app.get("/app.js")
    async def script():
        return FileResponse(
            Path(__file__).parent / "web/app.js", media_type="text/javascript"
        )

    @app.get("/style.css")
    async def style():
        return FileResponse(
            Path(__file__).parent / "web/style.css", media_type="text/css"
        )

    @app.get("/health")
    async def health(request: Request):
        return await traced(request, "/health", store.health)

    @app.post("/api/session")
    async def login(request: Request):
        with login_lock:
            now = time.monotonic()
            while login_attempts and now - login_attempts[0] > 30:
                login_attempts.popleft()
            if len(login_attempts) >= 16:
                return JSONResponse({"error": "login_rate_limited"}, status_code=429)
            login_attempts.append(now)
        data = await document(request, ("invite",))
        result = await traced(request, "/api/session", store.login, data["invite"])
        response = JSONResponse(
            {"csrf": result["csrf"], "expires_at": result["expires_at"]}
        )
        response.set_cookie(
            "consultation_session",
            result["token"],
            httponly=True,
            secure=parsed.scheme == "https",
            samesite="strict",
            max_age=1800,
        )
        return response

    @app.get("/api/me")
    async def me(request: Request):
        return asdict(await asyncio.to_thread(actor, request))

    @app.post("/api/logout")
    async def logout(request: Request):
        await asyncio.to_thread(actor, request)
        await traced(request, "/api/logout", store.logout, cookie(request.headers))
        response = JSONResponse({"status": "logged_out"})
        response.delete_cookie("consultation_session")
        return response

    @app.get("/api/rooms")
    async def rooms(request: Request):
        current = await asyncio.to_thread(actor, request)
        return await traced(request, "/api/rooms", store.rooms, current)

    @app.post("/api/rooms")
    async def new_room(request: Request):
        current = await asyncio.to_thread(actor, request)
        await document(request, ())
        return await traced(request, "/api/rooms", store.create_room, current)

    @app.get("/api/rooms/{room_id}/messages")
    async def messages(request: Request, room_id: str, after: int = 0):
        current = await asyncio.to_thread(actor, request)
        return await traced(
            request,
            "/api/rooms/{room_id}/messages",
            store.messages,
            current,
            room_id,
            after=after,
        )

    @app.post("/api/rooms/{room_id}/messages")
    async def send(request: Request, room_id: str):
        current = await asyncio.to_thread(actor, request)
        data = await document(request, ("client_request_id", "content"))
        return await traced(
            request,
            "/api/rooms/{room_id}/messages",
            store.send,
            current,
            room_id,
            data["client_request_id"],
            data["content"],
        )

    @app.put("/api/rooms/{room_id}/attachments/{attachment_id}")
    async def upload(request: Request, room_id: str, attachment_id: str):
        current = await asyncio.to_thread(actor, request)
        if request.headers.get("content-type") != "application/octet-stream":
            raise AppError()
        content = await body_bytes(request, 1048576)
        # Keep the known writer gate across storage I/O and metadata commit.
        result = await traced(
            request,
            "/api/rooms/{room_id}/attachments",
            store.upload_attachment,
            current,
            room_id,
            attachment_id,
            attachment_filename(request.headers),
            content,
            objects.put,
        )
        return result

    @app.get("/api/rooms/{room_id}/attachments/{attachment_id}")
    async def download(request: Request, room_id: str, attachment_id: str):
        current = await asyncio.to_thread(actor, request)
        meta = await traced(
            request,
            "/api/rooms/{room_id}/attachments",
            store.attachment,
            current,
            room_id,
            attachment_id,
        )
        content = await asyncio.to_thread(objects.get, meta["id"])
        if (
            len(content) != meta["byte_length"]
            or hashlib.sha256(content).hexdigest() != meta["content_digest"]
        ):
            return JSONResponse({"error": "object_integrity_failed"}, status_code=503)
        return Response(
            content,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": "attachment; filename*=UTF-8''"
                + quote(meta["filename"], safe="")
            },
        )

    @app.post("/api/rooms/{room_id}/summary")
    async def summary(request: Request, room_id: str):
        current = await asyncio.to_thread(actor, request)
        if current.role != "counselor":
            raise AccessDenied()
        items = await asyncio.to_thread(
            store.messages, current, room_id, after=0, limit=100
        )
        if summarize is None:
            return JSONResponse({"error": "ai_gateway_unconfigured"}, status_code=503)
        # Only a deployment-registered gateway receives this payload; a browser
        # cannot select endpoints, lower classification, or supply a model key.
        result = await traced(
            request,
            "/api/rooms/{room_id}/summary",
            summarize,
            items,
            data_class="confidential",
            purpose="consultation-summary",
        )
        return {"summary": result}

    @app.websocket("/api/rooms/{room_id}/stream")
    async def stream(websocket: WebSocket, room_id: str, after: int = 0):
        try:
            if (
                websocket.headers.getlist("host") != [parsed.netloc]
                or websocket.headers.getlist("origin") != [origin]
                or len(websocket.scope["subprotocols"]) != 2
                or websocket.scope["subprotocols"][0] != "consultation"
            ):
                raise AccessDenied()
            token, proof = cookie(websocket.headers), websocket.scope["subprotocols"][1]
            current = await asyncio.to_thread(store.authenticate, token, proof)
            await asyncio.to_thread(store.messages, current, room_id, after=after)
            await websocket.accept(subprotocol="consultation")
            while True:
                current = await asyncio.to_thread(store.authenticate, token, proof)
                items = await asyncio.to_thread(
                    store.messages, current, room_id, after=after
                )
                if items:
                    after = int(items[-1]["sequence"])
                await websocket.send_json(
                    {
                        "messages": items,
                        "cursor": str(after),
                        "environment": store.environment,
                    }
                )
                try:
                    event = await asyncio.wait_for(websocket.receive(), timeout=1)
                    if event["type"] == "websocket.disconnect":
                        return
                except TimeoutError:
                    pass
        except (AppError, psycopg.Error):
            await websocket.close(code=1008)
        except (WebSocketDisconnect, RuntimeError, OSError):
            return

    return app
