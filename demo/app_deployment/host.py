"""Personal-session deployment API; no browser-selected cluster or credential."""

import asyncio
import json
from urllib.parse import urlsplit
from starlette.requests import Request
from starlette.responses import JSONResponse
from .intake import MAX_UPLOAD


class AppHost:
    def __init__(self, app, *, origin, authorize, apps):
        self.app, self.origin, self.host, self.authorize, self.apps = (
            app,
            origin,
            urlsplit(origin).netloc,
            authorize,
            apps,
        )

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not scope.get("path", "").startswith(
            "/__apps/"
        ):
            return await self.app(scope, receive, send)
        request = Request(scope, receive)

        async def reply(value, status=200):
            await JSONResponse(
                value,
                status_code=status,
                headers={
                    "Cache-Control": "no-store",
                    "X-Content-Type-Options": "nosniff",
                },
            )(scope, receive, send)

        if (
            request.headers.getlist("host") != [self.host]
            or scope.get("query_string")
            or "authorization" in request.headers
            or request.headers.get("sec-fetch-site") == "cross-site"
            or self.authorize(scope) is not True
        ):
            return await reply({"error": "personal_session_required"}, 403)
        if request.method == "GET" and scope["path"] == "/__apps/status":
            try:
                team = self.apps.team_app() if hasattr(self.apps, "team_app") else None
            except Exception:
                team = None
            if self.authorize(scope) is not True:
                return await reply({"error": "personal_session_required"}, 403)
            return await reply(
                {
                    "apps": self.apps.states(),
                    "team_app": team,
                    "source_environment": "AWS EKS",
                    "target_environment": "온프렘 RKE2",
                    "migration_connected": False,
                }
            )
        if request.method != "POST" or request.headers.getlist("origin") != [
            self.origin
        ]:
            return await reply({"error": "same_origin_post_required"}, 403)
        path = scope["path"]
        limit = MAX_UPLOAD if path == "/__apps/zip" else 4096
        try:
            data = bytearray()
            async for chunk in request.stream():
                data.extend(chunk)
                if len(data) > limit:
                    raise ValueError("request_size_limit")
            if self.authorize(scope) is not True:
                return await reply({"error": "personal_session_required"}, 403)
            if path == "/__apps/zip":
                if request.headers.get("content-type") != "application/zip":
                    raise ValueError("zip_content_type_required")
                result = await asyncio.to_thread(
                    self.apps.ingest, bytes(data), {"kind": "zip"}
                )
            else:
                if request.headers.get("content-type") != "application/json":
                    raise ValueError("json_content_type_required")
                body = json.loads(data)
                if path == "/__apps/github" and set(body) == {"repository", "ref"}:
                    result = await asyncio.to_thread(
                        self.apps.github, body["repository"], body["ref"]
                    )
                elif path == "/__apps/deploy" and set(body) == {
                    "id",
                    "source_digest",
                    "health",
                    "public",
                }:
                    result = self.apps.deploy(
                        body["id"],
                        body["source_digest"],
                        body["health"],
                        body["public"],
                    )
                else:
                    raise ValueError("unsupported_request")
            if self.authorize(scope) is not True:
                return await reply({"error": "session_expired"}, 403)
            return await reply(result, 202)
        except Exception:
            return await reply(
                {
                    "error": "request_rejected",
                    "detail": "입력 형식·소스 제한·현재 배포 상태를 확인하세요. 자격·외부 명령 출력은 표시하지 않습니다.",
                },
                400,
            )
