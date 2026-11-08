"""Authenticated display of a host-owned native API read receipt, never a grant.

The host supplies its own bounded observation loader. Browser input cannot choose
an upstream, plan, credential, path or action. No upstream call is made here.
"""

from datetime import UTC, datetime
from urllib.parse import urlsplit

from starlette.requests import Request
from starlette.responses import JSONResponse


class MigrationReadStatus:
    def __init__(self, app, *, origin, authorize, load, clock=None):
        parsed = urlsplit(origin)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or not parsed.port
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username
            or not callable(authorize)
            or not callable(load)
        ):
            raise ValueError("explicit_local_read_host_required")
        self.app, self.origin, self.host = app, origin, parsed.netloc
        self.authorize, self.load = authorize, load
        self.clock = clock or (lambda: datetime.now(UTC))

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or scope.get("path") != "/__migration/status":
            return await self.app(scope, receive, send)
        request = Request(scope, receive)
        headers = {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"}

        async def reply(value, status=200):
            await JSONResponse(value, status_code=status, headers=headers)(scope, receive, send)

        if (
            request.method != "GET"
            or request.headers.getlist("host") != [self.host]
            or scope.get("query_string")
            or ("origin" in request.headers and request.headers.getlist("origin") != [self.origin])
            or request.headers.get("sec-fetch-site") == "cross-site"
            or request.headers.getlist("content-length") not in ([], ["0"])
            or "transfer-encoding" in request.headers
            or "authorization" in request.headers
        ):
            return await reply({"error": "read_boundary_denied"}, 403)
        try:
            if self.authorize(scope) is not True:
                return await reply({"error": "session_required"}, 403)
            source = self.load()
            if set(source) != {"checked_at", "tls_verified", "http_status", "plan_binding_confirmed"}:
                raise ValueError("read_receipt_invalid")
            at = datetime.fromisoformat(source["checked_at"])
            age = (self.clock() - at).total_seconds()
            if (
                at.tzinfo is None
                or age < 0
                or source["tls_verified"] is not True
                or type(source["http_status"]) is not int
                or source["http_status"] not in {200, 401, 403, 404, 503}
                or source["plan_binding_confirmed"] is not False
            ):
                raise ValueError("verified_read_receipt_required")
            value = {
                "kind": "native-plan-read-status.v1",
                "checked_at": at.isoformat(),
                "current": age < 180,
                "last_http_status": source["http_status"],
                "plan_connected": False,
                "authorizes_execution": False,
            }
            if self.authorize(scope) is not True:
                return await reply({"error": "session_required"}, 403)
        except Exception:
            return await reply({"error": "read_status_unavailable"}, 503)
        return await reply(value)
