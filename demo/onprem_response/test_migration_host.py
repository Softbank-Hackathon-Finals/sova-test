from datetime import UTC, datetime, timedelta

import pytest
from starlette.responses import Response
from starlette.testclient import TestClient

from onprem_response.migration_host import MigrationReadStatus

NOW = datetime(2026, 1, 1, tzinfo=UTC)


async def fallback(scope, receive, send):
    await Response(status_code=404)(scope, receive, send)


def host(*, age=0, status=403, authorize=lambda _: True, override=None):
    calls = []

    def load():
        calls.append("read")
        return {
            "checked_at": (NOW - timedelta(seconds=age)).isoformat(),
            "tls_verified": True,
            "http_status": status,
            "plan_binding_confirmed": False,
        } | (override or {})

    app = MigrationReadStatus(
        fallback,
        origin="http://127.0.0.1:18131",
        authorize=authorize,
        load=load,
        clock=lambda: NOW,
    )
    return TestClient(app, base_url="http://127.0.0.1:18131"), calls


def test_no_authenticated_session_does_not_load_private_receipt():
    client, calls = host(authorize=lambda _: False)
    assert client.get("/__migration/status").status_code == 403
    assert calls == []


@pytest.mark.parametrize(
    "method,path,headers",
    [
        ("POST", "/__migration/status", {}),
        ("GET", "/__migration/status?plan=other", {}),
        ("GET", "/__migration/status", {"Origin": "https://other.example"}),
        ("GET", "/__migration/status", {"Host": "other.example"}),
        ("GET", "/__migration/status", {"Sec-Fetch-Site": "cross-site"}),
        ("GET", "/__migration/status", {"Authorization": "Bearer injected"}),
    ],
)
def test_no_browser_selected_action_or_authority(method, path, headers):
    client, calls = host()
    assert client.request(method, path, headers=headers).status_code == 403
    assert calls == []


def test_revocation_during_load_withdraws_receipt():
    responses = iter([True, False])
    client, _ = host(authorize=lambda _: next(responses))
    assert client.get("/__migration/status").status_code == 403


@pytest.mark.parametrize("status", [200, 403])
def test_http_success_or_denial_never_becomes_migration_permission(status):
    client, _ = host(status=status)
    response = client.get("/__migration/status")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert result["last_http_status"] == status
    assert result["authorizes_execution"] is False
    assert result["plan_connected"] is False


def test_old_read_is_labelled_historical():
    client, _ = host(age=180)
    assert client.get("/__migration/status").json()["current"] is False


@pytest.mark.parametrize(
    "override",
    [
        {"tls_verified": False},
        {"plan_binding_confirmed": True},
        {"checked_at": (NOW + timedelta(seconds=1)).isoformat()},
        {"checked_at": "2026-01-01T00:00:00"},
        {"http_status": "200"},
        {"token": "must-not-be-returned"},
    ],
)
def test_untrusted_receipt_fails_closed(override):
    client, _ = host(override=override)
    result = client.get("/__migration/status")
    assert result.status_code == 503
    assert result.json() == {"error": "read_status_unavailable"}
