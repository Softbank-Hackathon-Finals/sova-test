"""Transport qualification with a fake T10; not an operational migration test."""

import json
import ssl
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from starlette.responses import Response
from starlette.testclient import TestClient

from onprem_response.native_bridge import NativePlanBridge, OperationWindow

NOW = datetime(2026, 1, 1, tzinfo=UTC)
ORIGIN = "http://127.0.0.1:18131"
PATH = "/v1/plans/plan-test"
POST = {"Origin": ORIGIN, "X-Bravo-Console": "1", "Idempotency-Key": "one-request"}


async def fallback(scope, receive, send):
    await Response(status_code=404)(scope, receive, send)


def window(**changes):
    return OperationWindow(
        **(
            {
                "plan_id": "plan-test",
                "expires_at": NOW + timedelta(minutes=5),
                "routes": frozenset({"approvals", "cutover", "failback"}),
                "approval_kinds": frozenset({"change", "shift", "cutover", "failback"}),
                "coordination_ref": "test-only-coordination",
            }
            | changes
        )
    )


def setup(
    *, authorize=lambda _: True, operation_window=lambda: None, handler=None, proof=None
):
    calls, proofs = [], []

    def upstream(request):
        calls.append(request)
        return (
            handler(request) if handler else httpx.Response(200, json={"native": True})
        )

    def issue():
        proofs.append(True)
        return proof() if proof else "test-proof-never-reflected"

    app = NativePlanBridge(
        fallback,
        origin=ORIGIN,
        upstream="https://native.example",
        tls=ssl.create_default_context(),
        tls_name="native.example",
        authorize=authorize,
        proof=issue,
        window=operation_window,
        transport=httpx.MockTransport(upstream),
        clock=lambda: NOW,
    )
    return TestClient(app, base_url=ORIGIN), calls, proofs


def test_no_session_no_proof_or_upstream():
    client, calls, proofs = setup(authorize=lambda _: False)
    assert client.get(PATH).status_code == 403
    assert not calls and not proofs


@pytest.mark.parametrize(
    "method,path,headers",
    [
        ("GET", PATH, {"Host": "elsewhere.example"}),
        ("GET", PATH, {"Origin": "http://127.0.0.1:9999"}),
        ("GET", PATH, {"Sec-Fetch-Site": "same-site"}),
        ("GET", PATH, {"Authorization": "Bearer injected"}),
        ("GET", PATH + "/..%2fregistrations", {}),
        ("GET", PATH + "?profile=default", {}),
        ("GET", PATH + "/events", {"Last-Event-ID": "another-plan:1"}),
        (
            "GET",
            PATH + "/events",
            [("Last-Event-ID", "plan-test:1"), ("Last-Event-ID", "plan-test:2")],
        ),
        ("GET", PATH + "/not-registered", {}),
        ("DELETE", PATH, {}),
        ("POST", "/v1/plans", POST),
        ("POST", PATH + "/cutover", POST),
    ],
)
def test_disallowed_boundary_never_reaches_t10(method, path, headers):
    client, calls, proofs = setup()
    assert client.request(method, path, headers=headers).status_code >= 400
    assert not calls and not proofs


def test_real_native_denial_is_preserved_not_replaced_with_a_plan():
    client, calls, _ = setup(
        handler=lambda _: httpx.Response(
            403,
            json={"detail": {"code": "operator_not_allowed"}},
            headers={"Set-Cookie": "secret=hidden"},
        )
    )
    response = client.get(PATH)
    assert response.status_code == 403
    assert response.json() == {"detail": {"code": "operator_not_allowed"}}
    assert "set-cookie" not in response.headers
    assert "test-proof" not in response.text
    assert calls[0].headers["host"] == "127.0.0.1:18131"


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "https://elsewhere.example"}),
        httpx.Response(200, text="not native JSON"),
        httpx.Response(
            200, content=b"x" * 131073, headers={"Content-Type": "application/json"}
        ),
    ],
)
def test_unconfirmed_or_redirected_response_is_not_success(response):
    client, calls, _ = setup(handler=lambda _: response)
    assert client.get(PATH).status_code == 502
    assert len(calls) == 1


@pytest.mark.parametrize(
    "changes",
    [
        {"plan_id": "other-plan"},
        {"expires_at": NOW},
        {"expires_at": NOW + timedelta(hours=2)},
        {"routes": frozenset({"failback"})},
        {"approval_kinds": frozenset({"cutover"})},
    ],
)
def test_approval_outside_window_never_issues_proof(changes):
    client, calls, proofs = setup(operation_window=lambda: window(**changes))
    response = client.post(
        PATH + "/approvals", json={"approval_kind": "change"}, headers=POST
    )
    assert response.status_code == 403
    assert not calls and not proofs


def test_coordinated_request_keeps_native_binding_and_key_without_inventing_authority():
    client, calls, _ = setup(operation_window=lambda: window())
    body = {
        "approval_kind": "failback",
        "plan_version": 12,
        "binding": {"plan_digest": "test-digest", "cutover_epoch": 3},
    }
    response = client.post(PATH + "/approvals", json=body, headers=POST)
    assert (
        response.status_code == 200
    )  # Fake server response, not qualification of this binding.
    assert len(calls) == 1 and json.loads(calls[0].content) == body
    assert calls[0].headers["idempotency-key"] == POST["Idempotency-Key"]
    assert calls[0].headers["authorization"] == "Bearer test-proof-never-reflected"
    assert "test-proof" not in response.text


def test_window_withdrawal_during_proof_stops_post():
    active = [window()]

    def proof():
        active[0] = None
        return "proof"

    client, calls, _ = setup(operation_window=lambda: active[0], proof=proof)
    assert (
        client.post(
            PATH + "/cutover", json={"approval_id": "existing"}, headers=POST
        ).status_code
        == 403
    )
    assert not calls


def test_session_revoked_during_proof_stops_request():
    active = [True]

    def proof():
        active[0] = False
        return "proof"

    client, calls, _ = setup(authorize=lambda _: active[0], proof=proof)
    assert client.get(PATH).status_code == 403
    assert not calls


def test_post_timeout_is_uncertain_and_never_retried():
    def failure(request):
        raise httpx.ReadTimeout("do not expose request or proof", request=request)

    client, calls, _ = setup(operation_window=lambda: window(), handler=failure)
    response = client.post(
        PATH + "/cutover", json={"approval_id": "existing"}, headers=POST
    )
    assert response.status_code == 503 and len(calls) == 1
    assert response.json()["detail"]["code"] == "native_result_unconfirmed"
    assert "do not expose" not in response.text


def test_sse_replay_preserves_cursor_and_frames():
    data = b'id: plan-test:1\nevent: plan.state.changed\ndata: {"test":true}\n\n'
    client, calls, _ = setup(
        handler=lambda _: httpx.Response(
            200, content=data, headers={"Content-Type": "text/event-stream"}
        )
    )
    response = client.get(
        PATH + "/events?follow=false", headers={"Last-Event-ID": "plan-test:0"}
    )
    assert response.status_code == 200 and response.content == data
    assert calls[0].headers["last-event-id"] == "plan-test:0"
    assert calls[0].url.query == b"follow=false"


def test_stream_revocation_stops_later_frames_and_closes_upstream():
    active, closed = [True], []

    class Frames(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b": first heartbeat\n\n"
            active[0] = False
            yield b": must not reach browser\n\n"

        async def aclose(self):
            closed.append(True)

    client, _, _ = setup(
        authorize=lambda _: active[0],
        handler=lambda _: httpx.Response(
            200, stream=Frames(), headers={"Content-Type": "text/event-stream"}
        ),
    )
    response = client.get(PATH + "/events")
    assert response.content == b": first heartbeat\n\n" and closed


def test_default_status_reports_no_operational_window():
    client, calls, proofs = setup()
    result = client.get("/__native/status").json()
    assert result["window"] is None and result["native_authorization_required"] is True
    assert not calls and not proofs
