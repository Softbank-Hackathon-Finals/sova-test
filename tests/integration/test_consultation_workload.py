"""Actual PostgreSQL and ASGI/WebSocket workload tests; synthetic customer data."""

from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import ExitStack
from datetime import timedelta
import hashlib
from threading import Event
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest

pytest.importorskip(
    "fastapi", reason="install the demo extra for reference-workload tests"
)
pytest.importorskip("opentelemetry.sdk")
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from examples.consultation.operator import prepare, set_writes
from examples.consultation.objects import LocalObjects
from examples.consultation.service import create_app
from examples.consultation.storage import ConsultationStore
from examples.consultation.telemetry import WorkloadTelemetry

pytestmark = pytest.mark.postgres
ORIGIN = "http://127.0.0.1:8794"


@pytest.fixture
def consultation(postgres_database, now, tmp_path):
    dsn, _ = postgres_database
    schema, role = "chat_" + uuid4().hex, "chat_role_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT"
            ).format(sql.Identifier(role))
        )
        users = prepare(
            admin, schema=schema, app_role=role, valid_until=now + timedelta(minutes=10)
        )

    def connect():
        return psycopg.connect(
            dsn, user=role, options="-c statement_timeout=5000 -c lock_timeout=1000"
        )

    store = ConsultationStore(connect, environment="source", schema=schema)
    objects = LocalObjects(tmp_path / "objects")
    telemetry = WorkloadTelemetry(
        application_id="consultation-test",
        environment="source",
        deployment_revision="a" * 64,
    )
    app = create_app(store, origin=ORIGIN, objects=objects, telemetry=telemetry)
    with ExitStack() as stack:
        clients = [
            stack.enter_context(
                TestClient(app, base_url=ORIGIN, headers={"Origin": ORIGIN})
            )
            for _ in users
        ]
        proofs = []
        for client, user in zip(clients, users, strict=True):
            response = client.post("/api/session", json={"invite": user["invite"]})
            assert response.status_code == 200, response.text
            proof = response.json()["csrf"]
            proofs.append(proof)
            client.headers["X-Consultation-CSRF"] = proof
        try:
            yield {
                "clients": clients,
                "users": users,
                "store": store,
                "objects": objects,
                "telemetry": telemetry,
                "dsn": dsn,
                "schema": schema,
                "role": role,
                "proofs": proofs,
            }
        finally:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(
                    sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role))
                )
                admin.execute(
                    sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
                )
                admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))


def test_customer_room_and_attachment_access_isolation(consultation):
    a, b, counselor = consultation["clients"]
    room = consultation["users"][0]["room_id"]
    assert (
        len(a.get("/api/rooms").json()) == 1
        and len(counselor.get("/api/rooms").json()) == 2
    )
    assert b.get(f"/api/rooms/{room}/messages").status_code == 403
    attachment = str(uuid4())
    content = b"synthetic confidential file"
    result = a.put(
        f"/api/rooms/{room}/attachments/{attachment}",
        content=content,
        headers={
            "Content-Type": "application/octet-stream",
            "X-Filename": "statement.txt",
        },
    )
    assert (
        result.status_code == 200
        and result.json()["content_digest"] == hashlib.sha256(content).hexdigest()
    )
    assert a.get(f"/api/rooms/{room}/attachments/{attachment}").content == content
    assert b.get(f"/api/rooms/{room}/attachments/{attachment}").status_code == 403
    assert (
        counselor.get(f"/api/rooms/{room}/attachments/{attachment}").content == content
    )


def test_commit_ack_and_retry_do_not_duplicate_message_or_room_sequence(consultation):
    a = consultation["clients"][0]
    room = consultation["users"][0]["room_id"]
    body = {"client_request_id": str(uuid4()), "content": "합성 상담 메시지"}
    first = a.post(f"/api/rooms/{room}/messages", json=body)
    again = a.post(f"/api/rooms/{room}/messages", json=body)
    assert first.status_code == 200 and first.json() == again.json()
    assert first.json()["sequence"] == "1"
    changed = a.post(f"/api/rooms/{room}/messages", json={**body, "content": "changed"})
    assert changed.status_code == 409
    assert len(a.get(f"/api/rooms/{room}/messages").json()) == 1
    with psycopg.connect(consultation["dsn"]) as admin:
        assert (
            admin.execute(
                sql.SQL(
                    "SELECT count(*) FROM {}.audit WHERE event='message_committed'"
                ).format(sql.Identifier(consultation["schema"]))
            ).fetchone()[0]
            == 1
        )


def test_concurrent_retries_share_one_committed_row(consultation):
    c = consultation
    store = c["store"]
    actor = store.authenticate(
        c["clients"][0].cookies["consultation_session"], c["proofs"][0]
    )
    room = c["users"][0]["room_id"]
    request_id = str(uuid4())
    with ThreadPoolExecutor(max_workers=4) as pool:
        rows = list(
            pool.map(
                lambda _: store.send(actor, room, request_id, "same request"), range(4)
            )
        )
    assert len({r["id"] for r in rows}) == 1 and {r["sequence"] for r in rows} == {"1"}


def test_pause_denies_new_writes_and_resume_preserves_request_identity(consultation):
    c = consultation
    a = c["clients"][0]
    room = c["users"][0]["room_id"]
    with psycopg.connect(c["dsn"]) as admin:
        set_writes(admin, schema=c["schema"], enabled=False)
    body = {"client_request_id": str(uuid4()), "content": "retry after pause"}
    result = a.post(f"/api/rooms/{room}/messages", json=body)
    assert result.status_code == 503 and result.headers["retry-after"] == "2"
    assert a.get(f"/api/rooms/{room}/messages").json() == []
    with psycopg.connect(c["dsn"]) as admin:
        set_writes(admin, schema=c["schema"], enabled=True)
    result = a.post(f"/api/rooms/{room}/messages", json=body)
    assert result.status_code == 200 and result.json()["writer_epoch"] == "3"


def test_pause_covers_session_mutations_too(consultation, now):
    from examples.consultation.operator import invite

    c = consultation
    with psycopg.connect(c["dsn"]) as admin:
        code = invite(
            admin, c["schema"], c["users"][0]["user_id"], now + timedelta(minutes=5)
        )
        set_writes(admin, schema=c["schema"], enabled=False)
    a = c["clients"][0]
    assert a.post("/api/session", json={"invite": code}).status_code == 503
    assert a.post("/api/logout").status_code == 503
    # Failed login must not consume the one-time invite; failed logout retains session.
    assert a.get("/api/rooms").status_code == 200
    with psycopg.connect(c["dsn"]) as admin:
        set_writes(admin, schema=c["schema"], enabled=True)
    assert a.post("/api/session", json={"invite": code}).status_code == 200


def test_pause_drains_attachment_storage_and_metadata_commit(consultation):
    c = consultation
    store = c["store"]
    actor = store.authenticate(
        c["clients"][0].cookies["consultation_session"], c["proofs"][0]
    )
    room, attachment = c["users"][0]["room_id"], str(uuid4())
    storing, release, pausing = Event(), Event(), Event()

    def blocked_put(key, content):
        storing.set()
        assert release.wait(5)
        c["objects"].put(key, content)

    def pause():
        with psycopg.connect(c["dsn"], autocommit=True) as admin:
            admin.execute("SET lock_timeout='3s'")
            pausing.set()
            return set_writes(admin, schema=c["schema"], enabled=False)

    with ThreadPoolExecutor(max_workers=2) as pool:
        upload = pool.submit(
            store.upload_attachment,
            actor,
            room,
            attachment,
            "file.txt",
            b"drained data",
            blocked_put,
        )
        try:
            assert storing.wait(2)
            paused = pool.submit(pause)
            assert pausing.wait(2)
            with pytest.raises(FutureTimeout):
                paused.result(timeout=0.15)
        finally:
            release.set()
        assert upload.result(timeout=5)["id"] == attachment
        assert paused.result(timeout=5) >= 2
    assert store.attachment(actor, room, attachment)["byte_length"] == len(
        b"drained data"
    )
    assert c["objects"].get(attachment) == b"drained data"
    called = []
    from examples.consultation.storage import WritesPaused

    with pytest.raises(WritesPaused):
        store.upload_attachment(
            actor, room, str(uuid4()), "blocked", b"no", lambda *_: called.append(True)
        )
    assert called == []


def test_storage_response_loss_leaves_no_ready_metadata_and_retry_converges(
    consultation,
):
    c = consultation
    store = c["store"]
    actor = store.authenticate(
        c["clients"][0].cookies["consultation_session"], c["proofs"][0]
    )
    room, attachment = c["users"][0]["room_id"], str(uuid4())
    content = b"immutable file"

    def lost_response(key, data):
        c["objects"].put(key, data)
        raise ConnectionError("controlled storage response loss")

    with pytest.raises(ConnectionError):
        store.upload_attachment(actor, room, attachment, "file", content, lost_response)
    with psycopg.connect(c["dsn"]) as admin:
        assert (
            admin.execute(
                sql.SQL(
                    "SELECT count(*) FROM {}.attachments WHERE attachment_id=%s"
                ).format(sql.Identifier(c["schema"])),
                (attachment,),
            ).fetchone()[0]
            == 0
        )
    store.upload_attachment(actor, room, attachment, "file", content, c["objects"].put)
    store.upload_attachment(actor, room, attachment, "file", content, c["objects"].put)
    assert (
        store.attachment(actor, room, attachment)["content_digest"]
        == hashlib.sha256(content).hexdigest()
    )
    with psycopg.connect(c["dsn"]) as admin:
        assert (
            admin.execute(
                sql.SQL(
                    "SELECT count(*) FROM {}.audit WHERE request_id=%s AND event='attachment_ready'"
                ).format(sql.Identifier(c["schema"])),
                (attachment,),
            ).fetchone()[0]
            == 1
        )


def test_app_role_cannot_disable_gate_or_rewrite_audit(consultation):
    c = consultation
    with c["store"].connect() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                sql.SQL("UPDATE {}.control SET writes_enabled=true").format(
                    sql.Identifier(c["schema"])
                )
            )
    with c["store"].connect() as app:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            app.execute(
                sql.SQL("DELETE FROM {}.audit").format(sql.Identifier(c["schema"]))
            )


def test_websocket_reconnect_replays_only_messages_after_cursor(consultation):
    c = consultation
    a = c["clients"][0]
    room = c["users"][0]["room_id"]
    for text in ("first", "second"):
        assert (
            a.post(
                f"/api/rooms/{room}/messages",
                json={"client_request_id": str(uuid4()), "content": text},
            ).status_code
            == 200
        )
    with a.websocket_connect(
        f"ws://127.0.0.1:8794/api/rooms/{room}/stream?after=1",
        subprotocols=["consultation", c["proofs"][0]],
    ) as ws:
        data = ws.receive_json()
        assert [m["content"] for m in data["messages"]] == ["second"] and data[
            "cursor"
        ] == "2"


def test_foreign_room_and_cross_origin_websocket_are_denied(consultation):
    c = consultation
    b = c["clients"][1]
    room = c["users"][0]["room_id"]
    with pytest.raises(WebSocketDisconnect) as error:
        with b.websocket_connect(
            f"ws://127.0.0.1:8794/api/rooms/{room}/stream",
            subprotocols=["consultation", c["proofs"][1]],
        ) as ws:
            ws.receive_json()
    assert getattr(error.value, "code", None) == 1008
    a = c["clients"][0]
    with pytest.raises(WebSocketDisconnect) as error:
        with a.websocket_connect(
            f"ws://127.0.0.1:8794/api/rooms/{room}/stream",
            headers={"Origin": "http://attacker.invalid"},
            subprotocols=["consultation", c["proofs"][0]],
        ) as ws:
            ws.receive_json()
    assert getattr(error.value, "code", None) == 1008


def test_real_otel_spans_exclude_customer_content_and_credentials(consultation):
    c = consultation
    a = c["clients"][0]
    room = c["users"][0]["room_id"]
    assert (
        a.post(
            f"/api/rooms/{room}/messages",
            json={
                "client_request_id": str(uuid4()),
                "content": "DO-NOT-EXPORT-PRIVATE-MESSAGE",
            },
        ).status_code
        == 200
    )
    spans = c["telemetry"].buffer.snapshot()["spans"]
    assert any(
        s["attributes"].get("http.route") == "/api/rooms/{room_id}/messages"
        for s in spans
    )
    assert "DO-NOT-EXPORT" not in repr(spans)
    assert c["proofs"][0] not in repr(spans) and c["clients"][0].cookies[
        "consultation_session"
    ] not in repr(spans)


def test_invite_replay_cookie_alone_and_cross_origin_requests_are_denied(consultation):
    c = consultation
    a = c["clients"][0]
    assert (
        a.post("/api/session", json={"invite": c["users"][0]["invite"]}).status_code
        == 403
    )
    proof = a.headers.pop("X-Consultation-CSRF")
    assert a.get("/api/me").status_code == 403
    a.headers["X-Consultation-CSRF"] = proof
    assert (
        a.get("/api/me", headers={"Origin": "http://attacker.invalid"}).status_code
        == 403
    )
    assert (
        a.post(
            "/api/rooms", json={}, headers={"Origin": "http://attacker.invalid"}
        ).status_code
        == 403
    )


def test_ai_gateway_unconfigured_is_not_a_fake_summary(consultation):
    c = consultation
    a, b, counselor = c["clients"]
    room = c["users"][0]["room_id"]
    assert a.post(f"/api/rooms/{room}/summary", json={}).status_code == 403
    response = counselor.post(f"/api/rooms/{room}/summary", json={})
    assert response.status_code == 503 and response.json() == {
        "error": "ai_gateway_unconfigured"
    }


def test_accidental_admin_connection_is_not_accepted_by_the_workload(consultation):
    from examples.consultation.storage import DatabaseBoundary

    store = ConsultationStore(
        lambda: psycopg.connect(consultation["dsn"]),
        environment="misconfigured",
        schema=consultation["schema"],
    )
    with pytest.raises(DatabaseBoundary):
        store.health()


def test_operator_pause_really_waits_for_active_app_transaction_even_with_autocommit(
    consultation,
):
    with consultation["store"].connect() as active:
        consultation["store"].write_gate(active)
        with psycopg.connect(consultation["dsn"], autocommit=True) as operator:
            operator.execute("SET lock_timeout='100ms'")
            with pytest.raises(psycopg.errors.LockNotAvailable):
                set_writes(operator, schema=consultation["schema"], enabled=False)
    with psycopg.connect(consultation["dsn"], autocommit=True) as operator:
        set_writes(operator, schema=consultation["schema"], enabled=False)
    assert consultation["clients"][0].get("/health").json()["writes_enabled"] is False


def test_unicode_filename_and_attachment_retry_preserve_single_audit_event(
    consultation,
):
    from urllib.parse import quote

    client = consultation["clients"][0]
    room = consultation["users"][0]["room_id"]
    attachment = str(uuid4())
    headers = {
        "Content-Type": "application/octet-stream",
        "X-Filename-Encoded": quote("합성 상담 서류.txt", safe=""),
    }
    for _ in range(2):
        assert (
            client.put(
                f"/api/rooms/{room}/attachments/{attachment}",
                content=b"synthetic",
                headers=headers,
            ).status_code
            == 200
        )
    result = client.get(f"/api/rooms/{room}/attachments/{attachment}")
    assert quote("합성 상담 서류.txt", safe="") in result.headers["Content-Disposition"]
    with psycopg.connect(consultation["dsn"]) as owner:
        assert (
            owner.execute(
                sql.SQL(
                    "SELECT count(*) FROM {}.audit WHERE event='attachment_ready'"
                ).format(sql.Identifier(consultation["schema"]))
            ).fetchone()[0]
            == 1
        )


def test_concurrent_cross_room_request_id_reuse_is_a_conflict_not_unknown_failure(
    consultation,
):
    from examples.consultation.storage import Conflict

    store = consultation["store"]
    client = consultation["clients"][0]
    actor = store.authenticate(
        client.cookies.get("consultation_session"), consultation["proofs"][0]
    )
    rooms = [consultation["users"][0]["room_id"], store.create_room(actor)["id"]]
    request_id = str(uuid4())

    def send(room):
        try:
            return store.send(actor, room, request_id, "same synthetic content")
        except Conflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(send, rooms))
    assert (
        sum(isinstance(result, dict) for result in results) == 1
        and results.count("conflict") == 1
    )


def test_large_postgresql_ids_and_websocket_cursor_are_lossless_decimal_strings(
    consultation,
):
    client = consultation["clients"][0]
    room = consultation["users"][0]["room_id"]
    large = 9007199254740992
    with psycopg.connect(consultation["dsn"]) as owner:
        owner.execute(
            sql.SQL("SELECT setval({}::regclass,%s,false)").format(
                sql.Literal(consultation["schema"] + ".messages_message_id_seq")
            ),
            (large,),
        )
        owner.execute(
            sql.SQL("UPDATE {}.rooms SET last_sequence=%s WHERE room_id=%s").format(
                sql.Identifier(consultation["schema"])
            ),
            (large - 1, room),
        )
    records = []
    for text in ("large first", "large second"):
        result = client.post(
            f"/api/rooms/{room}/messages",
            json={"client_request_id": str(uuid4()), "content": text},
        )
        assert result.status_code == 200
        records.append(result.json())
    assert [r["id"] for r in records] == [str(large), str(large + 1)]
    assert [r["sequence"] for r in records] == [str(large), str(large + 1)]
    with client.websocket_connect(
        f"ws://127.0.0.1:8794/api/rooms/{room}/stream?after={large}",
        subprotocols=["consultation", consultation["proofs"][0]],
    ) as ws:
        event = ws.receive_json()
        assert event["cursor"] == str(large + 1) and event["messages"] == [records[1]]
    assert client.get(f"/api/rooms/{room}/messages?after={large}").json() == [
        records[1]
    ]
    assert client.get(f"/api/rooms/{room}/messages?after={2**63}").status_code == 400
