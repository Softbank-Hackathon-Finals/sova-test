"""Controlled, actual PG data + app transition, not AWS/on-prem/HA qualification.

One known app writer is fenced at the DB boundary. No arbitrary writer inventory,
stable public ingress or continuous WebSocket session is claimed. Reverse recovery
uses explicit fixture-owner SQL, not a product migration worker.
"""

from contextlib import ExitStack
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4
import time

import psycopg
from psycopg import sql
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("opentelemetry.sdk")
from fastapi.testclient import TestClient
from examples.consultation.operator import prepare, grant_application, set_writes
from examples.consultation.storage import ConsultationStore
from examples.consultation.service import create_app
from examples.consultation.objects import LocalObjects
from examples.consultation.telemetry import WorkloadTelemetry
from replication_support import logical_pair
from sova.adapters.postgres_sequences import (
    PostgresSequenceObserver,
    compare_sequence_observations,
)
from sova.domain.data_manifest import compare_manifests

pytestmark = pytest.mark.postgres
TABLES = tuple(
    ("consultation", name)
    for name in (
        "users",
        "rooms",
        "invitations",
        "sessions",
        "messages",
        "attachments",
        "audit",
    )
)


@pytest.mark.parametrize(
    "separate_cluster", [False, True], ids=["same-cluster", "independent-clusters"]
)
def test_committed_messages_files_and_sessions_survive_controlled_database_transition(
    postgres_database, tmp_path, request, separate_cluster
):
    base, _ = postgres_database
    target_base = (
        request.getfixturevalue("second_postgres_database")
        if separate_cluster
        else None
    )

    def source_setup(conn, role):
        return prepare(
            conn,
            schema="consultation",
            app_role=role,
            valid_until=datetime.now(UTC) + timedelta(minutes=5),
        )

    def target_setup(conn, role):
        conn.execute(
            (Path(__file__).parents[2] / "examples/consultation/schema.sql").read_text()
        )
        grant_application(conn, schema="consultation", app_role=role)
        # Instance-local control is deliberately not part of the data publication.
        set_writes(conn, schema="consultation", enabled=False)

    with (
        logical_pair(
            base,
            tables=TABLES,
            source_setup=source_setup,
            target_setup=target_setup,
            target_base=target_base,
            tls_replication=separate_cluster,
        ) as pair,
        ExitStack() as stack,
    ):
        if separate_cluster:
            assert (
                pair.registration.source.system_identifier
                != pair.registration.target.system_identifier
            )
        clients = {}
        stores = {}
        objects = {}
        for side, port in (("source", 8794), ("target", 8795)):
            store = ConsultationStore(
                lambda side=side: psycopg.connect(
                    pair.dsns[side], user=pair.roles[side + "_app"]
                ),
                environment=side,
            )
            stores[side] = store
            objects[side] = LocalObjects(tmp_path / side)
            origin = f"http://127.0.0.1:{port}"
            telemetry = WorkloadTelemetry(
                application_id="consultation",
                environment=side,
                deployment_revision="a" * 64,
            )
            clients[side] = stack.enter_context(
                TestClient(
                    create_app(
                        store, origin=origin, objects=objects[side], telemetry=telemetry
                    ),
                    base_url=origin,
                    headers={"Origin": origin},
                )
            )
        source, target = clients["source"], clients["target"]
        assert (
            target.get("/health").status_code == 503
        )  # NOLOGIN target never accepts writes during copy.
        invite = pair.users[0]
        room = invite["room_id"]
        login = source.post("/api/session", json={"invite": invite["invite"]})
        assert login.status_code == 200
        proof = login.json()["csrf"]
        source.headers["X-Consultation-CSRF"] = proof
        first = {
            "client_request_id": str(uuid4()),
            "content": "합성 상담: 이전 전 확정 메시지",
        }
        committed = source.post(f"/api/rooms/{room}/messages", json=first)
        assert committed.status_code == 200
        attachment = str(uuid4())
        file_data = b"synthetic customer attachment"
        assert (
            source.put(
                f"/api/rooms/{room}/attachments/{attachment}",
                content=file_data,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Filename": "synthetic.txt",
                },
            ).status_code
            == 200
        )
        # Drain app transactions, then fence its actual login and pre-existing DB session.
        existing = psycopg.connect(pair.dsns["source"], user=pair.roles["source_app"])
        existing_pid = existing.info.backend_pid
        with psycopg.connect(pair.dsns["source"], autocommit=True) as owner:
            set_writes(owner, schema="consultation", enabled=False)
        pending = {
            "client_request_id": str(uuid4()),
            "content": "합성 상담: 대기 후 대상에 한 번만 저장",
        }
        blocked = source.post(f"/api/rooms/{room}/messages", json=pending)
        assert blocked.status_code == 503 and blocked.headers["Retry-After"] == "2"
        with psycopg.connect(pair.dsns["source"], autocommit=True) as owner:
            owner.execute(
                sql.SQL("ALTER ROLE {} NOLOGIN").format(
                    sql.Identifier(pair.roles["source_app"])
                )
            )
            owner.execute(
                # Signal delivery alone does not mean the backend has exited.
                # Wait at most five seconds before checking the writer fence.
                "SELECT pg_terminate_backend(pid,5000) FROM pg_catalog.pg_stat_activity WHERE datname=current_database() AND usename=%s AND pid<>pg_backend_pid()",
                (pair.roles["source_app"],),
            )
            assert (
                owner.execute(
                    "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE pid=%s",
                    (existing_pid,),
                ).fetchone()[0]
                == 0
            )
        try:
            with pytest.raises(psycopg.OperationalError):
                existing.execute("INSERT INTO consultation.messages VALUES(DEFAULT)")
        finally:
            existing.close()
        assert (
            source.post(f"/api/rooms/{room}/messages", json=pending).status_code == 503
        )
        boundary, plan = str(uuid4()), "b" * 64
        pair.barrier(boundary=boundary, plan=plan, epoch=2)
        report = pair.observe(boundary=boundary, plan=plan, epoch=2)
        assert (
            report["barrier_arrived"]
            and report["publisher_configuration_bound"]
            and not report["cutover_authorized"]
        )
        if separate_cluster:
            assert report["publisher_slot_bound"]
            assert report["publisher_transport_observation"][
                "encrypted_channel_observed"
            ]
        # Every declared data table is compared; matching message counts alone is insufficient.
        for table in TABLES:
            comparison = compare_manifests(
                pair.manifest("source", table, boundary),
                pair.manifest("target", table, boundary),
                now=datetime.now(UTC),
            )
            assert comparison["content_equal"] and not comparison["cutover_authorized"]
        # File bytes are a separate dependency, not covered by DB replication.
        objects["target"].put(attachment, objects["source"].get(attachment))
        assert objects["target"].get(attachment) == file_data
        for table in ("messages", "audit"):
            observations = []
            for side in ("source", "target"):
                registration, connect = pair.reader(side, ("consultation", table))
                observations.append(
                    PostgresSequenceObserver(
                        registration,
                        connect=connect,
                        authorize=lambda *args: None,
                        authenticate_registration=lambda _: None,
                        clock=lambda: datetime.now(UTC),
                        monotonic=time.monotonic,
                    ).observe("operator")
                )
            assert not compare_sequence_observations(
                *observations, now=datetime.now(UTC)
            )["observed_collision_safe"]
            with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
                sequence = "consultation." + (
                    "messages_message_id_seq"
                    if table == "messages"
                    else "audit_event_id_seq"
                )
                owner.execute(
                    "SELECT setval(%s::regclass,%s,false)",
                    (sequence, observations[0].next_value),
                )
            reg, connect = pair.reader("target", ("consultation", table))
            final = PostgresSequenceObserver(
                reg,
                connect=connect,
                authorize=lambda *args: None,
                authenticate_registration=lambda _: None,
                clock=lambda: datetime.now(UTC),
                monotonic=time.monotonic,
            ).observe("operator")
            assert compare_sequence_observations(
                observations[0], final, now=datetime.now(UTC)
            )["observed_collision_safe"]
        pair.pause_subscription()
        # Preserve the rollback stream before opening the target writer; creating
        # this slot after new target writes could silently omit committed data.
        reverse = pair.prepare_reverse()
        with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
            owner.execute(
                sql.SQL("ALTER ROLE {} LOGIN").format(
                    sql.Identifier(pair.roles["target_app"])
                )
            )
            set_writes(owner, schema="consultation", enabled=True)
        target.cookies.update(source.cookies)
        target.headers["X-Consultation-CSRF"] = proof
        assert target.get(f"/api/rooms/{room}/messages").json() == [committed.json()]
        assert (
            target.get(f"/api/rooms/{room}/attachments/{attachment}").content
            == file_data
        )
        written = target.post(f"/api/rooms/{room}/messages", json=pending)
        assert written.status_code == 200 and written.json()["environment"] == "target"
        assert (
            written.json()["sequence"] == "2"
            and written.json()["id"] != committed.json()["id"]
        )
        assert (
            target.post(f"/api/rooms/{room}/messages", json=pending).json()
            == written.json()
        )
        with psycopg.connect(pair.dsns["target"]) as owner:
            assert (
                owner.execute("SELECT count(*) FROM consultation.messages").fetchone()[
                    0
                ]
                == 2
            )
        assert source.get("/health").status_code == 503
        # Newly created target file/data must survive recovery too.
        new_attachment = str(uuid4())
        new_file = b"synthetic file created after target activation"
        assert (
            target.put(
                f"/api/rooms/{room}/attachments/{new_attachment}",
                content=new_file,
                headers={
                    "Content-Type": "application/octet-stream",
                    "X-Filename": "target.txt",
                },
            ).status_code
            == 200
        )
        with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
            set_writes(owner, schema="consultation", enabled=False)
            owner.execute(
                sql.SQL("ALTER ROLE {} NOLOGIN").format(
                    sql.Identifier(pair.roles["target_app"])
                )
            )
            owner.execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=current_database() AND usename=%s AND pid<>pg_backend_pid()",
                (pair.roles["target_app"],),
            )
        assert (
            target.post(
                f"/api/rooms/{room}/messages",
                json={"client_request_id": str(uuid4()), "content": "must not write"},
            ).status_code
            == 503
        )
        reverse_boundary = str(uuid4())
        reverse.barrier(boundary=reverse_boundary, plan="c" * 64, epoch=4)
        report = reverse.observe(boundary=reverse_boundary, plan="c" * 64, epoch=4)
        assert report["barrier_arrived"] and report["publisher_configuration_bound"]
        if separate_cluster:
            assert report["publisher_transport_observation"][
                "encrypted_channel_observed"
            ]
        for table in TABLES:
            comparison = compare_manifests(
                reverse.manifest("source", table, reverse_boundary),
                reverse.manifest("target", table, reverse_boundary),
                now=datetime.now(UTC),
            )
            assert comparison["content_equal"]
        objects["source"].put(new_attachment, objects["target"].get(new_attachment))
        for table in ("messages", "audit"):
            source_reg, source_connect = reverse.reader(
                "source", ("consultation", table)
            )
            target_reg, target_connect = reverse.reader(
                "target", ("consultation", table)
            )

            def sequence(reg, connect):
                return PostgresSequenceObserver(
                    reg,
                    connect=connect,
                    authorize=lambda *_: None,
                    authenticate_registration=lambda _: None,
                    clock=lambda: datetime.now(UTC),
                    monotonic=time.monotonic,
                ).observe("operator")

            current = sequence(source_reg, source_connect)
            sequence_name = "consultation." + (
                "messages_message_id_seq"
                if table == "messages"
                else "audit_event_id_seq"
            )
            with psycopg.connect(pair.dsns["source"], autocommit=True) as owner:
                owner.execute(
                    "SELECT setval(%s::regclass,%s,false)",
                    (sequence_name, current.next_value),
                )
            assert compare_sequence_observations(
                current, sequence(target_reg, target_connect), now=datetime.now(UTC)
            )["observed_collision_safe"]
        reverse.pause_subscription()
        with psycopg.connect(pair.dsns["source"], autocommit=True) as owner:
            owner.execute(
                sql.SQL("ALTER ROLE {} LOGIN").format(
                    sql.Identifier(pair.roles["source_app"])
                )
            )
            set_writes(owner, schema="consultation", enabled=True)
        recovered = source.get(f"/api/rooms/{room}/messages")
        assert recovered.status_code == 200
        assert recovered.json() == [committed.json(), written.json()]
        assert (
            source.get(f"/api/rooms/{room}/attachments/{new_attachment}").content
            == new_file
        )
        after_recovery = source.post(
            f"/api/rooms/{room}/messages",
            json={
                "client_request_id": str(uuid4()),
                "content": "committed after reverse recovery",
            },
        )
        assert after_recovery.status_code == 200
        assert after_recovery.json()["sequence"] == "3"
        assert int(after_recovery.json()["id"]) > int(written.json()["id"])
        assert target.get("/health").status_code == 503
