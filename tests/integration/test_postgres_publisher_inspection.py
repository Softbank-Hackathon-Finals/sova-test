"""Actual TLS logical replication; scoped projection, not RDS qualification."""

from dataclasses import replace

import psycopg
from psycopg import sql
import pytest

from replication_support import logical_pair
from sova.domain.contracts import ContractError

pytestmark = pytest.mark.postgres
BOUNDARY = "00000000-0000-4000-8000-000000000003"


@pytest.fixture
def pair(postgres_database, second_postgres_database):
    def setup(conn, role):
        conn.execute(
            "CREATE TABLE public.messages(id bigint PRIMARY KEY,body text NOT NULL)"
        )

    with logical_pair(
        postgres_database[0],
        target_base=second_postgres_database,
        tables=(("public", "messages"),),
        source_setup=setup,
        target_setup=setup,
        tls_replication=True,
    ) as result:
        result.barrier(boundary=BOUNDARY, plan="a" * 64, epoch=1)
        yield result


def observe(pair):
    return pair.observe(boundary=BOUNDARY, plan="a" * 64, epoch=1)


def test_live_tls_peer_and_slot_are_observed_without_cluster_stats_grant(pair):
    report = observe(pair)
    assert report["publisher_slot_bound"] and report["publisher_configuration_bound"]
    transport = report["publisher_transport_observation"]
    assert (
        transport["encrypted_channel_observed"]
        and len(transport["observation_digest"]) == 64
    )
    assert transport["tls_version"] in {"TLSv1.2", "TLSv1.3"}
    assert not transport["client_certificate_identity_verified"]
    assert not transport["authentication_method_verified"]
    assert not report["cutover_authorized"]
    with psycopg.connect(
        pair.dsns["source"], user=pair.roles["reader_source"]
    ) as reader:
        assert reader.execute(
            "SELECT pg_has_role(current_user,'pg_read_all_stats','MEMBER')"
        ).fetchone() == (False,)
        rows = reader.execute(
            "SELECT * FROM sova_publisher_inspection.channel_transport()"
        ).fetchall()
        assert len(rows) == 1 and rows[0][8] is True
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute("SELECT * FROM sova_publisher_inspection.reader_bindings")
    with psycopg.connect(
        pair.dsns["source"], user=pair.roles["reader_target"]
    ) as other:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            other.execute("SELECT * FROM sova_publisher_inspection.channel_transport()")


@pytest.mark.parametrize(
    "change", ["peer", "role", "application", "definition", "binding", "expiry"]
)
def test_runtime_identity_or_inspector_changes_cannot_reuse_old_observation(
    pair, change
):
    current = pair.registration
    inspector = current.publisher_inspector
    if change == "peer":
        pair.registration = replace(
            current,
            publisher_inspector=replace(
                inspector, expected_peer_addresses=("192.0.2.1",)
            ),
        )
    elif change == "role":
        pair.registration = replace(
            current,
            publisher_inspector=replace(
                inspector, replicator_oid=inspector.replicator_oid + 1
            ),
        )
    elif change == "application":
        pair.registration = replace(
            current,
            publisher_inspector=replace(inspector, application_name="different"),
        )
    else:
        with psycopg.connect(pair.dsns["source"], autocommit=True) as owner:
            if change == "definition":
                owner.execute(
                    "ALTER FUNCTION sova_publisher_inspection.channel_transport() SECURITY INVOKER"
                )
            if change == "binding":
                owner.execute(
                    "UPDATE sova_publisher_inspection.reader_bindings SET application_name='unregistered'"
                )
            if change == "expiry":
                owner.execute(
                    "UPDATE sova_publisher_inspection.reader_bindings SET valid_until=clock_timestamp()-interval '1 second'"
                )
    with pytest.raises(ContractError):
        observe(pair)


def test_subscriber_cannot_point_at_another_slot_with_same_publisher_config(pair):
    with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
        owner.execute(
            sql.SQL("ALTER SUBSCRIPTION {} DISABLE").format(
                sql.Identifier(pair.registration.subscription)
            )
        )
        owner.execute(
            sql.SQL("ALTER SUBSCRIPTION {} SET(slot_name='unapproved_slot')").format(
                sql.Identifier(pair.registration.subscription)
            )
        )
        owner.execute(
            sql.SQL("ALTER SUBSCRIPTION {} ENABLE").format(
                sql.Identifier(pair.registration.subscription)
            )
        )
    with pytest.raises(ContractError, match="slot binding"):
        observe(pair)


def test_replication_rejects_wrong_server_ca_instead_of_downgrading(pair, tmp_path):
    from psycopg.conninfo import make_conninfo
    from test_otel_collector_runtime import certificates

    certificates(tmp_path / "untrusted")
    config = make_conninfo(
        pair.publisher_connection("source", pair.registration.subscription),
        sslrootcert=str(tmp_path / "untrusted/ca.pem"),
        connect_timeout=2,
    )
    with pytest.raises(psycopg.OperationalError):
        psycopg.connect(config)
    assert observe(pair)["publisher_transport_observation"][
        "encrypted_channel_observed"
    ]


def test_publisher_observer_cannot_inherit_inspector_owner(pair):
    # Existing owner is the test cluster admin; such membership is rejected even NOINHERIT.
    role = pair.roles["reader_source"]
    with psycopg.connect(pair.dsns["source"], autocommit=True) as owner:
        admin = owner.execute("SELECT current_user").fetchone()[0]
        owner.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(admin), sql.Identifier(role)
            )
        )
    try:
        with pytest.raises(ContractError):
            observe(pair)
    finally:
        with psycopg.connect(pair.dsns["source"], autocommit=True) as owner:
            owner.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(admin), sql.Identifier(role)
                )
            )
