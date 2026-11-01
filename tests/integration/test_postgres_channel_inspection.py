"""Real redacted subscription inspection; never grants catalog credential reads."""

from uuid import uuid4

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo
import pytest

from replication_support import logical_pair
from sova.domain.contracts import ContractError

pytestmark = pytest.mark.postgres


@pytest.fixture
def pair(postgres_database):
    def setup(conn, role):
        conn.execute(
            "CREATE TABLE public.messages(id bigint PRIMARY KEY,body text NOT NULL)"
        )

    with logical_pair(
        postgres_database[0],
        tables=(("public", "messages"),),
        source_setup=setup,
        target_setup=setup,
    ) as result:
        result.barrier(
            boundary="00000000-0000-4000-8000-000000000001", plan="a" * 64, epoch=1
        )
        yield result


def observe(pair):
    return pair.observe(
        boundary="00000000-0000-4000-8000-000000000001", plan="a" * 64, epoch=1
    )


def test_bound_channel_uses_credential_free_inspection_port(pair):
    result = observe(pair)
    assert result["publisher_configuration_bound"] and not result["cutover_authorized"]
    assert "publisher-configuration-binding" not in result["not_verified"]
    with psycopg.connect(
        pair.dsns["target"], user=pair.roles["reader_target"]
    ) as reader:
        safe = reader.execute(
            "SELECT * FROM sova_replication_inspection.channel_state()"
        ).fetchall()
        assert len(safe) == 1 and len(safe[0][5]) == 64
    with psycopg.connect(
        pair.dsns["target"], user=pair.roles["reader_target"]
    ) as reader:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            reader.execute("SELECT subconninfo FROM pg_catalog.pg_subscription")
    with psycopg.connect(
        pair.dsns["target"], user=pair.roles["reader_source"]
    ) as wrong:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            wrong.execute("SELECT * FROM sova_replication_inspection.channel_state()")


def test_publisher_connection_change_rejected_even_with_same_publication_and_barrier(
    pair,
):
    changed = make_conninfo(
        pair.dsns["source"],
        user=pair.roles["replicator"],
        application_name="unapproved-change",
    )
    with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
        owner.execute(
            sql.SQL("ALTER SUBSCRIPTION {} CONNECTION {}").format(
                sql.Identifier(pair.registration.subscription), sql.Literal(changed)
            )
        )
    with pytest.raises(ContractError, match="configuration"):
        observe(pair)


def test_immediate_inspector_binding_revocation_prevents_observation(pair):
    with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
        owner.execute(
            "UPDATE sova_replication_inspection.reader_bindings SET valid_until=clock_timestamp()-interval '1 second'"
        )
    with pytest.raises(ContractError, match="binding"):
        observe(pair)


@pytest.mark.parametrize("change", ["owner", "definition"])
def test_inspector_owner_or_definition_change_is_not_trusted(pair, change):
    with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
        if change == "owner":
            owner.execute(
                sql.SQL(
                    "ALTER FUNCTION sova_replication_inspection.channel_state() OWNER TO {}"
                ).format(sql.Identifier(pair.roles["source_app"]))
            )
        else:
            owner.execute(
                "ALTER FUNCTION sova_replication_inspection.channel_state() SECURITY INVOKER"
            )
    with pytest.raises(ContractError, match="inspector"):
        observe(pair)


def test_observer_cannot_inherit_nonprivileged_function_owner_role(pair):
    from dataclasses import replace

    owner_role = "inspection_owner_" + uuid4().hex
    original = pair.registration
    with psycopg.connect(pair.dsns["target"], autocommit=True) as admin:
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(owner_role))
        )
        admin.execute(
            sql.SQL(
                "ALTER FUNCTION sova_replication_inspection.channel_state() OWNER TO {}"
            ).format(sql.Identifier(owner_role))
        )
        admin.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(owner_role), sql.Identifier(pair.roles["reader_target"])
            )
        )
    try:
        pair.registration = replace(
            original, inspector=replace(original.inspector, owner_role=owner_role)
        )
        with pytest.raises(ContractError, match="owner role"):
            observe(pair)
    finally:
        pair.registration = original
        with psycopg.connect(pair.dsns["target"], autocommit=True) as admin:
            admin.execute(
                sql.SQL(
                    "ALTER FUNCTION sova_replication_inspection.channel_state() OWNER TO {}"
                ).format(sql.Identifier(original.inspector.owner_role))
            )
            admin.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(owner_role),
                    sql.Identifier(pair.roles["reader_target"]),
                )
            )
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(owner_role)))


def test_late_write_grant_on_inspection_binding_is_rejected(pair):
    with psycopg.connect(pair.dsns["target"], autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "GRANT UPDATE ON sova_replication_inspection.reader_bindings TO {}"
            ).format(sql.Identifier(pair.roles["reader_target"]))
        )
    with pytest.raises(ContractError, match="SELECT-only"):
        observe(pair)
