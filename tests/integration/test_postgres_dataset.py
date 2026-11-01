"""Real isolated PostgreSQL snapshots. No cloud/CDC/final cutover claim."""

from dataclasses import replace
from datetime import timedelta
from uuid import uuid4
import time

import psycopg
from psycopg import sql
import pytest

from sova.adapters.postgres_dataset import (
    PostgresDatasetReader,
    PostgresDatasetRegistration,
    table_definition,
)
from sova.domain.contracts import ContractError
from sova.domain.evidence import RevisionSet

pytestmark = pytest.mark.postgres


@pytest.fixture
def dataset(postgres_database, scope, now):
    dsn, _ = postgres_database
    schema, reader = "dataset_" + uuid4().hex, "reader_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT"
            ).format(sql.Identifier(reader))
        )
        admin.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
        admin.execute(
            sql.SQL(
                "CREATE TABLE {}.messages(id bigint PRIMARY KEY,body text NOT NULL,amount numeric(12,2),at timestamptz,payload bytea)"
            ).format(sql.Identifier(schema))
        )
        admin.execute(
            sql.SQL(
                "INSERT INTO {}.messages VALUES (1,'합성 상담 비밀',1.00,'2026-11-01T00:00:00Z',decode('0102','hex')),(2,'reply',2.30,'2026-11-01T09:00:00+09:00',decode('03','hex'))"
            ).format(sql.Identifier(schema))
        )
        admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
                sql.Identifier(schema), sql.Identifier(reader)
            )
        )
        admin.execute(
            sql.SQL("GRANT SELECT ON {}.messages TO {}").format(
                sql.Identifier(schema), sql.Identifier(reader)
            )
        )
        admin.execute(
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO {}"
            ).format(sql.Identifier(reader))
        )
        identity = admin.execute(
            "SELECT current_database(),d.oid,c.system_identifier::text FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_control_system() c WHERE d.datname=current_database()"
        ).fetchone()
        definition = table_definition(admin, schema, "messages")
    registration = PostgresDatasetRegistration(
        scope,
        RevisionSet(*("a" * 64,) * 4),
        "private-dataset-reader-ref",
        *identity,
        reader,
        schema,
        "messages",
        definition["table_oid"],
        definition["schema_digest"],
        definition["columns"],
        definition["primary_key"],
        now - timedelta(seconds=1),
        now + timedelta(minutes=3),
        allow_private_unix_fixture=True,
    )

    def collect(reg=registration, *, autocommit=False, authenticate=lambda _: None):
        return PostgresDatasetReader(
            reg,
            connect=lambda ref: psycopg.connect(
                dsn, user=reader, autocommit=autocommit
            ),
            authorize=lambda actor, current_scope, action: None,
            authenticate_registration=authenticate,
            clock=lambda: now,
            monotonic=time.monotonic,
        ).snapshot("operator", boundary_id="snapshot-label-not-final-barrier")

    try:
        yield registration, collect, dsn
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(
                sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(reader))
            )
            admin.execute(
                sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(schema))
            )
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(reader)))


def test_reads_actual_rows_but_never_claims_final_barrier_or_cutover(dataset):
    _, collect, _ = dataset
    result = collect()
    assert result["manifest"].row_count == 2
    assert not result["final_boundary_verified"] and not result["cutover_authorized"]
    assert "합성 상담" not in repr(result)


def test_same_count_data_corruption_is_detected_by_actual_snapshot(dataset):
    r, collect, dsn = dataset
    before = collect()["manifest"]
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("UPDATE {}.messages SET body='corrupted' WHERE id=2").format(
                sql.Identifier(r.schema_name)
            )
        )
    after = collect()["manifest"]
    assert (
        before.row_count == after.row_count and before.keys_digest == after.keys_digest
    )
    assert before.content_digest != after.content_digest


@pytest.mark.parametrize(
    "field,value",
    [
        ("system_identifier", "1"),
        ("database_oid", 1),
        ("table_oid", 1),
        ("database_name", "other"),
        ("reader_role", "other"),
        ("schema_digest", "b" * 64),
    ],
)
def test_registered_resource_identity_drift_is_rejected(dataset, field, value):
    r, collect, _ = dataset
    with pytest.raises(ContractError):
        collect(replace(r, **{field: value}))


def test_autocommit_connection_cannot_masquerade_as_consistent_snapshot(dataset):
    _, collect, _ = dataset
    with pytest.raises(ContractError, match="non-autocommit"):
        collect(autocommit=True)


def test_write_capable_reader_is_rejected(dataset):
    r, collect, dsn = dataset
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("GRANT UPDATE ON {}.messages TO {}").format(
                sql.Identifier(r.schema_name), sql.Identifier(r.reader_role)
            )
        )
    with pytest.raises(ContractError, match="SELECT-only"):
        collect()


def test_reader_privilege_escalation_is_rejected(dataset):
    r, collect, dsn = dataset
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("ALTER ROLE {} CREATEDB").format(sql.Identifier(r.reader_role))
        )
    with pytest.raises(ContractError, match="Privileged"):
        collect()


def test_partial_rls_snapshot_is_not_a_complete_data_manifest(dataset):
    r, collect, dsn = dataset
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("ALTER TABLE {}.messages ENABLE ROW LEVEL SECURITY").format(
                sql.Identifier(r.schema_name)
            )
        )
        definition = table_definition(admin, r.schema_name, "messages")
    with pytest.raises(ContractError, match="RLS-filtered"):
        collect(replace(r, schema_digest=definition["schema_digest"]))


def test_revocation_and_capacity_prevent_snapshot_result(dataset):
    r, collect, _ = dataset
    with pytest.raises(ContractError, match="capacity"):
        collect(replace(r, maximum_rows=1))

    def deny(_):
        raise ContractError("registration revoked")

    with pytest.raises(ContractError, match="revoked"):
        collect(authenticate=deny)


def test_table_name_is_not_an_executable_sql_fragment(dataset):
    r, collect, dsn = dataset
    with pytest.raises(ContractError):
        collect(replace(r, table_name="messages; DROP SCHEMA public CASCADE"))
    with psycopg.connect(dsn) as admin:
        assert (
            admin.execute(
                sql.SQL("SELECT count(*) FROM {}.messages").format(
                    sql.Identifier(r.schema_name)
                )
            ).fetchone()[0]
            == 2
        )


def test_private_unix_transport_requires_explicit_fixture_permission(dataset):
    registration, collect, _ = dataset
    with pytest.raises(ContractError, match="transport"):
        collect(replace(registration, allow_private_unix_fixture=False))


def test_noinherit_write_role_is_not_a_readonly_verifier(dataset):
    registration, collect, dsn = dataset
    writer = "writer_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS"
            ).format(sql.Identifier(writer))
        )
        admin.execute(
            sql.SQL("GRANT UPDATE ON {}.messages TO {}").format(
                sql.Identifier(registration.schema_name), sql.Identifier(writer)
            )
        )
        admin.execute(
            sql.SQL("GRANT {} TO {}").format(
                sql.Identifier(writer), sql.Identifier(registration.reader_role)
            )
        )
    try:
        with pytest.raises(ContractError, match="SELECT-only"):
            collect()
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(
                sql.SQL("REVOKE {} FROM {}").format(
                    sql.Identifier(writer), sql.Identifier(registration.reader_role)
                )
            )
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(writer)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(writer)))


def test_large_numeric_changes_cannot_be_hidden_by_decimal_context_rounding(dataset):
    from decimal import Decimal, localcontext

    registration, collect, dsn = dataset
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL("ALTER TABLE {}.messages ALTER COLUMN amount TYPE numeric").format(
                sql.Identifier(registration.schema_name)
            )
        )
        definition = table_definition(owner, registration.schema_name, "messages")
        owner.execute(
            sql.SQL("UPDATE {}.messages SET amount=%s WHERE id=1").format(
                sql.Identifier(registration.schema_name)
            ),
            (Decimal("123456789012345678901234567890.12345678901"),),
        )
    current = replace(registration, schema_digest=definition["schema_digest"])
    with localcontext() as context:
        context.prec = 5
        before = collect(current)["manifest"]
        with psycopg.connect(dsn, autocommit=True) as owner:
            owner.execute(
                sql.SQL("UPDATE {}.messages SET amount=%s WHERE id=1").format(
                    sql.Identifier(registration.schema_name)
                ),
                (Decimal("123456789012345678901234567890.12345678902"),),
            )
        after = collect(current)["manifest"]
    assert (
        before.row_count == after.row_count
        and before.content_digest != after.content_digest
    )


@pytest.mark.parametrize("kind", ["json", "jsonb"])
def test_json_precision_and_json_null_are_preserved_in_actual_pg_snapshot(
    dataset, kind
):
    registration, collect, dsn = dataset
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL("ALTER TABLE {}.messages ADD COLUMN details {}").format(
                sql.Identifier(registration.schema_name), sql.SQL(kind)
            )
        )
        definition = table_definition(owner, registration.schema_name, "messages")
    current = replace(
        registration,
        columns=definition["columns"],
        schema_digest=definition["schema_digest"],
    )

    def capture(value):
        with psycopg.connect(dsn, autocommit=True) as owner:
            owner.execute(
                sql.SQL("UPDATE {}.messages SET details=%s::{} WHERE id=1").format(
                    sql.Identifier(registration.schema_name), sql.SQL(kind)
                ),
                (value,),
            )
        return collect(current)["manifest"].content_digest

    assert capture('{"amount":123456789012345678901234567890.01}') != capture(
        '{"amount":123456789012345678901234567890.02}'
    )
    assert capture(None) != capture("null")
    assert capture("1.0") == capture("1")
    if kind == "json":
        with pytest.raises(ContractError):
            capture('{"a":1,"a":2}')


def test_oversize_text_is_blocked_by_database_side_extraction_bound(dataset):
    registration, collect, dsn = dataset
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "UPDATE {}.messages SET body=repeat('x',1000000) WHERE id=1"
            ).format(sql.Identifier(registration.schema_name))
        )
    with pytest.raises(ContractError, match="extraction capacity"):
        collect()
