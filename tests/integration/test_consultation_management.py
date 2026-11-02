import json
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest

from examples.consultation.manage import main

pytestmark = pytest.mark.postgres


def test_operator_management_writes_invites_only_to_private_file_and_conflicts_before_mutation(
    postgres_database, tmp_path, capsys
):
    dsn, _ = postgres_database
    unique = uuid4().hex
    schema = "cli_" + unique
    role = "cli_app_" + unique
    secret = tmp_path / "owner.dsn"
    secret.write_text(dsn)
    secret.chmod(0o600)
    output = tmp_path / "invites.json"
    with psycopg.connect(dsn, autocommit=True) as owner:
        owner.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT CONNECTION LIMIT 8"
            ).format(sql.Identifier(role))
        )
    args = ["--owner-dsn-file", str(secret), "--schema", schema]
    try:
        assert (
            main(
                [
                    "prepare",
                    *args,
                    "--runtime-role",
                    role,
                    "--private-output",
                    str(output),
                ]
            )
            == 0
        )
        content = json.loads(output.read_text())
        assert len(content["users"]) == 3 and output.stat().st_mode & 0o777 == 0o600
        printed = capsys.readouterr()
        assert all(
            person["invite"] not in printed.out + printed.err
            for person in content["users"]
        )
        different = "unused_" + unique
        assert (
            main(
                [
                    "prepare",
                    "--owner-dsn-file",
                    str(secret),
                    "--schema",
                    different,
                    "--runtime-role",
                    role,
                    "--private-output",
                    str(output),
                ]
            )
            == 2
        )
        assert output.exists()  # never delete a pre-existing private output
        with psycopg.connect(dsn) as owner:
            assert (
                owner.execute(
                    "SELECT 1 FROM pg_namespace WHERE nspname=%s", (different,)
                ).fetchone()
                is None
            )
        assert main(["pause", *args]) == 0
        with psycopg.connect(dsn) as owner:
            assert owner.execute(
                sql.SQL("SELECT writes_enabled FROM {}.control").format(
                    sql.Identifier(schema)
                )
            ).fetchone() == (False,)
        assert main(["resume", *args]) == 0
        renewed = tmp_path / "renewed.json"
        assert main(["issue-invites", *args, "--private-output", str(renewed)]) == 0
        assert len(json.loads(renewed.read_text())["users"]) == 3
    finally:
        with psycopg.connect(dsn, autocommit=True) as owner:
            owner.execute(
                sql.SQL("DROP OWNED BY {} CASCADE").format(sql.Identifier(role))
            )
            owner.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(
                    sql.Identifier(schema)
                )
            )
            owner.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
