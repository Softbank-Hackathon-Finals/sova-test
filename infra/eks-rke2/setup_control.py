"""Reuse Sova's private PG demo setup for the separate relocation fixture."""

import argparse
import json
import os
from pathlib import Path
import secrets
import sys

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

PROJECT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT / "demo"))
from security_demo import Demo


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--pg-bin", required=True)
    parser.add_argument("--pg-share", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    root = args.root.resolve()
    if (root / "control-db.json").exists():
        raise RuntimeError("Control DB already registered; do not recreate")
    Demo(root, {"pg_bin": args.pg_bin, "pg_share": args.pg_share}).setup_database()
    path = root / "control-db.json"
    db = json.loads(path.read_text())
    with psycopg.connect(db["admin_dsn"], autocommit=True) as conn:
        for name in ("postgres_security_response_v1", "postgres_security_response_v2"):
            conn.execute(
                (PROJECT / "src/sova/adapters/sql" / (name + ".sql")).read_text()
            )
        for role in ("sova_response_admitter", "sova_response_worker"):
            conn.execute(
                sql.SQL(
                    "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
                ).format(sql.Identifier(role))
            )
            conn.execute(
                sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                    sql.Identifier(role)
                )
            )
            conn.execute(
                sql.SQL(
                    "GRANT SELECT ON ALL TABLES IN SCHEMA sova_control TO {}"
                ).format(sql.Identifier(role))
            )
            conn.execute(
                sql.SQL(
                    "GRANT USAGE ON ALL SEQUENCES IN SCHEMA sova_control TO {}"
                ).format(sql.Identifier(role))
            )
        for table in (
            "plans",
            "approvals",
            "lifecycle_audit",
            "operations",
            "operation_outbox",
            "operation_events",
        ):
            conn.execute(
                sql.SQL(
                    "GRANT INSERT ON sova_control.{} TO sova_response_admitter"
                ).format(sql.Identifier(table))
            )
        for table in (
            "app_execution",
            "effects",
            "effect_events",
            "execution_events",
            "security_routes",
        ):
            conn.execute(
                sql.SQL(
                    "GRANT INSERT ON sova_control.{} TO sova_response_worker"
                ).format(sql.Identifier(table))
            )
        for table, columns in (
            (
                "app_execution",
                "operation_id,owner_id,token,epoch,valid_until,mode,proof_digest,proof_valid_until,recovery_effects",
            ),
            ("effects", "status,revision,observation_document"),
            ("operations", "status,revision,updated_at"),
            ("security_routes", "target_environment,revision,plan_digest,updated_at"),
        ):
            conn.execute(
                sql.SQL(
                    "GRANT UPDATE({}) ON sova_control.{} TO sova_response_worker"
                ).format(sql.SQL(columns), sql.Identifier(table))
            )
        conn.execute(
            "GRANT UPDATE(lock_guard) ON sova_control.approvals TO sova_response_worker"
        )
        conn.execute(
            "GRANT UPDATE(lock_guard) ON sova_control.approvals TO sova_response_admitter"
        )
        conn.execute((PROJECT / "infra/eks-rke2/route-receipts.sql").read_text())
        conn.execute(
            "GRANT SELECT,INSERT ON sova_control.relocation_receipts TO sova_response_worker"
        )
    db["worker_dsn"] = make_conninfo(db["admin_dsn"], user="sova_response_worker")
    db["admitter_dsn"] = make_conninfo(db["admin_dsn"], user="sova_response_admitter")
    path.write_text(json.dumps(db, indent=2) + "\n")
    (root / "bridge-token").write_text(secrets.token_urlsafe(32))
    print("Separate private control DB and restricted roles ready; no TCP listener.")


if __name__ == "__main__":
    main()
