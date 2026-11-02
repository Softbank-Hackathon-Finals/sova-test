"""Explicitly isolated real PostgreSQL fixtures shared by repository suites."""

import os
from pathlib import Path
from uuid import uuid4
from datetime import timedelta
import psycopg
from psycopg import sql
import pytest
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.sql_resources import migration_sql
from sova.domain.contracts import ResourceScope
from sova.domain.evidence import RevisionSet, VerificationObligation, Gate
from sova.domain.plans import (
    LifecyclePlan,
    PlanStep,
    PlanPurpose,
    PlanApproval,
    Inspection,
)


@pytest.fixture(scope="session")
def postgres_database():
    dsn = os.environ.get("SOVA_TEST_POSTGRES_DSN")
    if not dsn:
        pytest.skip("SOVA_TEST_POSTGRES_DSN is required for real PostgreSQL tests")
    role = "sova_runtime_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert admin.execute(
            "SELECT current_setting('cluster_name'),current_database()"
        ).fetchone() == ("sova-persistence-test", "sova_test")
        migration = (
            Path(__file__).resolve().parents[1]
            / "src/sova/adapters/sql/postgres_lifecycle_v1.sql"
        )
        admin.execute(migration.read_text())
        admin.execute(migration_sql("postgres_lifecycle_v2.sql"))
        admin.execute(migration_sql("postgres_operations_v1.sql"))
        admin.execute(migration_sql("postgres_execution_v1.sql"))
        admin.execute(migration_sql("postgres_governance_v1.sql"))
        admin.execute(migration_sql("postgres_governance_v2.sql"))
        admin.execute(migration_sql("postgres_security_observations_v1.sql"))
        admin.execute(migration_sql("postgres_security_response_v1.sql"))
        admin.execute(migration_sql("postgres_security_response_v2.sql"))
        admin.execute(migration_sql("postgres_signed_evidence_v1.sql"))
        admin.execute(migration_sql("postgres_protection_parity_v1.sql"))
        admin.execute(migration_sql("postgres_verifier_registry_v1.sql"))
        admin.execute(migration_sql("postgres_modernization_v1.sql"))
        admin.execute(migration_sql("postgres_migration_programs_v1.sql"))
        admin.execute(
            sql.SQL(
                "CREATE ROLE {} LOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOINHERIT"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        admin.execute(
            sql.SQL(
                "GRANT SELECT,INSERT ON ALL TABLES IN SCHEMA sova_control TO {}"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL(
                "GRANT UPDATE(revision,revoked_at) ON sova_control.approvals TO {}"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        admin.execute(
            sql.SQL(
                "GRANT UPDATE(status,revision,updated_at) ON sova_control.operations TO {}"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL(
                "GRANT UPDATE(owner_id,lease_token,lease_until,attempt,published_at,suppressed_at,publisher_id,message_id) ON sova_control.operation_outbox TO {}"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL(
                "GRANT UPDATE(operation_id,owner_id,token,epoch,valid_until,mode,proof_digest,proof_valid_until,recovery_effects) ON sova_control.app_execution TO {}"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL(
                "GRANT UPDATE(status,revision,observation_document) ON sova_control.effects TO {}"
            ).format(sql.Identifier(role))
        )
    return dsn, role


@pytest.fixture
def postgres_bundle(postgres_database, now):
    dsn, role = postgres_database
    tenant = "tenant-" + uuid4().hex

    def connect():
        return psycopg.connect(dsn, user=role)

    repo = PostgresLifecycleRepository(connect, tenant_id=tenant, clock=lambda: now)
    scope = ResourceScope(tenant, "app", "environment", "owned-resource")
    revisions = RevisionSet("a" * 64, "b" * 64, "c" * 64, "d" * 64)
    obligation = VerificationObligation("owned", scope, Gate.PREFLIGHT, "v1")
    step = PlanStep(
        "isolate", scope, "test-ingress", "set_ingress", '{"blocked":true}', "r1"
    )
    plan = LifecyclePlan(
        "plan",
        tenant,
        "app",
        "author",
        PlanPurpose.CHANGE,
        revisions,
        now + timedelta(minutes=10),
        (step,),
        (obligation,),
    )
    approval = PlanApproval(
        plan.fingerprint, "approver", plan.purpose, plan.valid_until
    )
    inspection = Inspection(
        scope, revisions, now, plan.valid_until, '{"state":"known"}', "e" * 64
    )
    return repo, plan, approval, inspection, obligation


@pytest.fixture(scope="session")
def second_postgres_database(postgres_database):
    dsn = os.environ.get("SOVA_TEST_SECOND_POSTGRES_DSN")
    if not dsn:
        pytest.skip(
            "SOVA_TEST_SECOND_POSTGRES_DSN is required for independent-cluster tests"
        )
    with psycopg.connect(dsn, autocommit=True) as conn:
        assert conn.execute(
            "SELECT current_setting('cluster_name'),current_database()"
        ).fetchone() == ("sova-persistence-target-test", "sova_target_test")
        second_id = conn.execute(
            "SELECT system_identifier::text FROM pg_control_system()"
        ).fetchone()[0]
    with psycopg.connect(postgres_database[0]) as conn:
        first_id = conn.execute(
            "SELECT system_identifier::text FROM pg_control_system()"
        ).fetchone()[0]
    assert first_id != second_id
    return dsn
