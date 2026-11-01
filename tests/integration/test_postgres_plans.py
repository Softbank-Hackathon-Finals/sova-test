"""Real PostgreSQL only. Never migrate an arbitrary developer or cloud DB."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from uuid import uuid4

import psycopg
from psycopg import sql
import pytest

from support import IngressAdapter
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import ContractError, EffectStatus
from sova.domain.evidence import (
    EvidenceRecord,
    VerificationResult,
)
from sova.ports.plans import RecordNotFound, RepositoryConflict

pytestmark = pytest.mark.postgres


@pytest.fixture(scope="module")
def database(postgres_database):
    return postgres_database


@pytest.fixture
def bundle(postgres_bundle):
    return postgres_bundle


def test_restart_round_trip_for_plan_approval_and_snapshot(bundle, database, now):
    repo, plan, approval, inspection, _ = bundle
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", approval)
    repo.save_inspection("snapshot", inspection)
    restarted = PostgresLifecycleRepository(
        repo.connect, tenant_id=repo.tenant_id, clock=lambda: now
    )
    assert restarted.get_plan("app", "plan") == plan
    assert restarted.get_approval("app", "approval").approval == approval
    assert restarted.get_inspection("app", "snapshot") == inspection


def test_immutable_records_are_idempotent_but_not_replaceable(bundle):
    repo, plan, approval, inspection, _ = bundle
    repo.save_plan(plan)
    repo.save_plan(plan)
    with pytest.raises(RepositoryConflict):
        repo.save_plan(replace(plan, reason="different"))
    repo.save_inspection("snapshot", inspection)
    repo.save_inspection("snapshot", inspection)
    with pytest.raises(RepositoryConflict):
        repo.save_inspection(
            "snapshot", replace(inspection, facts_json='{"state":"changed"}')
        )
    repo.save_approval("app", "plan", "approval", approval)
    repo.save_approval("app", "plan", "approval", approval)


def test_tenant_and_application_reads_do_not_disclose_other_records(bundle, now):
    repo, plan, approval, inspection, _ = bundle
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", approval)
    repo.save_inspection("snapshot", inspection)
    other = PostgresLifecycleRepository(
        repo.connect, tenant_id="other-" + uuid4().hex, clock=lambda: now
    )
    for scoped in (repo, other):
        app = "different-app" if scoped is repo else "app"
        for action in (
            lambda: scoped.get_plan(app, "plan"),
            lambda: scoped.get_approval(app, "approval"),
            lambda: scoped.get_inspection(app, "snapshot"),
        ):
            with pytest.raises(RecordNotFound):
                action()
    with pytest.raises(ContractError):
        other.save_plan(plan)
    with pytest.raises(ContractError):
        other.save_inspection("snapshot", inspection)


def test_rls_itself_blocks_unscoped_and_other_tenant_queries(bundle):
    repo, plan, _, _, _ = bundle
    repo.save_plan(plan)
    with repo.connect() as conn:
        assert conn.execute("SELECT count(*) FROM sova_control.plans").fetchone() == (
            0,
        )
        conn.execute("SELECT set_config('sova.tenant_id',%s,true)", (repo.tenant_id,))
        assert conn.execute("SELECT tenant_id FROM sova_control.plans").fetchall() == [
            (repo.tenant_id,)
        ]
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO sova_control.plans(tenant_id,application_id,plan_id,digest,document) VALUES('other','app','x',%s,'{}')",
                ("f" * 64,),
            )


def test_runtime_cannot_overwrite_plan_approval_or_delete_audit(bundle):
    repo, plan, approval, _, _ = bundle
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", approval)
    for query in (
        "UPDATE sova_control.plans SET document='{}'",
        "UPDATE sova_control.approvals SET document='{}'",
        "DELETE FROM sova_control.lifecycle_audit",
    ):
        with repo.connect() as conn:
            conn.execute(
                "SELECT set_config('sova.tenant_id',%s,true)", (repo.tenant_id,)
            )
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(query)


def test_superuser_repository_is_rejected(database, bundle):
    dsn, _ = database
    repo, plan, _, _, _ = bundle
    privileged = PostgresLifecycleRepository(
        lambda: psycopg.connect(dsn), tenant_id=repo.tenant_id
    )
    with pytest.raises(ContractError, match="row security"):
        privileged.save_plan(plan)


def test_revocation_cas_and_reactivation_denial(bundle):
    repo, plan, approval, _, _ = bundle
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", approval)
    changed = repo.revoke_approval(
        "app", "approval", expected_revision=1, actor_id="security-officer"
    )
    assert changed.revoked and changed.revision == 2
    with pytest.raises(RepositoryConflict):
        repo.revoke_approval(
            "app", "approval", expected_revision=1, actor_id="security-officer"
        )
    with pytest.raises(RepositoryConflict):
        repo.save_approval("app", "plan", "approval", approval)


def test_concurrent_approval_revocations_have_one_winner(bundle):
    repo, plan, approval, _, _ = bundle
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", approval)

    def revoke(_):
        try:
            repo.revoke_approval(
                "app", "approval", expected_revision=1, actor_id="approver"
            )
            return "won"
        except RepositoryConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(revoke, range(2)))
    assert sorted(results) == ["conflict", "won"]


def test_concurrent_plan_inserts_are_idempotent(bundle):
    repo, plan, _, _, _ = bundle
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(repo.save_plan, (plan, plan)))
    with repo.transaction() as conn:
        count = conn.execute(
            "SELECT count(*) FROM sova_control.lifecycle_audit WHERE record_id='plan' AND action='plan_created'"
        ).fetchone()
        assert count == (1,)


def test_saved_approval_is_checked_again_at_execution(bundle, now, tmp_path):
    repo, plan, approval, _, obligation = bundle
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", approval)
    proof = EvidenceRecord(
        "proof",
        "owned",
        obligation.scope,
        plan.revisions,
        "v1",
        now,
        plan.valid_until,
        VerificationResult.PASS,
        "artifact",
        "e" * 64,
    )
    with sqlite3.connect(tmp_path / "effects.sqlite") as db:
        effect = EffectExecutor(
            SQLiteEffectJournal(db), authorize=lambda *_: None, clock=lambda: now
        )
        calls = 0

        def revoke_during_dispatch(*_):
            nonlocal calls
            calls += 1
            if calls == 3:
                repo.revoke_approval(
                    "app", "approval", expected_revision=1, actor_id="approver"
                )

        executor = ApprovedPlanExecutor(
            effect,
            required_obligations=lambda _: (obligation,),
            authenticate_approval=revoke_during_dispatch,
            authenticate_evidence=lambda _: None,
            clock=lambda: now,
        )
        adapter = IngressAdapter()
        with pytest.raises(ContractError, match="revoked"):
            StoredPlanExecutor(repo, executor).execute_step(
                "app",
                "plan",
                "approval",
                "isolate",
                operation_id="operation",
                epoch=1,
                evidence=(proof,),
                adapter=adapter,
            )
        assert not adapter.calls
        assert (
            effect.journal.get(
                plan.command("isolate", operation_id="operation", epoch=1)
            ).status
            == EffectStatus.NOT_APPLIED
        )


def test_persisted_plan_executes_without_recreating_in_memory_objects(
    bundle, now, tmp_path
):
    repo, plan, approval, _, obligation = bundle
    repo.save_plan(plan)
    repo.save_approval("app", "plan", "approval", approval)
    proof = EvidenceRecord(
        "proof",
        "owned",
        obligation.scope,
        plan.revisions,
        "v1",
        now,
        plan.valid_until,
        VerificationResult.PASS,
        "artifact",
        "e" * 64,
    )
    with sqlite3.connect(tmp_path / "effects.sqlite") as db:
        effect = EffectExecutor(
            SQLiteEffectJournal(db), authorize=lambda *_: None, clock=lambda: now
        )
        executor = ApprovedPlanExecutor(
            effect,
            required_obligations=lambda _: (obligation,),
            authenticate_approval=lambda *_: None,
            authenticate_evidence=lambda _: None,
            clock=lambda: now,
        )
        result = StoredPlanExecutor(repo, executor).execute_step(
            "app",
            "plan",
            "approval",
            "isolate",
            operation_id="operation",
            epoch=1,
            evidence=(proof,),
            adapter=IngressAdapter(),
        )
        assert result.status == EffectStatus.APPLIED


def test_audit_failure_rolls_back_plan_creation(bundle, database):
    repo, plan, _, _, _ = bundle
    dsn, role = database
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            sql.SQL("REVOKE INSERT ON sova_control.lifecycle_audit FROM {}").format(
                sql.Identifier(role)
            )
        )
        try:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                repo.save_plan(plan)
        finally:
            admin.execute(
                sql.SQL("GRANT INSERT ON sova_control.lifecycle_audit TO {}").format(
                    sql.Identifier(role)
                )
            )
    with pytest.raises(RecordNotFound):
        repo.get_plan("app", "plan")


def test_stored_plan_corruption_is_detected(bundle, database):
    repo, plan, _, _, _ = bundle
    repo.save_plan(plan)
    from psycopg.types.json import Jsonb

    altered = {**plan.document, "reason": "changed outside repository"}
    with psycopg.connect(database[0]) as admin:
        admin.execute(
            "UPDATE sova_control.plans SET document=%s WHERE tenant_id=%s AND application_id=%s AND plan_id=%s",
            (Jsonb(altered), repo.tenant_id, "app", "plan"),
        )
    with pytest.raises(ContractError, match="integrity"):
        repo.get_plan("app", "plan")


def test_database_foreign_key_prevents_cross_application_approval(bundle):
    repo, plan, approval, _, _ = bundle
    repo.save_plan(plan)
    with repo.connect() as conn:
        conn.execute("SELECT set_config('sova.tenant_id',%s,true)", (repo.tenant_id,))
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            conn.execute(
                """INSERT INTO sova_control.approvals
                (tenant_id,application_id,approval_id,plan_id,plan_digest,document)
                VALUES(%s,'another-app','invalid','plan',%s,'{}')""",
                (repo.tenant_id, approval.plan_digest),
            )


def test_tenant_context_is_cleared_on_reused_connection(bundle, now):
    repo, plan, _, _, _ = bundle
    connection = repo.connect()
    connection.autocommit = True

    @contextmanager
    def pooled():
        yield connection

    try:
        first = PostgresLifecycleRepository(
            pooled, tenant_id=repo.tenant_id, clock=lambda: now
        )
        first.save_plan(plan)
        assert connection.execute(
            "SELECT current_setting('sova.tenant_id',true)"
        ).fetchone()[0] in ("", None)
        other = PostgresLifecycleRepository(
            pooled, tenant_id="other", clock=lambda: now
        )
        with pytest.raises(RecordNotFound):
            other.get_plan("app", "plan")
        assert first.get_plan("app", "plan") == plan
    finally:
        connection.close()


def test_non_superuser_table_owner_is_also_rejected(bundle, database):
    repo, plan, _, _, _ = bundle
    dsn, role = database
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute("CREATE TABLE sova_control.owner_probe(value text)")
        admin.execute(
            sql.SQL("ALTER TABLE sova_control.owner_probe OWNER TO {}").format(
                sql.Identifier(role)
            )
        )
        try:
            with pytest.raises(ContractError, match="row security"):
                repo.save_plan(plan)
        finally:
            admin.execute("DROP TABLE sova_control.owner_probe")
