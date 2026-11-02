"""Real disposable PostgreSQL; provider and identity authorities are test doubles."""

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from uuid import uuid4

import psycopg
import pytest

from governance_support import bundle, release_bundle
from support import IngressAdapter
from sova.adapters.postgres_governance import PostgresSecurityHolds
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.governance import GovernanceGuard, SecurityHoldService
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import ContractError, EffectStatus
from sova.ports.plans import RecordNotFound, RepositoryConflict

pytestmark = pytest.mark.postgres


@pytest.fixture
def case(postgres_bundle, now):
    lifecycle = postgres_bundle[0]
    scope = postgres_bundle[3].scope
    policy, plan, approval, evidence, hold = bundle(scope, now)
    repository = PostgresSecurityHolds(lifecycle.connect, tenant_id=lifecycle.tenant_id)
    return lifecycle, repository, policy, plan, approval, evidence, hold


def test_append_only_hold_survives_new_repository_and_idempotent_open(case):
    lifecycle, repo, _, plan, _, _, hold = case
    assert repo.open_hold(hold) == repo.open_hold(hold)
    restarted = PostgresSecurityHolds(lifecycle.connect, tenant_id=repo.tenant_id)
    assert restarted.get_hold(plan.application_id, hold.hold_id).active
    assert len(restarted.active_holds(plan.application_id)) == 1
    with pytest.raises(RepositoryConflict):
        repo.open_hold(replace(hold, reason="replace incident"))


def test_tenant_app_and_rls_boundaries(case):
    lifecycle, repo, _, plan, _, _, hold = case
    repo.open_hold(hold)
    other = PostgresSecurityHolds(lifecycle.connect, tenant_id="other-" + uuid4().hex)
    assert other.active_holds(plan.application_id) == ()
    with pytest.raises(RecordNotFound):
        other.get_hold(plan.application_id, hold.hold_id)
    with pytest.raises(RecordNotFound):
        repo.get_hold("other-app", hold.hold_id)
    with pytest.raises(ContractError):
        other.open_hold(hold)
    with lifecycle.connect() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.security_hold_events"
        ).fetchone() == (0,)
        conn.execute("SELECT set_config('sova.tenant_id',%s,true)", (repo.tenant_id,))
        assert conn.execute(
            "SELECT count(*) FROM sova_control.security_hold_events"
        ).fetchone() == (1,)
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(
                "INSERT INTO sova_control.security_hold_events(tenant_id,application_id,hold_id,revision,event_kind,digest,document) VALUES('other','app','x',1,'opened',%s,'{}')",
                ("a" * 64,),
            )


@pytest.mark.parametrize(
    "query",
    [
        "UPDATE sova_control.security_hold_events SET document='{}'",
        "DELETE FROM sova_control.security_hold_events",
    ],
)
def test_runtime_cannot_overwrite_or_delete_security_history(case, query):
    lifecycle, repo, _, _, _, _, hold = case
    repo.open_hold(hold)
    with lifecycle.connect() as conn:
        conn.execute("SELECT set_config('sova.tenant_id',%s,true)", (repo.tenant_id,))
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(query)


def test_concurrent_release_is_compare_and_swap_and_cannot_reactivate(case, now):
    lifecycle, repo, _, plan, _, _, hold = case
    repo.open_hold(hold)
    request, _ = release_bundle(hold, plan.revisions, now)

    def release():
        try:
            repo.release_hold(plan.application_id, request)
            return "released"
        except RepositoryConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: release(), range(2)))
    assert sorted(results) == ["conflict", "released"]
    assert repo.active_holds(plan.application_id) == ()
    assert repo.get_hold(plan.application_id, hold.hold_id).revision == 2
    with pytest.raises(RepositoryConflict):
        repo.open_hold(hold)
    with lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT event_kind FROM sova_control.security_hold_events WHERE hold_id=%s ORDER BY revision",
            (hold.hold_id,),
        ).fetchall() == [("opened",), ("released",)]


def test_concurrent_open_has_one_immutable_event(case):
    lifecycle, repo, _, _, _, _, hold = case
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: repo.open_hold(hold), range(2)))
    assert results[0] == results[1]
    with lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.security_hold_events"
        ).fetchone() == (1,)


def test_ordinary_approval_does_not_release_hold_and_success_requires_security_service(
    case, now, tmp_path
):
    lifecycle, repo, policy, plan, approval, evidence, hold = case
    lifecycle.save_plan(plan)
    lifecycle.save_approval(plan.application_id, plan.plan_id, "approval", approval)
    guard = GovernanceGuard(
        repo,
        policy_provider=lambda _: policy,
        evidence_provider=lambda _: (evidence,),
        authenticate_policy=lambda _: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    repo.open_hold(hold)
    adapter = IngressAdapter()
    with sqlite3.connect(tmp_path / "effects.sqlite") as connection:
        effects = EffectExecutor(
            SQLiteEffectJournal(connection),
            authorize=lambda *_: None,
            clock=lambda: now,
        )
        executor = ApprovedPlanExecutor(
            effects,
            required_obligations=lambda _: plan.obligations,
            authenticate_approval=lambda *_: None,
            authenticate_evidence=lambda _: None,
            governance_guard=guard,
            clock=lambda: now,
        )
        stored = StoredPlanExecutor(lifecycle, executor)

        def run():
            return stored.execute_step(
                plan.application_id,
                plan.plan_id,
                "approval",
                "isolate",
                operation_id="operation",
                epoch=1,
                evidence=(evidence,),
                adapter=adapter,
            )

        with pytest.raises(ContractError, match="governance"):
            run()
        assert adapter.calls == []
        request, revalidation = release_bundle(hold, plan.revisions, now)
        service = SecurityHoldService(
            repo,
            authorize=lambda *_: None,
            authenticate_release=lambda _: None,
            authenticate_evidence=lambda _: None,
            current_revisions=lambda _: plan.revisions,
            clock=lambda: now,
        )
        service.release(
            request.requested_by, plan.application_id, request, revalidation
        )
        assert run().status == EffectStatus.APPLIED
        assert len(adapter.calls) == 1


def test_hold_raised_after_claim_blocks_apply(case, now, tmp_path):
    _, repo, policy, plan, approval, evidence, hold = case
    guard = GovernanceGuard(
        repo,
        policy_provider=lambda _: policy,
        evidence_provider=lambda _: (evidence,),
        authenticate_policy=lambda _: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: now,
    )
    adapter = IngressAdapter()
    validate = adapter.validate
    calls = []

    def inject(command):
        calls.append(command)
        if len(calls) == 2:
            repo.open_hold(hold)
        validate(command)

    adapter.validate = inject
    with sqlite3.connect(tmp_path / "effects.sqlite") as connection:
        journal = SQLiteEffectJournal(connection)
        executor = ApprovedPlanExecutor(
            EffectExecutor(journal, authorize=lambda *_: None, clock=lambda: now),
            required_obligations=lambda _: plan.obligations,
            authenticate_approval=lambda *_: None,
            authenticate_evidence=lambda _: None,
            governance_guard=guard,
            clock=lambda: now,
        )
        with pytest.raises(ContractError, match="governance"):
            executor.execute_step(
                plan,
                approval,
                "isolate",
                operation_id="operation",
                epoch=1,
                evidence=(evidence,),
                adapter=adapter,
            )
        assert adapter.calls == []
        command = plan.command("isolate", operation_id="operation", epoch=1)
        assert journal.get(command).status == EffectStatus.NOT_APPLIED


def test_privileged_database_identity_is_rejected(case, postgres_database):
    _, repo, _, plan, _, _, _ = case
    dsn, _ = postgres_database
    privileged = PostgresSecurityHolds(
        lambda: psycopg.connect(dsn), tenant_id=repo.tenant_id
    )
    with pytest.raises(ContractError):
        privileged.active_holds(plan.application_id)


def test_deployment_reader_cannot_open_or_release_security_holds(
    case, postgres_database
):
    from psycopg import sql

    lifecycle, repo, _, plan, _, _, hold = case
    repo.open_hold(hold)
    dsn, _ = postgres_database
    role = "sova_security_reader_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as conn:
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
            sql.SQL("GRANT SELECT ON sova_control.security_hold_events TO {}").format(
                sql.Identifier(role)
            )
        )
    reader = PostgresSecurityHolds(
        lambda: psycopg.connect(dsn, user=role), tenant_id=lifecycle.tenant_id
    )
    assert reader.active_holds(plan.application_id)[0].hold == hold
    with pytest.raises(psycopg.errors.InsufficientPrivilege):
        reader.open_hold(replace(hold, hold_id="new-incident"))


def test_database_trigger_serializes_even_direct_security_insert(case, now):
    from dataclasses import replace
    from threading import Event
    from concurrent.futures import ThreadPoolExecutor
    from psycopg.types.json import Jsonb
    from sova.adapters.plan_codec import document_hash
    from sova.adapters.postgres_governance import lock_security_hold_set
    from sova.domain.governance import StoredHold

    lifecycle, repo, _, plan, _, _, hold = case
    held = StoredHold(hold, 1)
    other = StoredHold(
        replace(
            hold,
            hold_id="other-app",
            scope=replace(hold.scope, application_id="independent-app"),
        ),
        1,
    )
    entered = Event()

    def insert(stored, signal=False):
        with lifecycle.transaction() as connection:
            if signal:
                entered.set()
            connection.execute(
                "INSERT INTO sova_control.security_hold_events(tenant_id,application_id,hold_id,revision,event_kind,digest,document) VALUES(%s,%s,%s,1,'opened',%s,%s)",
                (
                    repo.tenant_id,
                    stored.hold.scope.application_id,
                    stored.hold.hold_id,
                    document_hash(stored.document),
                    Jsonb(stored.document),
                ),
            )

    with ThreadPoolExecutor(max_workers=2) as pool:
        with lifecycle.transaction() as transaction:
            lock_security_hold_set(transaction, repo.tenant_id, plan.application_id)
            waiting = pool.submit(insert, held, True)
            assert entered.wait(1)
            # A different app's insert is an independent positive control.
            independent = pool.submit(insert, other)
            independent.result(timeout=3)
            assert not waiting.done()
        waiting.result(timeout=3)
    assert repo.get_hold(plan.application_id, hold.hold_id).active


def test_database_and_application_hold_lock_keys_match_for_escaped_identifiers(case):
    from sova.adapters.plan_codec import document_hash

    lifecycle = case[0]
    with lifecycle.transaction() as connection:
        for tenant, app in [("tenant", "app"), ("조직-α", '앱"\\경로')]:
            expected = document_hash(
                {"tenant": tenant, "app": app, "purpose": "security-hold-set"}
            )
            assert connection.execute(
                "SELECT sova_control.security_hold_set_key(%s,%s)", (tenant, app)
            ).fetchone() == (expected,)
