"""Actual PostgreSQL RLS/immutability; HTTP and cloud evidence are test doubles."""

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import psycopg
from psycopg import sql
import pytest

from relocation_receipts import RelocationReceipts
from relocation_server import RouteAdapter
from support import permit_for
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.postgres_security_routes import PostgresSecurityRoutes
from sova.application.effects import EffectExecutor
from sova.domain.contracts import ContractError, ResourceScope, canonical_json
from sova.domain.operations import OperationRequest
from sova.domain.plans import PlanStep
from sova.ports.plans import RepositoryConflict

pytestmark = pytest.mark.postgres


@pytest.fixture
def receipt(postgres_database, postgres_bundle, now):
    dsn, role = postgres_database
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(
            (
                Path(__file__).resolve().parents[3]
                / "infra/eks-rke2/route-receipts.sql"
            ).read_text()
        )
        admin.execute(
            sql.SQL(
                "GRANT SELECT,INSERT ON sova_control.relocation_receipts TO {}"
            ).format(sql.Identifier(role))
        )
        admin.execute(
            sql.SQL(
                "GRANT UPDATE(target_environment,revision,plan_digest,updated_at) ON sova_control.security_routes TO {}"
            ).format(sql.Identifier(role))
        )
    lifecycle, template, approval, _, _ = postgres_bundle
    registration = "d" * 64
    scope = ResourceScope(lifecycle.tenant_id, "app", "local-entry", "quote-entry")
    step = PlanStep(
        "route",
        scope,
        RouteAdapter.adapter_id,
        "switch_route",
        canonical_json(
            dict(source="aws", target="vm", route_revision=1, registration=registration)
        ),
        "route-1",
    )
    plan = replace(template, steps=(step,))
    lifecycle.save_plan(plan)
    lifecycle.save_approval(
        "app", "plan", "approval", replace(approval, plan_digest=plan.fingerprint)
    )
    PostgresOperationRepository(lifecycle).submit(
        OperationRequest(
            lifecycle.tenant_id,
            "app",
            "operation",
            "plan",
            plan.fingerprint,
            "approval",
            1,
            "operator",
            "route-request",
        )
    )
    ownership = PostgresExecutionOwnership(lifecycle)
    lease = ownership.acquire("app", "operation", "worker")
    routes = PostgresSecurityRoutes(lifecycle.connect, tenant_id=lifecycle.tenant_id)
    routes.register("app", "quote-entry", "aws")
    runtime = SimpleNamespace(
        revision=registration,
        require_registration=lambda: None,
        routes=routes,
        app="app",
        route=lambda: routes.get("app", "quote-entry"),
    )
    journal = PostgresEffectJournal(ownership, lease)
    command = plan.command("route", operation_id="operation", epoch=lease.epoch)
    EffectExecutor(journal, authorize=journal.authorize, clock=lambda: now).execute(
        command, permit_for(command), RouteAdapter(runtime)
    )
    args = dict(
        operation_id="operation",
        plan_digest=plan.fingerprint,
        effect_digest=command.fingerprint,
        registration_digest=registration,
        target="vm",
        route_revision=2,
        postflight=dict(
            ok=True, total=220, environment="vm", id="a" * 32, latency_ms=3.0
        ),
    )
    return RelocationReceipts(lifecycle), args, routes


def test_postflight_is_immutable_and_can_be_read_by_new_connection(receipt):
    repo, args, routes = receipt
    repo.save("app", **args)
    restarted = RelocationReceipts(
        PostgresLifecycleRepository(
            repo.lifecycle.connect, tenant_id=repo.lifecycle.tenant_id
        )
    )
    records = restarted.history("app", args["registration_digest"])
    assert records[0]["historical"] is True
    assert records[0]["full_migration_verified"] is False
    repo.save("app", **args)
    with pytest.raises(RepositoryConflict):
        repo.save(
            "app", **{**args, "postflight": {**args["postflight"], "id": "b" * 32}}
        )
    routes.switch(
        "app",
        "quote-entry",
        source="vm",
        target="aws",
        expected_revision=2,
        plan_digest="a" * 64,
    )
    # Idempotent receipt read does not require replaying an old route.
    repo.save("app", **args)
    assert routes.get("app", "quote-entry")["environment_id"] == "aws"


@pytest.mark.parametrize(
    "change",
    [
        dict(operation_id="missing"),
        dict(effect_digest="a" * 64),
        dict(route_revision=3),
        dict(registration_digest="a" * 64),
        dict(target="aws"),
    ],
)
def test_postflight_must_match_applied_route_effect(receipt, change):
    repo, args, _ = receipt
    with pytest.raises(ContractError):
        repo.save("app", **{**args, **change})
    history = repo.history("app", args["registration_digest"])
    assert history[0]["status"] == "needs_attention"
    assert "receipt_digest" not in history[0]


def test_receipt_is_scoped_and_runtime_cannot_update_or_delete(receipt):
    repo, args, _ = receipt
    repo.save("app", **args)
    other = RelocationReceipts(
        PostgresLifecycleRepository(repo.lifecycle.connect, tenant_id="other")
    )
    assert other.history("app", args["registration_digest"]) == []
    assert repo.history("app", "f" * 64) == []
    for statement in (
        "UPDATE sova_control.relocation_receipts SET digest=digest",
        "DELETE FROM sova_control.relocation_receipts",
    ):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with repo.lifecycle.transaction() as conn:
                conn.execute(statement)
