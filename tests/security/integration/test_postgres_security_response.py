from dataclasses import replace
from datetime import UTC, datetime, timedelta
import pytest
import psycopg
from security_support import security_snapshot
from sova.domain.security_response import (
    StatelessResponseProfile,
    SecurityResponseBinding,
)
from sova.domain.governance import SecurityHold
from sova.domain.plans import PlanApproval
from sova.domain.operations import OperationRequest
from sova.domain.evidence import EvidenceRecord, VerificationResult
from sova.domain.contracts import EffectObservation, EffectStatus, ContractError
from sova.adapters.postgres_governance import PostgresSecurityHolds
from sova.adapters.postgres_operations import PostgresOperationRepository
from sova.adapters.postgres_execution import PostgresExecutionOwnership
from sova.adapters.postgres_effects import PostgresEffectJournal
from sova.application.security_response import SecurityResponseGuard
from sova.application.security_response_runner import SecurityResponseRunner

pytestmark = pytest.mark.postgres


@pytest.fixture
def response(postgres_bundle, now):
    lifecycle = postgres_bundle[0]
    lifecycle.clock = lambda: datetime.now(UTC)
    scope = postgres_bundle[3].scope
    source = security_snapshot(scope, now)
    target = security_snapshot(replace(scope, environment_id="target"), now)
    profile = StatelessResponseProfile(
        "test",
        "a" * 64,
        "f" * 64,
        True,
        True,
        True,
        "operator",
        now + timedelta(minutes=5),
    )
    hold = SecurityHold(
        "incident", source.graph.resources[0].scope, "detector", "violation", now
    )
    holds = PostgresSecurityHolds(lifecycle.connect, tenant_id=lifecycle.tenant_id)
    holds.open_hold(hold)
    binding = SecurityResponseBinding(
        source,
        target,
        "deployment:api",
        "deployment:api",
        (hold.hold_id,),
        profile,
        "c" * 64,
    )
    plan = binding.compile(
        plan_id="response",
        created_by="planner",
        now=now,
        valid_until=now + timedelta(minutes=2),
    )
    approval = PlanApproval(
        plan.fingerprint, "approver", plan.purpose, plan.valid_until
    )
    lifecycle.save_plan(plan)
    lifecycle.save_approval(scope.application_id, plan.plan_id, "approval", approval)
    request = OperationRequest(
        scope.tenant_id,
        scope.application_id,
        "response-operation",
        plan.plan_id,
        plan.fingerprint,
        "approval",
        1,
        "operator",
        "response-request",
    )
    operations = PostgresOperationRepository(lifecycle)
    operations.submit(request)
    evidence = tuple(
        EvidenceRecord(
            "e:" + o.obligation_id,
            o.obligation_id,
            o.scope,
            plan.revisions,
            o.verifier_version,
            now,
            plan.valid_until,
            VerificationResult.PASS,
            "test-admission",
            "f" * 64,
        )
        for o in plan.obligations
    )
    return lifecycle, operations, holds, binding, plan, evidence, request


class ResponseAdapter:
    adapter_id = "sova-stateless-security-response"

    def __init__(self, fail=None):
        self.calls = []
        self.fail = fail

    def validate(self, command):
        pass

    def apply(self, command):
        self.calls.append(command.action)
        if command.action == self.fail:
            raise OSError("Lost effect response")

    def readback(self, command, now):
        return EffectObservation(
            command.scope,
            command.fingerprint,
            EffectStatus.APPLIED,
            now,
            '{"test":"provider-double"}',
        )


def run(response, adapter, *, emit=None):
    lifecycle, operations, holds, binding, plan, evidence, request = response
    guard = SecurityResponseGuard(
        binding,
        holds,
        authorize_profile=lambda *_: None,
        verify_admission=lambda *_: None,
        clock=lambda: datetime.now(UTC),
    )
    runner = SecurityResponseRunner(
        lifecycle,
        operations,
        PostgresExecutionOwnership(lifecycle),
        journal_factory=PostgresEffectJournal,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda *_: None,
        clock=lambda: datetime.now(UTC),
    )
    return runner.run(
        plan.application_id,
        request.operation_id,
        owner_id="worker",
        evidence=evidence,
        guard=guard,
        adapter=adapter,
        emit=emit or (lambda *_: None),
    )


def test_response_has_own_state_profile_and_retains_hold(response):
    result = run(response, ResponseAdapter())
    assert result["status"] == "response_verified"
    assert response[2].active_holds(response[4].application_id)
    assert (
        response[1]
        .get(response[4].application_id, response[6].operation_id)
        .state.profile.value
        == "security_response"
    )
    with pytest.raises(ContractError):
        run(response, ResponseAdapter())
    with response[0].transaction() as conn:
        assert conn.execute(
            "SELECT suppressed_at IS NOT NULL FROM sova_control.operation_outbox"
        ).fetchone() == (True,)


def test_new_hold_blocks_response_before_external_mutation(response):
    _, _, holds, binding, plan, _, _ = response
    holds.open_hold(
        SecurityHold(
            "new-incident",
            binding.source_resource.scope,
            "detector",
            "second incident",
            datetime.now(UTC),
        )
    )
    adapter = ResponseAdapter()
    with pytest.raises(ContractError):
        run(response, adapter)
    assert adapter.calls == []


def test_unknown_response_retains_effect_barrier_and_is_not_replayed(response):
    from sova.application.effects import UncertainEffect

    adapter = ResponseAdapter(fail="activate_replacement")
    with pytest.raises(UncertainEffect):
        run(response, adapter)
    assert adapter.calls == ["apply_isolation", "activate_replacement"]
    stored = response[1].get(response[4].application_id, response[6].operation_id)
    assert stored.state.status.value == "recovery_required"
    with pytest.raises(ContractError):
        run(response, adapter)
    assert len(adapter.calls) == 2


def test_incident_trigger_deduplicates_concurrent_collectors(response):
    from concurrent.futures import ThreadPoolExecutor

    _, _, holds, binding, _, _, _ = response
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda _: holds.open_incident(
                    binding.target_resource.scope, "posture:read-only-root", "collector"
                ),
                range(2),
            )
        )
    assert sum(created for _, created in results) == 1
    assert results[0][0].hold.hold_id == results[1][0].hold.hold_id


def test_signed_issuer_revocation_stops_later_response_steps(response, now):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sova.adapters.ed25519_evidence import (
        Ed25519EvidenceSigner,
        Ed25519EvidenceVerifier,
    )
    from sova.adapters.postgres_signed_evidence import PostgresSignedEvidence
    from sova.application.signed_evidence import SignedEvidenceAuthority
    from sova.domain.signed_evidence import VerifierTrust

    lifecycle, operations, holds, binding, plan, evidence, request = response
    signer = Ed25519EvidenceSigner(
        Ed25519PrivateKey.generate(),
        issuer_id="response-admission-verifier",
        key_id="key-1",
    )
    trust = [
        VerifierTrust(
            signer.issuer_id,
            signer.key_id,
            signer.public_key_hex,
            (binding.source_resource.scope,),
            ("sova-security-response-admission-v1",),
            now - timedelta(seconds=1),
            plan.valid_until,
        )
    ]
    authority = SignedEvidenceAuthority(
        PostgresSignedEvidence(lifecycle.connect, tenant_id=lifecycle.tenant_id),
        Ed25519EvidenceVerifier(lambda *_: trust[0]),
        clock=lambda: datetime.now(UTC),
    )
    for record in evidence:
        authority.ingest(signer.sign(record, issued_at=datetime.now(UTC)))
    guard = SecurityResponseGuard(
        binding,
        holds,
        authorize_profile=lambda *_: None,
        verify_admission=lambda *_: None,
        clock=lambda: datetime.now(UTC),
    )
    adapter = ResponseAdapter()
    original = adapter.apply

    def revoke_after_first(command):
        original(command)
        trust[0] = replace(trust[0], revoked=True)

    adapter.apply = revoke_after_first
    runner = SecurityResponseRunner(
        lifecycle,
        operations,
        PostgresExecutionOwnership(lifecycle),
        journal_factory=PostgresEffectJournal,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=authority.authenticate,
        clock=lambda: datetime.now(UTC),
    )
    with pytest.raises(ContractError):
        runner.run(
            plan.application_id,
            request.operation_id,
            owner_id="worker",
            evidence=evidence,
            guard=guard,
            adapter=adapter,
            emit=lambda *_: None,
        )
    assert adapter.calls == ["apply_isolation"]
    assert (
        operations.get(plan.application_id, request.operation_id).state.status.value
        == "recovery_required"
    )


def test_completed_response_has_atomic_receipt_and_released_execution_owner(response):
    result = run(response, ResponseAdapter())
    lifecycle, operations, _, _, plan, _, request = response
    current, proof = operations.get_response_completion(
        plan.application_id, request.operation_id
    )
    assert proof.fingerprint == result["completion_digest"]
    assert current.state.status.value == "response_verified"
    with lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT owner_id,token,valid_until FROM sova_control.app_execution"
        ).fetchone() == (None, None, None)
        assert conn.execute(
            "SELECT proof_digest FROM sova_control.execution_events WHERE action='released'"
        ).fetchone() == (proof.fingerprint,)


def test_lost_completion_acknowledgement_recovers_receipt_without_replaying_effects(
    response, monkeypatch
):
    operations = response[1]
    original = operations.finish_response

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("Simulated lost COMMIT acknowledgement")

    monkeypatch.setattr(operations, "finish_response", lost)
    adapter = ResponseAdapter()
    result = run(response, adapter)
    assert (
        result["status"] == "response_verified"
        and result["completion_recovered_read_only"]
    )
    assert len(adapter.calls) == 4


def test_release_failure_rolls_back_receipt_terminal_state_and_outbox_suppression(
    response, monkeypatch
):
    def fail_release(*_):
        raise OSError("Simulated failure before ownership release")

    monkeypatch.setattr(PostgresExecutionOwnership, "_release_locked", fail_release)
    adapter = ResponseAdapter()
    with pytest.raises(OSError):
        run(response, adapter)
    assert len(adapter.calls) == 4
    lifecycle, operations, _, _, plan, _, request = response
    assert (
        operations.get(plan.application_id, request.operation_id).state.status.value
        == "recovery_required"
    )
    with lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.security_response_completions"
        ).fetchone() == (0,)
        assert conn.execute(
            "SELECT suppressed_at FROM sova_control.operation_outbox"
        ).fetchone() == (None,)
        assert conn.execute(
            "SELECT owner_id IS NOT NULL FROM sova_control.app_execution"
        ).fetchone() == (True,)


@pytest.mark.parametrize("change", ["approval", "hold"])
def test_late_revocation_or_new_incident_never_becomes_completed_response(
    response, change
):
    lifecycle, operations, holds, binding, plan, _, request = response

    def emit(action, _):
        if action != "switch_route":
            return
        if change == "approval":
            lifecycle.revoke_approval(
                plan.application_id,
                request.approval_id,
                expected_revision=1,
                actor_id="security-operator",
            )
        else:
            holds.open_hold(
                SecurityHold(
                    "late-incident",
                    binding.target_resource.scope,
                    "detector",
                    "late violation",
                    datetime.now(UTC),
                )
            )

    with pytest.raises(ContractError):
        run(response, ResponseAdapter(), emit=emit)
    assert (
        operations.get(plan.application_id, request.operation_id).state.status.value
        == "recovery_required"
    )
    with lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.security_response_completions"
        ).fetchone() == (0,)


def test_expired_owner_cannot_publish_terminal_or_recovery_state(response, monkeypatch):
    from sova.ports.operations import LeaseLost

    lifecycle, operations, _, _, plan, _, request = response
    original = operations.finish_response

    def expire(*args, **kwargs):
        with lifecycle.transaction() as conn:
            conn.execute(
                "UPDATE sova_control.app_execution SET valid_until=clock_timestamp()-interval '1 second'"
            )
        return original(*args, **kwargs)

    monkeypatch.setattr(operations, "finish_response", expire)
    with pytest.raises(LeaseLost):
        run(response, ResponseAdapter())
    assert (
        operations.get(plan.application_id, request.operation_id).state.status.value
        == "verifying"
    )
    with lifecycle.transaction() as conn:
        assert conn.execute(
            "SELECT count(*) FROM sova_control.security_response_completions"
        ).fetchone() == (0,)


def test_generic_transition_cannot_bypass_completion_receipt(response):
    from sova.domain.workflows import OperationStatus

    _, operations, _, _, plan, _, request = response
    with pytest.raises(ContractError, match="atomic"):
        operations.advance(
            plan.application_id,
            request.operation_id,
            OperationStatus.RESPONSE_VERIFIED,
            expected_revision=1,
            actor_id="worker",
        )


@pytest.mark.parametrize(
    "query",
    [
        "UPDATE sova_control.security_response_completions SET document='{}'",
        "DELETE FROM sova_control.security_response_completions",
    ],
)
def test_runtime_cannot_rewrite_or_delete_completion_history(response, query):
    run(response, ResponseAdapter())
    lifecycle = response[0]
    with lifecycle.transaction() as conn:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            conn.execute(query)


def test_completion_history_does_not_cross_tenant_or_app(response):
    from sova.adapters.postgres_plans import PostgresLifecycleRepository
    from sova.ports.plans import RecordNotFound

    run(response, ResponseAdapter())
    lifecycle, operations, _, _, plan, _, request = response
    other = PostgresOperationRepository(
        PostgresLifecycleRepository(lifecycle.connect, tenant_id="other-tenant")
    )
    for repository, app in [(other, plan.application_id), (operations, "other-app")]:
        with pytest.raises(RecordNotFound):
            repository.get_response_completion(app, request.operation_id)
    with lifecycle.connect() as conn:
        # RLS without a tenant context discloses no completion rows.
        assert conn.execute(
            "SELECT count(*) FROM sova_control.security_response_completions"
        ).fetchone() == (0,)


def test_completion_worker_can_lock_but_cannot_create_revoke_or_restore_approval(
    response, postgres_database
):
    from uuid import uuid4
    from psycopg import sql
    from sova.adapters.postgres_plans import PostgresLifecycleRepository

    dsn, _ = postgres_database
    role = "sova_completion_" + uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
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
            sql.SQL("GRANT SELECT ON ALL TABLES IN SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        admin.execute(
            sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA sova_control TO {}").format(
                sql.Identifier(role)
            )
        )
        for table in (
            "app_execution",
            "effects",
            "effect_events",
            "execution_events",
            "operation_events",
            "security_response_completions",
        ):
            admin.execute(
                sql.SQL("GRANT INSERT ON sova_control.{} TO {}").format(
                    sql.Identifier(table), sql.Identifier(role)
                )
            )
        for table, columns in (
            (
                "app_execution",
                "operation_id,owner_id,token,epoch,valid_until,mode,proof_digest,proof_valid_until,recovery_effects",
            ),
            ("effects", "status,revision,observation_document"),
            ("operations", "status,revision,updated_at"),
            ("operation_outbox", "suppressed_at,lease_token,lease_until,owner_id"),
            ("approvals", "lock_guard"),
        ):
            admin.execute(
                sql.SQL("GRANT UPDATE({}) ON sova_control.{} TO {}").format(
                    sql.SQL(columns), sql.Identifier(table), sql.Identifier(role)
                )
            )
    original = response[0]
    worker = PostgresLifecycleRepository(
        lambda: psycopg.connect(dsn, user=role),
        tenant_id=original.tenant_id,
        clock=lambda: datetime.now(UTC),
    )
    scoped_response = (worker, PostgresOperationRepository(worker), *response[2:])
    result = run(scoped_response, ResponseAdapter())
    assert result["status"] == "response_verified"
    for update in (
        "UPDATE sova_control.approvals SET revision=1,revoked_at=NULL",
        "UPDATE sova_control.approvals SET revoked_at=clock_timestamp()",
        "UPDATE sova_control.approvals SET document='{}'",
        "DELETE FROM sova_control.approvals",
        "INSERT INTO sova_control.approvals DEFAULT VALUES",
    ):
        with worker.transaction() as conn:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                conn.execute(update)
    with worker.transaction() as conn:
        with pytest.raises(psycopg.errors.GeneratedAlways):
            conn.execute("UPDATE sova_control.approvals SET lock_guard=true")
