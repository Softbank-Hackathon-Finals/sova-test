import sqlite3
import threading
from dataclasses import replace
from datetime import timedelta

import pytest

from support import permit_for
from sova.adapters.sqlite_effects import EffectConflict, SQLiteEffectJournal
from sova.application.effects import EffectExecutor, UncertainEffect
from sova.domain.contracts import ContractError, EffectStatus


@pytest.fixture
def journal(tmp_path):
    connection = sqlite3.connect(tmp_path / "effects.sqlite", check_same_thread=False)
    store = SQLiteEffectJournal(connection)
    yield store
    connection.close()


def executor(journal, now, authorize=lambda *_args: None):
    return EffectExecutor(journal, authorize=authorize, clock=lambda: now)


def test_intent_and_claim_are_durable_before_apply(journal, command, adapter, now):
    def before_apply(actual):
        record = journal.get(actual)
        assert record.status == EffectStatus.IN_FLIGHT and record.revision == 2
        other = sqlite3.connect(
            journal.db.execute("PRAGMA database_list").fetchone()[2]
        )
        try:
            assert other.execute("SELECT status FROM sova_effects_v1").fetchone() == (
                "in_flight",
            )
        finally:
            other.close()

    adapter.before_apply = before_apply
    result = executor(journal, now).execute(command, permit_for(command), adapter)
    assert result.status == EffectStatus.APPLIED and result.revision == 3
    assert result.observation.evidence == {"blocked": True}


def test_duplicate_success_is_historical_receipt_without_reapplying(
    journal, command, adapter, now
):
    engine = executor(journal, now)
    one = engine.execute(command, permit_for(command), adapter)
    two = engine.execute(command, permit_for(command), adapter)
    assert one == two and len(adapter.calls) == 1 and adapter.reads == 1


def test_same_key_different_input_is_rejected(journal, command, adapter, now):
    engine = executor(journal, now)
    engine.execute(command, permit_for(command), adapter)
    changed = replace(command, parameters_json='{"blocked":false}')
    with pytest.raises(EffectConflict, match="different command"):
        engine.execute(changed, permit_for(changed), adapter)
    assert len(adapter.calls) == 1


def test_lost_response_remains_unknown_and_cannot_be_replayed(
    journal, command, adapter, now
):
    def lost(_command):
        raise TimeoutError("response disappeared after successful mutation")

    adapter.after_apply = lost
    engine = executor(journal, now)
    with pytest.raises(UncertainEffect):
        engine.execute(command, permit_for(command), adapter)
    assert adapter.blocked and journal.get(command).status == EffectStatus.UNKNOWN
    with pytest.raises(UncertainEffect):
        engine.execute(command, permit_for(command), adapter)
    assert len(adapter.calls) == 1
    recovered = engine.reconcile(command, permit_for(command), adapter)
    assert recovered.status == EffectStatus.APPLIED and len(adapter.calls) == 1
    events = journal.db.execute(
        "SELECT status FROM sova_effect_events_v1 ORDER BY seq"
    ).fetchall()
    assert events == [
        ("prepared",),
        ("in_flight",),
        ("unknown",),
        ("confirmed_applied",),
    ]


def test_unresolved_result_blocks_other_command_for_same_resource(
    journal, command, adapter, now
):
    journal.reserve(command)
    different = replace(command, operation_id="operation-2", idempotency_key="other")
    with pytest.raises(EffectConflict, match="Unresolved"):
        executor(journal, now).execute(different, permit_for(different), adapter)
    assert adapter.calls == []


def test_readback_mismatch_is_unknown_not_a_retry_permission(
    journal, command, adapter, now
):
    adapter.after_apply = lambda _cmd: setattr(adapter, "blocked", False)
    engine = executor(journal, now)
    with pytest.raises(UncertainEffect):
        engine.execute(command, permit_for(command), adapter)
    record = engine.reconcile(command, permit_for(command), adapter)
    assert record.status == EffectStatus.UNKNOWN and len(adapter.calls) == 1


def test_restart_does_not_reissue_an_inflight_effect(journal, command, adapter, now):
    prepared = journal.reserve(command)
    journal.transition(
        command, prepared.revision, EffectStatus.PREPARED, EffectStatus.IN_FLIGHT
    )
    connection = sqlite3.connect(
        journal.db.execute("PRAGMA database_list").fetchone()[2]
    )
    try:
        restarted = SQLiteEffectJournal(connection)
        with pytest.raises(UncertainEffect):
            executor(restarted, now).execute(command, permit_for(command), adapter)
        assert adapter.calls == []
        adapter.blocked = True
        assert (
            executor(restarted, now)
            .reconcile(command, permit_for(command), adapter)
            .status
            == EffectStatus.APPLIED
        )
    finally:
        connection.close()


def test_holds_expiry_scope_and_adapter_fail_before_effects(
    journal, command, adapter, now
):
    engine = executor(journal, now)
    permits = [
        permit_for(command, security_hold=True),
        permit_for(command, expires_at=now),
        permit_for(command, fencing_epoch=2),
    ]
    for permit in permits:
        with pytest.raises(ContractError):
            engine.execute(command, permit, adapter)
    adapter.adapter_id = "different"
    with pytest.raises(ContractError):
        engine.execute(command, permit_for(command), adapter)
    assert adapter.calls == []
    assert journal.db.execute("SELECT count(*) FROM sova_effects_v1").fetchone() == (0,)


def test_revocation_between_claim_and_apply_is_confirmed_not_issued(
    journal, command, adapter, now
):
    checks = 0

    def revoke(*_args):
        nonlocal checks
        checks += 1
        if checks == 2:
            raise ContractError("approval revoked")

    with pytest.raises(ContractError, match="revoked"):
        executor(journal, now, revoke).execute(command, permit_for(command), adapter)
    assert (
        adapter.calls == [] and journal.get(command).status == EffectStatus.NOT_APPLIED
    )


def test_expired_command_can_be_read_only_reconciled(journal, command, adapter, now):
    prepared = journal.reserve(command)
    journal.transition(
        command, prepared.revision, EffectStatus.PREPARED, EffectStatus.IN_FLIGHT
    )
    adapter.blocked = True
    later = command.expires_at + timedelta(seconds=1)
    permit = permit_for(
        command, expires_at=later + timedelta(minutes=1), security_hold=True
    )
    result = executor(journal, later).reconcile(command, permit, adapter)
    assert result.status == EffectStatus.APPLIED and adapter.calls == []


def test_stale_claim_revision_cannot_complete_another_execution(journal, command, now):
    journal.reserve(command)
    journal.transition(command, 1, EffectStatus.PREPARED, EffectStatus.IN_FLIGHT)
    with pytest.raises(EffectConflict):
        journal.transition(command, 1, EffectStatus.IN_FLIGHT, EffectStatus.UNKNOWN)
    assert journal.get(command).status == EffectStatus.IN_FLIGHT


def test_concurrent_connections_cannot_both_apply(journal, command, adapter, now):
    entered, release = threading.Event(), threading.Event()
    result = []

    def block(_command):
        entered.set()
        assert release.wait(3)

    adapter.before_apply = block
    engine = executor(journal, now)

    def first():
        try:
            result.append(engine.execute(command, permit_for(command), adapter))
        except Exception as error:
            result.append(error)

    thread = threading.Thread(target=first)
    thread.start()
    assert entered.wait(3)
    other = sqlite3.connect(journal.db.execute("PRAGMA database_list").fetchone()[2])
    try:
        with pytest.raises(UncertainEffect):
            executor(SQLiteEffectJournal(other), now).execute(
                command, permit_for(command), adapter
            )
    finally:
        release.set()
        thread.join(timeout=3)
        other.close()
    assert len(result) == 1 and not isinstance(result[0], Exception)
    assert len(adapter.calls) == 1
