import sqlite3
from dataclasses import replace
from datetime import timedelta

import pytest

from support import permit_for
from sova.adapters.sqlite_effects import EffectConflict, SQLiteEffectJournal
from sova.application.effects import EffectExecutor, UncertainEffect
from sova.domain.contracts import ContractError, EffectStatus


@pytest.fixture
def journal(tmp_path):
    db = sqlite3.connect(tmp_path / "effects.sqlite")
    yield SQLiteEffectJournal(db)
    db.close()


def engine(journal, now):
    return EffectExecutor(journal, authorize=lambda *_: None, clock=lambda: now)


def test_claim_audit_failure_rolls_back_before_external_call(
    journal, command, adapter, now
):
    original = journal._event

    def fail_claim(command, revision, status, observation_json=None):
        if status == EffectStatus.IN_FLIGHT:
            raise sqlite3.OperationalError("injected journal full")
        return original(command, revision, status, observation_json)

    journal._event = fail_claim
    with pytest.raises(sqlite3.OperationalError):
        engine(journal, now).execute(command, permit_for(command), adapter)
    assert adapter.calls == []
    assert journal.get(command).status == EffectStatus.PREPARED
    assert journal.db.execute(
        "SELECT count(*) FROM sova_effect_events_v1"
    ).fetchone() == (1,)
    journal._event = original
    assert (
        engine(journal, now).execute(command, permit_for(command), adapter).status
        == EffectStatus.APPLIED
    )
    assert len(adapter.calls) == 1


def test_success_record_loss_never_causes_reapplication(journal, command, adapter, now):
    original = journal.transition

    def lose_completion(command, revision, expected, status, observation=None):
        if status == EffectStatus.APPLIED:
            raise sqlite3.OperationalError("injected completion write failure")
        return original(command, revision, expected, status, observation)

    journal.transition = lose_completion
    runner = engine(journal, now)
    with pytest.raises(sqlite3.OperationalError):
        runner.execute(command, permit_for(command), adapter)
    assert journal.get(command).status == EffectStatus.IN_FLIGHT
    with pytest.raises(UncertainEffect):
        runner.execute(command, permit_for(command), adapter)
    assert len(adapter.calls) == 1
    journal.transition = original
    assert (
        runner.reconcile(command, permit_for(command), adapter).status
        == EffectStatus.APPLIED
    )
    assert len(adapter.calls) == 1


@pytest.mark.parametrize("wrong", ["scope", "command", "time"])
def test_misbound_readback_never_completes_effect(
    journal, command, adapter, now, wrong
):
    readback = adapter.readback

    def forged(cmd, when):
        actual = readback(cmd, when)
        if wrong == "scope":
            return replace(actual, scope=replace(cmd.scope, tenant_id="other"))
        if wrong == "command":
            return replace(actual, command_digest="f" * 64)
        return replace(actual, observed_at=when - timedelta(seconds=1))

    adapter.readback = forged
    with pytest.raises(UncertainEffect):
        engine(journal, now).execute(command, permit_for(command), adapter)
    assert journal.get(command).status == EffectStatus.UNKNOWN


def test_cancellation_only_releases_a_never_claimed_intent(
    journal, command, adapter, now
):
    runner = engine(journal, now)
    journal.reserve(command)
    result = runner.cancel_prepared(command, permit_for(command), adapter)
    assert result.status == EffectStatus.NOT_APPLIED and not adapter.calls
    with pytest.raises(ContractError):
        runner.cancel_prepared(command, permit_for(command), adapter)
    next_command = replace(command, idempotency_key="new-approved-command")
    assert (
        runner.execute(next_command, permit_for(next_command), adapter).status
        == EffectStatus.APPLIED
    )
    with pytest.raises(ContractError):
        runner.cancel_prepared(next_command, permit_for(next_command), adapter)


def test_journal_does_not_commit_someone_elses_transaction(journal, command):
    journal.db.execute("CREATE TABLE unrelated(value TEXT)")
    journal.db.execute("INSERT INTO unrelated VALUES('not committed')")
    with pytest.raises(EffectConflict, match="transaction boundary"):
        journal.reserve(command)
    assert journal.db.in_transaction
    journal.db.rollback()
    assert journal.db.execute("SELECT count(*) FROM unrelated").fetchone() == (0,)
