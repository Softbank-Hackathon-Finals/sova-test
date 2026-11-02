"""A child process exits after a durable test effect, before recording success.

The effect is a temporary local file, never an AWS or application mutation.
"""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from support import IngressAdapter, permit_for
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor, UncertainEffect
from sova.domain.contracts import EffectStatus

import pytest


def test_real_process_death_preserves_intent_and_prevents_replay(
    tmp_path, command, now
):
    command_file = tmp_path / "command.json"
    command_file.write_text(json.dumps(command.document))
    db_path, effect_path = tmp_path / "effects.sqlite", tmp_path / "effect.txt"
    core_path = Path(__file__).resolve().parents[3] / "src"
    script = """
import json, os, sqlite3, sys
from datetime import datetime
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from sova.domain.contracts import EffectCommand, ExecutionPermit
from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
command=EffectCommand.from_document(json.loads(Path(sys.argv[2]).read_text()))
class CrashingAdapter:
    adapter_id="test-ingress"
    def validate(self, command): pass
    def apply(self, command):
        with open(sys.argv[4], "a") as effect:
            effect.write("once\\n"); effect.flush(); os.fsync(effect.fileno())
        os._exit(42)
    def readback(self, command, now): raise AssertionError("must exit before readback")
db=sqlite3.connect(sys.argv[3])
permit=ExecutionPermit(command.scope, command.operation_id, command.plan_digest,
                       command.fingerprint, command.fencing_epoch, command.expires_at)
EffectExecutor(SQLiteEffectJournal(db), authorize=lambda *_:None,
    clock=lambda:datetime.fromisoformat(sys.argv[5])).execute(command,permit,CrashingAdapter())
"""
    child = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            script,
            str(core_path),
            str(command_file),
            str(db_path),
            str(effect_path),
            now.isoformat(),
        ],
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert child.returncode == 42, child.stderr
    assert effect_path.read_text() == "once\n"
    with sqlite3.connect(db_path) as connection:
        journal = SQLiteEffectJournal(connection)
        assert journal.get(command).status == EffectStatus.IN_FLIGHT
        adapter = IngressAdapter()
        adapter.blocked = True
        engine = EffectExecutor(journal, authorize=lambda *_: None, clock=lambda: now)
        with pytest.raises(UncertainEffect):
            engine.execute(command, permit_for(command), adapter)
        assert adapter.calls == [] and effect_path.read_text() == "once\n"
        result = engine.reconcile(command, permit_for(command), adapter)
        assert result.status == EffectStatus.APPLIED
        assert adapter.calls == [] and effect_path.read_text() == "once\n"
