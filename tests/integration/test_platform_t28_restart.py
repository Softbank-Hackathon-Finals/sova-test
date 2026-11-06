"""Real pinned T28 + child process death; zero real operator/cloud commands."""

from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from sova.adapters.platform_t28 import DurableT28Port, OperatorBinding
from sova.domain.contracts import ContractError, EffectStatus, canonical_json
from support import permit_for
from t28_support import runtime


@pytest.fixture
def platform():
    root = os.environ.get("SOVA_T28_PLATFORM_SOURCE")
    if not root:
        pytest.skip("Explicit clean qualified platform source required")
    return Path(root).resolve(strict=True)


@pytest.mark.parametrize("phase,exit_code,expected", [
    ("before-effect", 41, EffectStatus.IN_FLIGHT),
    ("after-effect", 42, EffectStatus.IN_FLIGHT),
    ("after-receipt", 43, EffectStatus.APPLIED),
])
def test_actual_process_exit_before_jsonl_does_not_reissue_operator(platform, tmp_path, phase, exit_code, expected):
    code = "from t28_support import runtime; import sys; d,a,p,b,db=runtime(*sys.argv[1:]); sys.exit(p.run(d,a))"
    paths = [str(Path(__file__).parents[1]), str(Path(__file__).parents[2] / "src")]
    env = os.environ | {"PYTHONPATH": os.pathsep.join(paths + [os.environ.get("PYTHONPATH", "")]), "PYTHONDONTWRITEBYTECODE": "1"}
    child = subprocess.run([sys.executable, "-c", code, str(platform), str(tmp_path), phase],
                           env=env, capture_output=True, timeout=20)
    assert child.returncode == exit_code, child.stderr.decode()
    assert len((tmp_path / "run.jsonl").read_text().splitlines()) == 1
    driver, args, port, binding, db = runtime(platform, tmp_path)
    try:
        assert port.executor.journal.get(binding.command).status == expected
        assert port.run(driver, args) == (0 if expected == EffectStatus.APPLIED else 3)
        effect = tmp_path / "effect.txt"
        assert (effect.read_text() if effect.exists() else "") == ("" if phase == "before-effect" else "once\n")
        if phase == "after-effect":
            # Explicit read-only reconciliation, then descriptive JSONL resolution.
            record = port.executor.reconcile(binding.command, binding.permit, binding.adapter)
            assert record.status == EffectStatus.APPLIED
            args.step, args.by, args.note, args.status = "s4-fault-inject", "test-reconciler", "synthetic readback", "done"
            assert driver.cmd_mark(args, "resolved") == 0
            assert port.run(driver, args) == 0
            assert effect.read_text() == "once\n"
    finally:
        db.close()


@pytest.mark.parametrize("fault", ["argv", "plan", "application", "diff", "image", "revoked", "forged-jsonl", "profile", "reader-command", "header-profile"])
def test_changed_registration_or_authority_never_issues_effect(platform, tmp_path, fault):
    driver, args, port, binding, db = runtime(platform, tmp_path, deny=fault == "revoked")
    try:
        if fault in {"diff", "image"}:
            # A changed command under the same durable key cannot replace an accepted intent.
            port.executor.journal.reserve(binding.command)
            parameters = binding.command.parameters
            parameters[fault + "_digest"] = ("sha256:" if fault == "image" else "") + "d" * 64
            command = replace(binding.command, parameters_json=canonical_json(parameters))
            port = DurableT28Port(platform, args.plan_id, args.application_id,
                (OperatorBinding(command, permit_for(command), binding.adapter),), port.executor)
        elif fault == "argv":
            args.receipts = "unused"
            driver.STEPS = (replace(driver.STEPS[0], command=("unregistered-effect",)),)
        elif fault in {"plan", "application"}:
            setattr(args, fault + "_id", "different")
        elif fault == "profile":
            args.profile = "real"
        elif fault == "reader-command":
            args.plan_state_command = ["unregistered-subprocess"]
        elif fault == "header-profile":
            head = driver.header(args)
            head["profile"] = "real"
            Path(args.record).write_text(json.dumps(head) + "\n")
        elif fault == "forged-jsonl":
            Path(args.record).write_text(json.dumps(driver.header(args)) + "\n" +
                json.dumps({"step": "s4-fault-inject", "status": "done"}) + "\n")
        if fault in {"diff", "image", "revoked"}:
            assert port.run(driver, args) == 3
        else:
            with pytest.raises((ContractError, RuntimeError)):
                port.run(driver, args)
        assert not (tmp_path / "effect.txt").exists()
    finally:
        db.close()


def test_new_record_path_does_not_reset_durable_completion(platform, tmp_path):
    driver, args, port, _, db = runtime(platform, tmp_path)
    try:
        assert port.run(driver, args) == 0
        args.record = str(tmp_path / "different-run.jsonl")
        assert port.run(driver, args) == 0
        assert (tmp_path / "effect.txt").read_text() == "once\n"
    finally:
        db.close()


def test_two_processes_cannot_dispatch_the_same_operator(platform, tmp_path):
    code = "from t28_support import runtime; import sys; d,a,p,b,db=runtime(*sys.argv[1:]); sys.exit(p.run(d,a))"
    paths = [str(Path(__file__).parents[1]), str(Path(__file__).parents[2] / "src")]
    env = os.environ | {"PYTHONPATH": os.pathsep.join(paths + [os.environ.get("PYTHONPATH", "")]), "PYTHONDONTWRITEBYTECODE": "1"}
    first = subprocess.Popen([sys.executable, "-c", code, str(platform), str(tmp_path), "pause-before-effect"],
                             env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        deadline = time.monotonic() + 10
        while not (tmp_path / "claimed").exists():
            assert first.poll() is None and time.monotonic() < deadline
            time.sleep(0.02)
        second = subprocess.run([sys.executable, "-c", code, str(platform), str(tmp_path), "normal"],
                                env=env, capture_output=True, timeout=10)
        assert second.returncode == 3, second.stderr.decode()
        assert not (tmp_path / "effect.txt").exists()
        (tmp_path / "release").touch()
        _, error = first.communicate(timeout=10)
        assert first.returncode == 0, error.decode()
        assert (tmp_path / "effect.txt").read_text() == "once\n"
    finally:
        if first.poll() is None:
            first.kill()
        first.communicate(timeout=5)
