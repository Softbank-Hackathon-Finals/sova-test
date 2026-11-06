import json
import os

import pytest

from sova.interfaces.cli import main


def test_offline_plan_is_available_without_cloud_login_or_input_files(capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Offline intake must not execute cloud or shell commands")
    import subprocess
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert main(["security-intake-plan"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert len(result["required_tests"]) == 20
    assert not result["authorizes_execution"] and not result["live_verified"]
    assert result["reported_counts"]["target"] == {"NOT_PROVIDED": 20}


def test_private_or_missing_input_errors_do_not_echo_path_or_contents(capsys, tmp_path):
    private = tmp_path / "sensitive-operator-identifier.json"
    assert main(["security-intake-plan", "--control-run", str(private)]) == 2
    text = str(capsys.readouterr())
    assert "sensitive-operator" not in text


@pytest.mark.skipif(not hasattr(os, "geteuid") or not hasattr(os, "O_NOFOLLOW"), reason="Mac/Linux owner-check contract")
def test_owner_checked_status_intake_never_claims_positive_detection(capsys, tmp_path):
    from datetime import UTC, datetime
    now = int(datetime.now(UTC).timestamp() * 1000)
    path = tmp_path / "status.json"
    path.write_text(json.dumps({"kind": "source_status", "source": "aws_security_hub",
        "environment_id": "private-environment", "state": "FAILED", "checked_time": now,
        "error_code": "INGESTION_GAP"}), encoding="utf-8")
    path.chmod(0o600)
    assert main(["security-intake-plan", "--source-status", str(path)]) == 0
    result = json.loads(capsys.readouterr().out)
    status = result["source_statuses"][0]
    assert status["coverage"] == "GAP_OR_STALE" and status["positive_finding"] == "NOT_ESTABLISHED"
    assert "private-environment" not in json.dumps(result)
    path.chmod(0o644)
    assert main(["security-intake-plan", "--source-status", str(path)]) == 2
    capsys.readouterr()
    path.chmod(0o600)
    link = tmp_path / "status-link.json"
    link.symlink_to(path)
    assert main(["security-intake-plan", "--source-status", str(link)]) == 2
    assert "private-environment" not in str(capsys.readouterr())
