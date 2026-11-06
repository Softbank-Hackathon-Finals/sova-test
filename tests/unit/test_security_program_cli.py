from dataclasses import replace
from datetime import timedelta
import json

from sova.interfaces.cli import main
from sova.interfaces.security_program import example_program
from sova_security.adapters.modernization_codec import encode
from sova_security.domain.security_program import ProgramInput, ProgramKind


def test_catalog_traces_both_documents(capsys):
    assert main(["security-program-catalog"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["catalog_version"] == "security-modernization.v1"
    assert len(data["checks"]) == 22


def test_example_has_no_fabricated_passing_evidence(capsys, tmp_path):
    assert main(["security-program-example"]) == 0
    example = capsys.readouterr().out
    path = tmp_path / "program.json"
    path.write_text(example, encoding="utf-8")
    for phase in ("preflight", "postflight"):
        assert main(["security-program-check", str(path), "--phase", phase]) == 1
        report = json.loads(capsys.readouterr().out)
        assert report["authenticated"] is False
        assert report["execution_authorized"] is False
        assert report["checks_passed"] is False
        assert all(row["result"] == "unknown" for row in report["review"]["results"])


def test_expired_program_and_extra_json_fields_are_rejected(tmp_path, now, capsys):
    example = example_program(ProgramKind.PATCH, now - timedelta(days=365))
    path = tmp_path / "program.json"
    path.write_text(encode(example), encoding="utf-8")
    assert main(["security-program-check", str(path)]) == 2
    capsys.readouterr()
    body = json.loads(encode(example))
    body["grant_production_access"] = True
    path.write_text(json.dumps(body), encoding="utf-8")
    assert main(["security-program-check", str(path)]) == 2


def test_example_registration_is_bound_to_full_subject(now):
    value = example_program(ProgramKind.MIGRATION, now)
    from sova_security.contracts.commands import ContractError
    import pytest

    with pytest.raises(ContractError):
        ProgramInput(replace(value.program, subject_digest="0" * 64), ())
