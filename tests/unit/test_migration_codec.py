from datetime import timedelta
from copy import deepcopy

import pytest

from sova.adapters.migration_codec import decode_migration_program
from sova.application.migration_phases import (
    PhaseAction,
    MigrationPhase,
    phase_action_digest,
)
from sova.domain.contracts import ContractError
from sova.domain.evidence import RevisionSet
from sova.domain.migration_program import six_area_program
from dataclasses import replace


@pytest.fixture
def program(scope, now):
    return six_area_program(
        scope,
        replace(scope, environment_id="destination"),
        RevisionSet(*("a" * 64, "b" * 64, "c" * 64, "d" * 64)),
        issued_at=now,
        valid_until=now + timedelta(minutes=5),
    )


def test_program_roundtrip_preserves_complete_digest(program):
    decoded = decode_migration_program(program.document)
    assert decoded == program and decoded.fingerprint == program.fingerprint


@pytest.mark.parametrize(
    "change",
    [
        "schema",
        "bool_schema",
        "bool_gate",
        "missing",
        "weaken",
        "duplicate",
        "extra",
        "scope",
        "oversize",
    ],
)
def test_invalid_or_weakened_stored_program_cannot_be_restored(program, change):
    document = deepcopy(program.document)
    if change == "schema":
        document["schema_version"] = 2
    if change == "bool_schema":
        document["schema_version"] = True
    if change == "bool_gate":
        document["requirements"][0]["gate"] = True
    if change == "missing":
        document["requirements"].pop()
    if change == "weaken":
        document["requirements"][0]["required"] = False
    if change == "duplicate":
        document["requirements"].append(document["requirements"][0])
    if change == "extra":
        document["allow_execution"] = True
    if change == "scope":
        document["target_scope"]["tenant_id"] = "another"
    if change == "oversize":
        document["requirements"] *= 20
    with pytest.raises(ContractError):
        decode_migration_program(document)


def test_registry_digest_ignores_order_but_binds_all_phase_actions():
    a = PhaseAction("db", "pause_writes", MigrationPhase.QUIESCE)
    b = PhaseAction("edge", "switch", MigrationPhase.CUTOVER)
    assert phase_action_digest((a, b)) == phase_action_digest((b, a))
    assert phase_action_digest((a,)) != phase_action_digest((a, b))
    assert phase_action_digest(
        (replace(a, phase=MigrationPhase.PREPARE), b)
    ) != phase_action_digest((a, b))
