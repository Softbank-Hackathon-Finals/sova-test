from datetime import datetime

from sova.adapters.plan_codec import fields
from sova.domain.contracts import (
    ContractError,
    EffectObservation,
    EffectStatus,
    ResourceScope,
    canonical_json,
)
from sova.domain.migration_phases import MigrationPhase
from sova.domain.phase_completion import PhaseCompletion


def decode_phase_completion(value):
    fields(
        value,
        (
            "schema_version",
            "tenant_id",
            "application_id",
            "operation_id",
            "plan_digest",
            "program_digest",
            "phase",
            "epoch",
            "owner_id",
            "verified_until",
            "observations",
        ),
    )
    canonical_json(value, limit=262144)
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or type(value["observations"]) is not list
        or not 1 <= len(value["observations"]) <= 128
    ):
        raise ContractError("Invalid stored phase receipt schema")
    observations = []
    try:
        for o in value["observations"]:
            fields(o, ("scope", "command_digest", "status", "observed_at", "evidence"))
            fields(
                o["scope"],
                ("tenant_id", "application_id", "environment_id", "resource_id"),
            )
            observations.append(
                EffectObservation(
                    ResourceScope(**o["scope"]),
                    o["command_digest"],
                    EffectStatus(o["status"]),
                    datetime.fromisoformat(o["observed_at"]),
                    canonical_json(o["evidence"]),
                )
            )
        return PhaseCompletion(
            value["tenant_id"],
            value["application_id"],
            value["operation_id"],
            value["plan_digest"],
            value["program_digest"],
            MigrationPhase(value["phase"]),
            value["epoch"],
            value["owner_id"],
            datetime.fromisoformat(value["verified_until"]),
            tuple(observations),
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise ContractError("Invalid stored phase receipt") from exc
