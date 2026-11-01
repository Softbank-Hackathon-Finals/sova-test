"""Strict, bounded reconstruction of immutable six-area programs."""

from datetime import datetime

from sova.adapters.plan_codec import fields
from sova.domain.contracts import ContractError, ResourceScope, canonical_json
from sova.domain.evidence import Gate, RevisionSet, VerificationObligation
from sova.domain.migration_program import (
    MigrationArea,
    MigrationProgram,
    ProgramRequirement,
)


def decode_migration_program(value):
    fields(
        value,
        (
            "schema_version",
            "source_scope",
            "target_scope",
            "revisions",
            "issued_at",
            "valid_until",
            "requirements",
        ),
    )
    canonical_json(value, limit=131072)
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise ContractError("Unsupported stored program schema")
    requirements = value["requirements"]
    if type(requirements) is not list or not 1 <= len(requirements) <= 256:
        raise ContractError("Bounded stored program requirements required")
    scopes = ("tenant_id", "application_id", "environment_id", "resource_id")
    fields(value["source_scope"], scopes)
    fields(value["target_scope"], scopes)
    fields(value["revisions"], ("source", "configuration", "policy", "environment"))
    rows = []
    try:
        for r in requirements:
            fields(
                r, ("area", "id", "scope", "gate", "verifier", "required", "objective")
            )
            fields(r["scope"], scopes)
            if type(r["gate"]) is not int:
                raise ContractError("Stored program gate must be an integer")
            rows.append(
                ProgramRequirement(
                    MigrationArea(r["area"]),
                    VerificationObligation(
                        r["id"],
                        ResourceScope(**r["scope"]),
                        Gate(r["gate"]),
                        r["verifier"],
                        r["required"],
                    ),
                    r["objective"],
                )
            )
        return MigrationProgram(
            ResourceScope(**value["source_scope"]),
            ResourceScope(**value["target_scope"]),
            RevisionSet(**value["revisions"]),
            datetime.fromisoformat(value["issued_at"]),
            datetime.fromisoformat(value["valid_until"]),
            tuple(rows),
        )
    except (ValueError, TypeError, KeyError) as exc:
        raise ContractError("Invalid stored migration program") from exc
