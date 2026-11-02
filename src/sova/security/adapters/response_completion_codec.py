from datetime import datetime
from sova.adapters.registration.graph_codec import exact
from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    EffectObservation,
    EffectStatus,
    canonical_json,
)
from sova.security.domain.response_completion import ResponseCompletion


def decode_response_completion(data, plan):
    try:
        exact(
            data,
            (
                "schema_version",
                "scope",
                "operation_id",
                "plan_digest",
                "epoch",
                "owner_id",
                "command_digest",
                "observed_at",
                "verified_until",
                "evidence",
            ),
        )
        exact(
            data["scope"],
            ("tenant_id", "application_id", "environment_id", "resource_id"),
        )
        if (
            type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or data["plan_digest"] != plan.fingerprint
        ):
            raise ContractError("Completion schema or plan mismatch")
        command = plan.command(
            "switch_route", operation_id=data["operation_id"], epoch=data["epoch"]
        )
        observation = EffectObservation(
            ResourceScope(**data["scope"]),
            data["command_digest"],
            EffectStatus.APPLIED,
            datetime.fromisoformat(data["observed_at"]),
            canonical_json(data["evidence"]),
        )
        return ResponseCompletion(
            command,
            observation,
            data["owner_id"],
            datetime.fromisoformat(data["verified_until"]),
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Invalid response completion") from exc
