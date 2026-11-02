"""Versioned, exact protection policy codec. Provider raw payloads are forbidden."""

from datetime import datetime
from sova.adapters.registration.graph_codec import exact
from sova.domain.contracts import ContractError, ResourceScope, digest
from sova.security.domain.governance import ControlFamily
from sova.security.domain.protection_parity import (
    Availability,
    ProtectionEndpoint,
    ProtectionRequirement,
    ProtectionPolicy,
)


def decode_endpoint(data):
    exact(
        data,
        (
            "scope",
            "provider",
            "implementation",
            "provider_capability",
            "adapter_implementation",
            "source_digest",
            "configuration_digest",
            "environment_digest",
            "verifier_version",
        ),
    )
    exact(
        data["scope"], ("tenant_id", "application_id", "environment_id", "resource_id")
    )
    return ProtectionEndpoint(
        scope=ResourceScope(**data["scope"]),
        provider_capability=Availability(data["provider_capability"]),
        adapter_implementation=Availability(data["adapter_implementation"]),
        **{
            k: v
            for k, v in data.items()
            if k not in {"scope", "provider_capability", "adapter_implementation"}
        },
    )


def decode_protection_policy(data):
    try:
        profiled = (
            isinstance(data, dict)
            and type(data.get("schema_version")) is int
            and data["schema_version"] == 2
        )
        profile_digest = digest(data["profile_digest"]) if profiled else None
        if profiled:
            data = {k: v for k, v in data.items() if k != "profile_digest"}
        exact(
            data,
            (
                "schema_version",
                "tenant_id",
                "application_id",
                "revision",
                "requirements",
                "issued_at",
                "valid_until",
            ),
        )
        if (
            type(data["schema_version"]) is not int
            or data["schema_version"] not in (1, 2)
            or type(data["requirements"]) is not list
        ):
            raise ContractError("Unsupported protection policy schema")
        requirements = []
        for req in data["requirements"]:
            exact(
                req,
                (
                    "requirement_id",
                    "family",
                    "objective",
                    "source",
                    "target",
                    "required",
                ),
            )
            requirements.append(
                ProtectionRequirement(
                    req["requirement_id"],
                    ControlFamily(req["family"]),
                    req["objective"],
                    decode_endpoint(req["source"]),
                    decode_endpoint(req["target"]),
                    req["required"],
                )
            )
        return ProtectionPolicy(
            data["tenant_id"],
            data["application_id"],
            data["revision"],
            tuple(requirements),
            datetime.fromisoformat(data["issued_at"]),
            datetime.fromisoformat(data["valid_until"]),
            profile_digest,
        )
    except (KeyError, ValueError, TypeError) as exc:
        raise ContractError("Invalid protection policy document") from exc
