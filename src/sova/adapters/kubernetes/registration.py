"""Decode operator registrations. No uploaded kubeconfig or executable plugins."""

from datetime import datetime
from sova.adapters.registration.graph_codec import exact
from sova.domain.contracts import ContractError
from sova.domain.discovery import KubernetesReadRegistration


def decode_registration(data):
    try:
        exact(
            data,
            (
                "schema_version",
                "tenant_id",
                "application_id",
                "environment_id",
                "location",
                "endpoint",
                "approved_addresses",
                "ca_digest",
                "namespace",
                "namespace_uid",
                "revision",
                "registered_at",
                "valid_until",
            ),
        )
        if (
            type(data["schema_version"]) is not int
            or data["schema_version"] != 1
            or not isinstance(data["approved_addresses"], list)
        ):
            raise ContractError("Invalid registration schema")
        return KubernetesReadRegistration(
            **{
                k: v
                for k, v in data.items()
                if k
                not in {
                    "schema_version",
                    "registered_at",
                    "valid_until",
                    "approved_addresses",
                }
            },
            approved_addresses=tuple(data["approved_addresses"]),
            registered_at=datetime.fromisoformat(data["registered_at"]),
            valid_until=datetime.fromisoformat(data["valid_until"]),
        )
    except (TypeError, ValueError, KeyError) as exc:
        raise ContractError("Invalid Kubernetes registration") from exc
