"""Strict owner registration codec; no credentials or endpoint overrides."""

from datetime import datetime
from sova.adapters.registration.graph_codec import exact
from sova.security.domain.aws_security import RdsReadRegistration, RdsManagementRelation
from sova.domain.contracts import ContractError, ResourceScope


def decode_rds_registration(data):
    try:
        # Historical v1 means Sova-managed only. It never opts an external
        # resource into read-only registration by omission.
        if (
            isinstance(data, dict)
            and type(data.get("schema_version")) is int
            and data["schema_version"] == 1
        ):
            exact(
                data,
                (
                    "schema_version",
                    "scope",
                    "account_id",
                    "region",
                    "immutable_resource_id",
                    "minimum_backup_days",
                    "revision",
                    "issued_at",
                    "valid_until",
                ),
            )
            data = {**data, "schema_version": 2, "management_relation": "sova_managed"}
        exact(
            data,
            (
                "schema_version",
                "scope",
                "account_id",
                "region",
                "immutable_resource_id",
                "minimum_backup_days",
                "revision",
                "issued_at",
                "valid_until",
                "management_relation",
            ),
        )
        if type(data["schema_version"]) is not int or data["schema_version"] != 2:
            raise ContractError("Unsupported RDS read registration schema")
        exact(
            data["scope"],
            ("tenant_id", "application_id", "environment_id", "resource_id"),
        )
        return RdsReadRegistration(
            ResourceScope(**data["scope"]),
            data["account_id"],
            data["region"],
            data["immutable_resource_id"],
            data["minimum_backup_days"],
            data["revision"],
            datetime.fromisoformat(data["issued_at"]),
            datetime.fromisoformat(data["valid_until"]),
            RdsManagementRelation(data["management_relation"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ContractError("Invalid RDS read registration") from exc
