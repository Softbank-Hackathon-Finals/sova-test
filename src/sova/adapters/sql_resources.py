"""Resolve package-owned security SQL and host-owned lifecycle migrations."""

from importlib.resources import files
from sova_security.migrations import (
    MIGRATIONS,
    migration_sql as security_migration_sql,
)
from sova.domain.contracts import ContractError


def migration_sql(name: str) -> str:
    if name in MIGRATIONS:
        return security_migration_sql(name)
    if not isinstance(name, str) or "/" in name or "\\" in name:
        raise ContractError("Invalid host migration name")
    resource = files("sova.adapters").joinpath("sql", name)
    if not resource.is_file() or not name.endswith(".sql"):
        raise ContractError("Unknown host migration")
    return resource.read_text(encoding="utf-8")
