"""Bounded canonical JSON-row manifests. Equality is not a cutover authority.

Adapters must normalize database types and establish a consistent final snapshot.
No row contents are retained in this artifact. Writer fencing, CDC/barriers,
sequence checks and recovery are separate obligations in the migration program.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova.domain.evidence import RevisionSet


@dataclass(frozen=True, slots=True)
class DataManifest:
    scope: ResourceScope
    revisions: RevisionSet
    dataset_id: str
    schema_digest: str
    boundary_id: str
    row_count: int
    keys_digest: str
    content_digest: str
    observed_at: datetime
    valid_until: datetime
    normalization_version: str = "canonical-json-rows-v1"

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed dataset scope and revisions required")
        identifier(self.normalization_version)
        identifier(self.dataset_id)
        identifier(self.boundary_id)
        for value in (self.schema_digest, self.keys_digest, self.content_digest):
            digest(value)
        if type(self.row_count) is not int or self.row_count < 0:
            raise ContractError("Nonnegative row count required")
        object.__setattr__(self, "observed_at", utc(self.observed_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.observed_at:
            raise ContractError("Positive manifest validity required")


def manifest_rows(
    rows,
    *,
    scope,
    revisions,
    dataset_id,
    columns,
    primary_key,
    boundary_id,
    observed_at,
    valid_until,
    maximum_rows=100000,
):
    if (
        type(columns) is not tuple
        or not columns
        or len(set(columns)) != len(columns)
        or type(primary_key) is not tuple
        or not primary_key
        or len(set(primary_key)) != len(primary_key)
        or not set(primary_key) <= set(columns)
        or type(maximum_rows) is not int
        or not 1 <= maximum_rows <= 1000000
    ):
        raise ContractError("Explicit bounded columns and primary key required")
    for column in columns:
        identifier(column)
    schema_digest = hashlib.sha256(
        canonical_json(
            {"columns": list(columns), "primary_key": list(primary_key)}
        ).encode()
    ).hexdigest()
    entries = {}
    total_bytes = 0
    for row in rows:
        if type(row) is not dict or set(row) != set(columns):
            raise ContractError("Every row must match declared columns")
        if any(type(row[k]) not in (str, int) for k in primary_key):
            raise ContractError("Only non-null string/integer primary keys supported")
        key = canonical_json({k: row[k] for k in primary_key})
        encoded = canonical_json(row, limit=65536).encode()
        total_bytes += len(encoded)
        if key in entries:
            raise ContractError("Duplicate primary key in snapshot")
        if len(entries) >= maximum_rows or total_bytes > 64 * 1024 * 1024:
            raise ContractError("Snapshot exceeds bounded verifier capacity")
        entries[key] = hashlib.sha256(encoded).digest()
    keys_hash, content_hash = hashlib.sha256(), hashlib.sha256()
    for key in sorted(entries):
        encoded = key.encode()
        prefix = len(encoded).to_bytes(8, "big")
        keys_hash.update(prefix + encoded)
        content_hash.update(prefix + encoded + entries[key])
    return DataManifest(
        scope,
        revisions,
        dataset_id,
        schema_digest,
        boundary_id,
        len(entries),
        keys_hash.hexdigest(),
        content_hash.hexdigest(),
        observed_at,
        valid_until,
    )


def compare_manifests(source, target, *, now):
    if not isinstance(source, DataManifest) or not isinstance(target, DataManifest):
        raise ContractError("Typed source and target manifests required")
    a, b = source.scope, target.scope
    if (a.tenant_id, a.application_id) != (
        b.tenant_id,
        b.application_id,
    ) or a.environment_id == b.environment_id:
        raise ContractError("Distinct same-application environments required")
    now = utc(now)
    if any(not m.observed_at <= now < m.valid_until for m in (source, target)):
        raise ContractError("Manifest expired or from future")
    if (
        source.normalization_version != target.normalization_version
        or source.revisions != target.revisions
        or source.dataset_id != target.dataset_id
        or source.boundary_id != target.boundary_id
    ):
        raise ContractError(
            "Manifests do not share the exact revision/dataset/final boundary"
        )
    checks = {
        field: getattr(source, field) == getattr(target, field)
        for field in ("schema_digest", "row_count", "keys_digest", "content_digest")
    }
    return {
        "content_equal": all(checks.values()),
        "normalization_version": source.normalization_version,
        "checks": checks,
        "cutover_authorized": False,
        "remaining_obligations": [
            "authenticate-manifest-issuers",
            "all-writer-fencing",
            "final-boundary-readback",
            "sequence-safety",
            "post-cutover-write",
            "recovery-after-new-writes",
        ],
    }
