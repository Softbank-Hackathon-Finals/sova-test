"""Scoped read-only PostgreSQL snapshots for independent data comparison.

The operator supplies a credential resolver for an opaque reference. The reader
never accepts a DSN, SQL expression or predicate from an uploaded application.
It verifies cluster/database/relation identities and a nonprivileged reader,
then uses one repeatable-read transaction. This is not CDC, writer fencing, a
backup, or a claim that a caller's boundary label is a verified final barrier.
"""

import base64
from dataclasses import dataclass, replace
from datetime import date, datetime
from decimal import Decimal
import hashlib
import json
import math
import re
from uuid import UUID

from psycopg import sql
from psycopg.types.json import set_json_loads
from sova.adapters.postgres_readonly import begin_registered_read, require_select_only

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    digest,
    identifier,
    utc,
)
from sova.domain.data_manifest import manifest_rows
from sova.domain.evidence import RevisionSet


_TYPES = {
    "int2",
    "int4",
    "int8",
    "text",
    "varchar",
    "bool",
    "uuid",
    "numeric",
    "bytea",
    "json",
    "jsonb",
    "timestamp",
    "timestamptz",
    "date",
    "float4",
    "float8",
}


@dataclass(frozen=True, slots=True)
class PostgresDatasetRegistration:
    scope: ResourceScope
    revisions: RevisionSet
    connection_ref: str
    database_name: str
    database_oid: int
    system_identifier: str
    reader_role: str
    schema_name: str
    table_name: str
    table_oid: int
    schema_digest: str
    columns: tuple[str, ...]
    primary_key: tuple[str, ...]
    issued_at: datetime
    valid_until: datetime
    maximum_rows: int = 100000
    allow_private_unix_fixture: bool = False

    def __post_init__(self):
        if not isinstance(self.scope, ResourceScope) or not isinstance(
            self.revisions, RevisionSet
        ):
            raise ContractError("Typed dataset registration scope required")
        for value in (
            self.connection_ref,
            self.database_name,
            self.reader_role,
            self.schema_name,
            self.table_name,
        ):
            identifier(value)
        for value in (self.database_oid, self.table_oid):
            if type(value) is not int or value < 1:
                raise ContractError(
                    "Positive registered database/relation OIDs required"
                )
        if type(self.system_identifier) is not str or not re.fullmatch(
            r"[0-9]{1,20}", self.system_identifier
        ):
            raise ContractError("Registered PostgreSQL cluster identity required")
        digest(self.schema_digest)
        if (
            type(self.columns) is not tuple
            or not 1 <= len(self.columns) <= 128
            or len(set(self.columns)) != len(self.columns)
            or type(self.primary_key) is not tuple
            or not self.primary_key
            or len(set(self.primary_key)) != len(self.primary_key)
            or not set(self.primary_key) <= set(self.columns)
        ):
            raise ContractError("Exact bounded columns and primary key required")
        for column in self.columns:
            identifier(column)
        if type(self.maximum_rows) is not int or not 1 <= self.maximum_rows <= 1000000:
            raise ContractError("Bounded dataset capacity required")
        if type(self.allow_private_unix_fixture) is not bool:
            raise ContractError("Explicit database transport policy required")
        object.__setattr__(self, "issued_at", utc(self.issued_at))
        object.__setattr__(self, "valid_until", utc(self.valid_until))
        if self.valid_until <= self.issued_at:
            raise ContractError("Positive registration interval required")

    def require_current(self, now):
        if not self.issued_at <= utc(now) < self.valid_until:
            raise ContractError("Dataset registration expired or from future")


def table_definition(connection, schema_name, table_name):
    """Read metadata only; authentication/registration belongs to the caller."""
    table = connection.execute(
        "SELECT c.oid,c.relkind,c.relrowsecurity,c.relforcerowsecurity FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=%s AND c.relname=%s",
        (schema_name, table_name),
    ).fetchone()
    if table is None or table[1] != "r":
        raise ContractError("Only registered ordinary PostgreSQL tables supported")
    columns = connection.execute(
        "SELECT a.attnum,a.attname,t.typname,tn.nspname,pg_catalog.format_type(a.atttypid,a.atttypmod),a.attnotnull,a.attidentity,a.attgenerated FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_type t ON t.oid=a.atttypid JOIN pg_catalog.pg_namespace tn ON tn.oid=t.typnamespace WHERE a.attrelid=%s AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum",
        (table[0],),
    ).fetchall()
    if not columns or any(c[2] not in _TYPES or c[3] != "pg_catalog" for c in columns):
        raise ContractError("Unsupported PostgreSQL column type")
    pk = connection.execute(
        "SELECT indkey::smallint[] FROM pg_catalog.pg_index WHERE indrelid=%s AND indisprimary AND indisvalid",
        (table[0],),
    ).fetchone()
    if pk is None:
        raise ContractError("A valid primary key is required for data comparison")
    by_number = {c[0]: c[1] for c in columns}
    primary_key = tuple(by_number[number] for number in pk[0])
    document = {
        "columns": [
            {
                "name": c[1],
                "type": c[4],
                "not_null": c[5],
                "identity": c[6],
                "generated": c[7],
            }
            for c in columns
        ],
        "primary_key": list(primary_key),
        "row_security": table[2],
        "force_row_security": table[3],
    }
    fingerprint = hashlib.sha256(
        canonical_json(document, limit=65536).encode()
    ).hexdigest()
    return {
        "table_oid": table[0],
        "columns": tuple(c[1] for c in columns),
        "primary_key": primary_key,
        "schema_digest": fingerprint,
        "document": document,
    }


def exact_decimal(value):
    if not value.is_finite():
        raise ContractError("Nonfinite numeric data unsupported")
    if value.is_zero():
        return "0"
    parts = value.as_tuple()
    digits = len(parts.digits)
    exponent = parts.exponent
    expanded = (
        digits + exponent
        if exponent >= 0
        else (digits + 1 if digits + exponent > 0 else 2 - exponent)
    )
    if expanded + parts.sign > 65536:
        raise ContractError("Numeric normalization capacity exceeded")
    # Decimal.normalize() rounds according to the ambient decimal Context.
    # Formatting without precision is exact; trim fractional zeros only.
    text = format(value, "f")
    return text.rstrip("0").rstrip(".") if "." in text else text


@dataclass(frozen=True, slots=True)
class JSONValue:
    value: object


def lossless_json(raw):
    if len(raw) > 65536:
        raise ContractError("JSON normalization capacity exceeded")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ContractError("Duplicate JSON keys are unsupported")
            result[key] = value
        return result

    def constant(_):
        raise ContractError("Nonfinite JSON number unsupported")

    try:
        return JSONValue(
            json.loads(
                raw,
                parse_float=Decimal,
                object_pairs_hook=unique,
                parse_constant=constant,
            )
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ContractError("Unsupported JSON snapshot representation") from exc


def json_tokens(value):
    result = []

    def visit(item, depth=0):
        if depth > 8 or len(result) > 8192:
            raise ContractError("JSON structure normalization capacity exceeded")
        if item is None:
            result.append(["null"])
        elif type(item) is bool:
            result.append(["boolean", item])
        elif type(item) is str:
            result.append(["string", item])
        elif type(item) is int:
            result.append(["number", str(item)])
        elif type(item) is Decimal:
            result.append(["number", exact_decimal(item)])
        elif type(item) is list:
            result.append(["array", len(item)])
            for child in item:
                visit(child, depth + 1)
            result.append(["end-array"])
        elif type(item) is dict:
            result.append(["object", len(item)])
            for key in sorted(item):
                result.append(["key", key])
                visit(item[key], depth + 1)
            result.append(["end-object"])
        else:
            raise ContractError("Unsupported lossless JSON scalar")

    visit(value)
    if len(result) > 8192:
        raise ContractError("JSON token capacity exceeded")
    return result


def normalize_value(value):
    if isinstance(value, JSONValue):
        return {"type": "json", "tokens": json_tokens(value.value)}
    if value is None or type(value) in (str, bool, int):
        return value
    if isinstance(value, UUID):
        return str(value)
    if type(value) is Decimal:
        return {"type": "decimal", "value": exact_decimal(value)}
    if type(value) is float:
        if not math.isfinite(value):
            raise ContractError("Nonfinite float data unsupported")
        return {"type": "float", "value": value.hex()}
    if isinstance(value, datetime):
        return {
            "type": "timestamp-aware" if value.tzinfo else "timestamp-naive",
            "value": utc(value).isoformat(timespec="microseconds")
            if value.tzinfo
            else value.isoformat(timespec="microseconds"),
        }
    if isinstance(value, date):
        return {"type": "date", "value": value.isoformat()}
    if isinstance(value, (bytes, memoryview)):
        return {
            "type": "bytes",
            "base64": base64.b64encode(bytes(value)).decode("ascii"),
        }
    if type(value) in (dict, list):
        # JSON encoding below rejects nonfinite values, invalid types and depth.
        return value
    raise ContractError("Unsupported PostgreSQL value")


class PostgresDatasetReader:
    def __init__(
        self,
        registration,
        *,
        connect,
        authorize,
        authenticate_registration,
        clock,
        monotonic,
    ):
        if not isinstance(registration, PostgresDatasetRegistration):
            raise ContractError("Typed PostgreSQL dataset registration required")
        self.registration = registration
        self.connect = connect
        self.authorize = authorize
        self.authenticate_registration = authenticate_registration
        self.clock = clock
        self.monotonic = monotonic

    def snapshot(self, actor, *, boundary_id):
        r = self.registration
        self.authorize(actor, r.scope, "data:snapshot-read")
        self.authenticate_registration(r)
        r.require_current(self.clock())
        identifier(boundary_id)
        started = self.monotonic()
        with self.connect(r.connection_ref) as connection:
            begin_registered_read(connection, r)
            definition = table_definition(connection, r.schema_name, r.table_name)
            if (
                definition["table_oid"],
                definition["schema_digest"],
                definition["columns"],
                definition["primary_key"],
            ) != (r.table_oid, r.schema_digest, r.columns, r.primary_key):
                raise ContractError("Registered table or schema drift")
            require_select_only(connection, r.table_oid)
            if definition["document"]["row_security"]:
                raise ContractError(
                    "RLS-filtered snapshots need a separately qualified completeness verifier"
                )
            self.authorize(actor, r.scope, "data:snapshot-read")
            self.authenticate_registration(r)
            set_json_loads(lossless_json, connection)
            with connection.cursor(name="sova_registered_dataset") as cursor:
                cursor.itersize = 100
                # Bound the textual row on the DB side before libpq transfers
                # large values. This still uses source CPU under statement timeout.
                # OFFSET 0 keeps the lateral size decision a separate plan node.
                sizes = sql.SQL(" + ").join(
                    sql.SQL(
                        "COALESCE(pg_catalog.octet_length(t.{}::text),0)::bigint"
                    ).format(sql.Identifier(column))
                    for column in r.columns
                )
                values = sql.SQL(",").join(
                    sql.SQL("CASE WHEN b.oversized THEN NULL ELSE t.{} END").format(
                        sql.Identifier(column)
                    )
                    for column in r.columns
                )
                cursor.execute(
                    sql.SQL(
                        "SELECT {},b.oversized FROM {}.{} t CROSS JOIN LATERAL (SELECT ({})>32768 AS oversized OFFSET 0) b"
                    ).format(
                        values,
                        sql.Identifier(r.schema_name),
                        sql.Identifier(r.table_name),
                        sizes,
                    )
                )

                def rows():
                    for row in cursor:
                        if row[-1]:
                            raise ContractError(
                                "Dataset row exceeds bounded extraction capacity"
                            )
                        r.require_current(self.clock())
                        if self.monotonic() - started > 15:
                            raise ContractError("Dataset snapshot time budget exceeded")
                        yield {
                            column: normalize_value(value)
                            for column, value in zip(r.columns, row[:-1], strict=True)
                        }

                observed_at = self.clock()
                manifest = manifest_rows(
                    rows(),
                    scope=r.scope,
                    revisions=r.revisions,
                    dataset_id=r.table_name,
                    columns=r.columns,
                    primary_key=r.primary_key,
                    boundary_id=boundary_id,
                    observed_at=observed_at,
                    valid_until=r.valid_until,
                    maximum_rows=r.maximum_rows,
                )
            r.require_current(self.clock())
            self.authenticate_registration(r)
            return {
                "manifest": replace(
                    manifest,
                    schema_digest=r.schema_digest,
                    normalization_version="postgres-lossless-v2",
                ),
                "verification_scope": "registered-consistent-read-only-snapshot",
                "final_boundary_verified": False,
                "cutover_authorized": False,
            }
