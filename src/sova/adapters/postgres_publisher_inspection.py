"""Observe a registered active WAL sender without exposing cluster-wide stats.

TLS/slot/role/peer observations are not a client certificate identity, an HBA
authentication-method audit, all-writer fencing or authorization to cut over.
"""

from dataclasses import dataclass
from datetime import datetime
import hashlib
import ipaddress
from pathlib import Path
import re

from psycopg import sql

from sova.adapters.postgres_readonly import require_select_only
from sova.domain.contracts import ContractError, canonical_json, digest, identifier, utc


@dataclass(frozen=True, slots=True)
class PublisherInspector:
    function_oid: int
    definition_digest: str
    owner_role: str
    binding_oid: int
    slot_name: str
    replicator_oid: int
    replicator_role: str
    application_name: str
    expected_peer_addresses: tuple[str, ...]

    def __post_init__(self):
        for value in (self.function_oid, self.binding_oid, self.replicator_oid):
            if type(value) is not int or not 0 < value <= 4294967295:
                raise ContractError("Registered publisher inspector OID required")
        digest(self.definition_digest)
        for value in (self.owner_role, self.replicator_role, self.application_name):
            identifier(value)
        if len(self.application_name.encode()) > 63 or not re.fullmatch(
            r"[a-z0-9_]{1,63}", self.slot_name
        ):
            raise ContractError("Bounded publisher slot/application name required")
        if (
            type(self.expected_peer_addresses) is not tuple
            or not 1 <= len(self.expected_peer_addresses) <= 16
        ):
            raise ContractError("Bounded immutable publisher peer addresses required")
        try:
            addresses = tuple(
                str(ipaddress.ip_address(value))
                for value in self.expected_peer_addresses
            )
        except ValueError as exc:
            raise ContractError("Numeric publisher peer addresses required") from exc
        if addresses != self.expected_peer_addresses or len(set(addresses)) != len(
            addresses
        ):
            raise ContractError("Canonical unique publisher peer addresses required")


def _definition(connection):
    return connection.execute(
        "SELECT p.oid,pg_catalog.pg_get_functiondef(p.oid),pg_catalog.pg_get_userbyid(p.proowner),p.prosecdef FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='sova_publisher_inspection' AND p.proname='channel_transport' AND p.pronargs=0"
    ).fetchone()


def _binding_identity(connection):
    return connection.execute(
        "SELECT c.oid,pg_catalog.pg_get_userbyid(c.relowner),c.relkind,c.relrowsecurity,c.relforcerowsecurity,EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(c.relacl,pg_catalog.acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner AND a.privilege_type IN ('INSERT','UPDATE','DELETE','TRUNCATE','TRIGGER')),EXISTS(SELECT 1 FROM pg_catalog.aclexplode(COALESCE(n.nspacl,pg_catalog.acldefault('n',n.nspowner))) a WHERE a.grantee<>n.nspowner AND a.privilege_type='CREATE'),pg_catalog.pg_get_userbyid(n.nspowner) FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='sova_publisher_inspection' AND c.relname='reader_bindings'"
    ).fetchone()


def install_publisher_inspector(
    connection,
    *,
    reader_role,
    slot_name,
    replicator_role,
    application_name,
    expected_peer_addresses,
    valid_until: datetime,
):
    """Explicit owner installation, separate from app/runtime provisioning."""
    for value in (reader_role, replicator_role, application_name):
        identifier(value)
    valid_until = utc(valid_until)
    if not re.fullmatch(r"[a-z0-9_]{1,63}", slot_name):
        raise ContractError("Registered logical slot required")
    with connection.transaction():
        owner = connection.execute("SELECT current_user").fetchone()[0]
        existing = connection.execute(
            "SELECT pg_catalog.pg_get_userbyid(nspowner) FROM pg_catalog.pg_namespace WHERE nspname='sova_publisher_inspection'"
        ).fetchone()
        if existing is not None and existing != (owner,):
            raise ContractError("Publisher inspector schema owner drift")
        reader = connection.execute(
            "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s", (reader_role,)
        ).fetchone()
        replicator = connection.execute(
            "SELECT oid FROM pg_catalog.pg_roles WHERE rolname=%s AND rolreplication AND NOT rolsuper AND NOT rolbypassrls",
            (replicator_role,),
        ).fetchone()
        slot = connection.execute(
            "SELECT slot_type,plugin,database=current_database() FROM pg_catalog.pg_replication_slots WHERE slot_name=%s",
            (slot_name,),
        ).fetchone()
        if (
            reader is None
            or reader_role == owner
            or replicator is None
            or reader == replicator
            or slot != ("logical", "pgoutput", True)
        ):
            raise ContractError(
                "Distinct registered reader/replicator and local logical slot required"
            )
        connection.execute(
            (
                Path(__file__).parent / "sql/postgres_publisher_inspection_v1.sql"
            ).read_text()
        )
        identity = _binding_identity(connection)
        if identity is None or identity[1:] != (
            owner,
            "r",
            False,
            False,
            False,
            False,
            owner,
        ):
            raise ContractError(
                "Publisher inspector binding is mutable by another role"
            )
        definition = _definition(connection)
        if definition is None or definition[2:] != (owner, True):
            raise ContractError("Publisher inspector definition owner drift")
        registration = PublisherInspector(
            definition[0],
            hashlib.sha256(definition[1].encode()).hexdigest(),
            owner,
            identity[0],
            slot_name,
            replicator[0],
            replicator_role,
            application_name,
            expected_peer_addresses,
        )
        connection.execute(
            "INSERT INTO sova_publisher_inspection.reader_bindings VALUES(%s,%s,%s,%s,%s) ON CONFLICT(reader_oid) DO UPDATE SET slot_name=EXCLUDED.slot_name,replicator_oid=EXCLUDED.replicator_oid,application_name=EXCLUDED.application_name,valid_until=EXCLUDED.valid_until",
            (reader[0], slot_name, replicator[0], application_name, valid_until),
        )
        connection.execute(
            sql.SQL("GRANT USAGE ON SCHEMA sova_publisher_inspection TO {}").format(
                sql.Identifier(reader_role)
            )
        )
        connection.execute(
            sql.SQL(
                "GRANT EXECUTE ON FUNCTION sova_publisher_inspection.channel_transport() TO {}"
            ).format(sql.Identifier(reader_role))
        )
        return registration


def inspect_publisher_transport(connection, inspector, *, database_oid, valid_until):
    """Called only after authenticated, registered read-only source connection."""
    if not isinstance(inspector, PublisherInspector):
        raise ContractError("Typed publisher inspector required")
    definition = _definition(connection)
    if definition is None or (
        definition[0],
        hashlib.sha256(definition[1].encode()).hexdigest(),
        definition[2],
        definition[3],
    ) != (
        inspector.function_oid,
        inspector.definition_digest,
        inspector.owner_role,
        True,
    ):
        raise ContractError("Publisher inspector definition or ownership changed")
    if connection.execute(
        "SELECT pg_catalog.pg_has_role(current_user,%s,'MEMBER')",
        (inspector.owner_role,),
    ).fetchone()[0]:
        raise ContractError("Publisher observer must not inherit inspector ownership")
    identity = _binding_identity(connection)
    if identity != (
        inspector.binding_oid,
        inspector.owner_role,
        "r",
        False,
        False,
        False,
        False,
        inspector.owner_role,
    ):
        raise ContractError("Publisher inspector binding identity or ACL drift")
    require_select_only(connection, inspector.binding_oid)
    rows = connection.execute(
        "SELECT * FROM sova_publisher_inspection.channel_transport()"
    ).fetchall()
    if len(rows) != 1:
        raise ContractError("One current registered publisher WAL sender required")
    (
        slot,
        db,
        pid,
        role_oid,
        role,
        application,
        peer,
        state,
        encrypted,
        version,
        bits,
        deadline,
    ) = rows[0]
    if (slot, db, role_oid, role, application, deadline) != (
        inspector.slot_name,
        database_oid,
        inspector.replicator_oid,
        inspector.replicator_role,
        inspector.application_name,
        valid_until,
    ):
        raise ContractError("Publisher WAL sender identity/binding drift")
    if (
        type(pid) is not int
        or pid <= 0
        or peer not in inspector.expected_peer_addresses
        or state != "streaming"
        or encrypted is not True
        or version not in {"TLSv1.2", "TLSv1.3"}
        or type(bits) is not int
        or bits < 128
    ):
        raise ContractError("Registered publisher encrypted peer is not verified")
    proof = {
        "slot": slot,
        "database_oid": db,
        "backend_pid": pid,
        "role_oid": role_oid,
        "role": role,
        "application": application,
        "peer": peer,
        "tls_version": version,
        "cipher_bits": bits,
    }
    return {
        "observation_digest": hashlib.sha256(
            canonical_json(proof).encode()
        ).hexdigest(),
        "encrypted_channel_observed": True,
        "tls_version": version,
        "cipher_bits": bits,
        "client_certificate_identity_verified": False,
        "authentication_method_verified": False,
    }
