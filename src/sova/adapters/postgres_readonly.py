"""Common fresh, TLS-bound, nonprivileged read-only PostgreSQL boundary."""

from psycopg.pq import TransactionStatus
from sova.domain.contracts import ContractError


def begin_registered_read(connection, registration):
    if (
        connection.autocommit
        or connection.info.transaction_status != TransactionStatus.IDLE
    ):
        raise ContractError("Fresh non-autocommit snapshot connection required")
    if connection.info.host.startswith("/"):
        if not registration.allow_private_unix_fixture:
            raise ContractError("Unix fixture transport not authorized")
    elif (
        not connection.info.ssl_in_use
        or connection.info.get_parameters().get("sslmode") != "verify-full"
    ):
        raise ContractError("Certificate/hostname-verified PostgreSQL TLS required")
    connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
    connection.execute("SET LOCAL statement_timeout='3s'")
    connection.execute("SET LOCAL lock_timeout='1s'")
    connection.execute("SET LOCAL TIME ZONE 'UTC'")
    identity = connection.execute(
        "SELECT current_database(),d.oid,c.system_identifier::text,current_user,session_user FROM pg_catalog.pg_database d CROSS JOIN pg_catalog.pg_control_system() c WHERE d.datname=current_database()"
    ).fetchone()
    if identity != (
        registration.database_name,
        registration.database_oid,
        registration.system_identifier,
        registration.reader_role,
        registration.reader_role,
    ):
        raise ContractError("Database/cluster/reader identity drift")
    if connection.execute(
        "SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE (rolname=current_user OR pg_catalog.pg_has_role(current_user,oid,'MEMBER')) AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication))"
    ).fetchone()[0]:
        raise ContractError("Privileged database reader rejected")


def require_select_only(connection, oid, *, sequence=False):
    function = "has_sequence_privilege" if sequence else "has_table_privilege"
    rights = (
        "USAGE,UPDATE"
        if sequence
        else "INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER"
    )
    # Include NOINHERIT memberships: SET ROLE can otherwise elevate a reader.
    query = f"SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_roles r WHERE (r.rolname=current_user OR pg_catalog.pg_has_role(current_user,r.oid,'MEMBER')) AND pg_catalog.{function}(r.oid,%s,%s))"
    if connection.execute(query, (oid, rights)).fetchone()[0]:
        raise ContractError(
            "Dataset reader must have SELECT-only rights, including role memberships"
        )
