"""Operator-only fixture preparation. Never import this module in the app server."""

from datetime import datetime, UTC
import hashlib
from pathlib import Path
import re
import secrets
from uuid import uuid4

from psycopg import sql


def prepare(conn, *, schema, app_role, valid_until):
    with conn.transaction():
        return _prepare(conn, schema=schema, app_role=app_role, valid_until=valid_until)


def _prepare(conn, *, schema, app_role, valid_until):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema):
        raise ValueError("Bounded SQL schema identifier required")
    conn.execute(
        (Path(__file__).parent / "schema.sql")
        .read_text()
        .replace("consultation", schema)
    )
    grant_application(conn, schema=schema, app_role=app_role)
    people = []
    for role, name in (
        ("customer", "고객 A"),
        ("customer", "고객 B"),
        ("counselor", "상담원"),
    ):
        user_id = str(uuid4())
        conn.execute(
            sql.SQL("INSERT INTO {}.users VALUES(%s,%s,%s,false)").format(
                sql.Identifier(schema)
            ),
            (user_id, name, role),
        )
        people.append(
            {
                "user_id": user_id,
                "display_name": name,
                "role": role,
                "invite": invite(conn, schema, user_id, valid_until),
            }
        )
    for person in people[:2]:
        room = str(uuid4())
        person["room_id"] = room
        conn.execute(
            sql.SQL(
                "INSERT INTO {}.rooms(room_id,customer_id,counselor_id) VALUES(%s,%s,%s)"
            ).format(sql.Identifier(schema)),
            (room, person["user_id"], people[2]["user_id"]),
        )
    return people


def grant_application(conn, *, schema, app_role):
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", schema) or not re.fullmatch(
        r"[a-z][a-z0-9_]{0,62}", app_role
    ):
        raise ValueError("Bounded registered schema and application role required")
    conn.execute(
        sql.SQL("GRANT USAGE ON SCHEMA {} TO {}").format(
            sql.Identifier(schema), sql.Identifier(app_role)
        )
    )
    for table in (
        "users",
        "rooms",
        "control",
        "messages",
        "attachments",
        "invitations",
        "sessions",
    ):
        conn.execute(
            sql.SQL("GRANT SELECT ON {}.{} TO {}").format(
                sql.Identifier(schema), sql.Identifier(table), sql.Identifier(app_role)
            )
        )
    for table in ("rooms", "messages", "attachments", "sessions", "audit"):
        conn.execute(
            sql.SQL("GRANT INSERT ON {}.{} TO {}").format(
                sql.Identifier(schema), sql.Identifier(table), sql.Identifier(app_role)
            )
        )
    for table, column in (
        ("rooms", "last_sequence"),
        ("attachments", "state"),
        ("invitations", "consumed_at"),
    ):
        conn.execute(
            sql.SQL("GRANT UPDATE({}) ON {}.{} TO {}").format(
                sql.Identifier(column),
                sql.Identifier(schema),
                sql.Identifier(table),
                sql.Identifier(app_role),
            )
        )
    conn.execute(
        sql.SQL("GRANT DELETE ON {}.sessions TO {}").format(
            sql.Identifier(schema), sql.Identifier(app_role)
        )
    )
    conn.execute(
        sql.SQL("GRANT USAGE ON ALL SEQUENCES IN SCHEMA {} TO {}").format(
            sql.Identifier(schema), sql.Identifier(app_role)
        )
    )


def invite(conn, schema, user_id, valid_until):
    if valid_until.tzinfo is None or valid_until <= datetime.now(UTC):
        raise ValueError("Future aware invite deadline required")
    code = secrets.token_urlsafe(32)
    conn.execute(
        sql.SQL("INSERT INTO {}.invitations VALUES(%s,%s,%s,NULL)").format(
            sql.Identifier(schema)
        ),
        (hashlib.sha256(code.encode()).hexdigest(), user_id, valid_until),
    )
    return code


def set_writes(conn, *, schema, enabled):
    """Drain this instrumented app's transactions, not arbitrary external writers."""
    if type(enabled) is not bool:
        raise ValueError("Explicit writer state required")
    key = int.from_bytes(
        hashlib.sha256(schema.encode()).digest()[:8], "big", signed=True
    )
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (key,))
        return conn.execute(
            sql.SQL(
                "UPDATE {}.control SET writes_enabled=%s,writer_epoch=writer_epoch+1,last_command_digest=NULL WHERE singleton RETURNING writer_epoch"
            ).format(sql.Identifier(schema)),
            (enabled,),
        ).fetchone()[0]
