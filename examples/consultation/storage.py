"""PostgreSQL business transactions. Credentials are resolved by the operator.

This workload is single-organization; Sova tenant isolation is a separate
boundary. Invites are synthetic demo enrollment, not enterprise identity.
"""

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, UTC, timedelta
import hashlib
import hmac
import re
import secrets
from uuid import UUID, uuid4

from psycopg import sql


class AppError(Exception):
    status = 400
    code = "invalid_request"


class AccessDenied(AppError):
    status = 403
    code = "access_denied"


class Conflict(AppError):
    status = 409
    code = "idempotency_conflict"


class WritesPaused(AppError):
    status = 503
    code = "writes_paused"


def uuid(value):
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise AppError() from exc


def token_hash(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise AccessDenied()
    return hashlib.sha256(value.encode("ascii")).hexdigest()


@dataclass(frozen=True)
class Actor:
    user_id: str
    display_name: str
    role: str


class DatabaseBoundary(AppError):
    status = 503
    code = "database_identity_unverified"


class ConsultationStore:
    def __init__(self, connect, *, environment, schema="consultation"):
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", environment):
            raise ValueError("Registered environment name required")
        self._connector, self.environment, self.schema = connect, environment, schema
        self.control_key = int.from_bytes(
            hashlib.sha256(schema.encode()).digest()[:8], "big", signed=True
        )

    @contextmanager
    def connect(self):
        with self._connector() as conn, conn.transaction():
            same_identity, privileged = conn.execute(
                "SELECT current_user=session_user,EXISTS(SELECT 1 FROM pg_catalog.pg_roles WHERE (rolname=current_user OR pg_catalog.pg_has_role(current_user,oid,'MEMBER')) AND (rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole OR rolreplication))"
            ).fetchone()
            if not same_identity or privileged:
                raise DatabaseBoundary()
            yield conn

    def query(self, conn, template, params=()):
        return conn.execute(
            sql.SQL(template).format(schema=sql.Identifier(self.schema)), params
        )

    def health(self):
        with self.connect() as conn:
            row = self.query(
                conn,
                "SELECT writes_enabled,writer_epoch FROM {schema}.control WHERE singleton",
            ).fetchone()
            if not row:
                raise RuntimeError("Application control missing")
            return {
                "database": "reachable",
                "writes_enabled": row[0],
                "writer_epoch": row[1],
                "environment": self.environment,
            }

    def login(self, invite):
        code_hash = token_hash(invite)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        expires = datetime.now(UTC) + timedelta(minutes=30)
        with self.connect() as conn:
            self.write_gate(conn)
            row = self.query(
                conn,
                "UPDATE {schema}.invitations i SET consumed_at=clock_timestamp() FROM {schema}.users u WHERE i.code_hash=%s AND i.user_id=u.user_id AND NOT u.disabled AND i.consumed_at IS NULL AND i.expires_at>clock_timestamp() RETURNING i.user_id",
                (code_hash,),
            ).fetchone()
            if row is None:
                raise AccessDenied()
            self.query(
                conn,
                "INSERT INTO {schema}.sessions VALUES (%s,%s,%s,%s)",
                (token_hash(token), token_hash(csrf), row[0], expires),
            )
            self.audit(conn, str(row[0]), "session_created")
        return {"token": token, "csrf": csrf, "expires_at": expires.isoformat()}

    def authenticate(self, token, csrf):
        hashed, proof = token_hash(token), token_hash(csrf)
        with self.connect() as conn:
            row = self.query(
                conn,
                "SELECT u.user_id,u.display_name,u.role,s.csrf_hash FROM {schema}.sessions s JOIN {schema}.users u ON u.user_id=s.user_id WHERE s.token_hash=%s AND s.expires_at>clock_timestamp() AND NOT u.disabled",
                (hashed,),
            ).fetchone()
        if row is None or not hmac.compare_digest(row[3], proof):
            raise AccessDenied()
        return Actor(str(row[0]), row[1], row[2])

    def logout(self, token):
        with self.connect() as conn:
            self.write_gate(conn)
            self.query(
                conn,
                "DELETE FROM {schema}.sessions WHERE token_hash=%s",
                (token_hash(token),),
            )

    def audit(self, conn, actor_id, event, room_id=None, request_id=None):
        self.query(
            conn,
            "INSERT INTO {schema}.audit(actor_id,event,room_id,request_id) VALUES(%s,%s,%s,%s)",
            (actor_id, event, room_id, request_id),
        )

    def room(self, conn, actor, room_id, *, lock=False):
        room_id = uuid(room_id)
        row = self.query(
            conn,
            "SELECT room_id,last_sequence FROM {schema}.rooms WHERE room_id=%s AND (customer_id=%s OR counselor_id=%s)"
            + (" FOR UPDATE" if lock else ""),
            (room_id, actor.user_id, actor.user_id),
        ).fetchone()
        if row is None:
            raise AccessDenied()
        return row

    def rooms(self, actor):
        with self.connect() as conn:
            rows = self.query(
                conn,
                "SELECT room_id,last_sequence,created_at FROM {schema}.rooms WHERE customer_id=%s OR counselor_id=%s ORDER BY created_at",
                (actor.user_id, actor.user_id),
            ).fetchall()
        return [
            {"id": str(r[0]), "last_sequence": r[1], "created_at": r[2].isoformat()}
            for r in rows
        ]

    def write_gate(self, conn):
        conn.execute("SELECT pg_advisory_xact_lock_shared(%s)", (self.control_key,))
        row = self.query(
            conn,
            "SELECT writes_enabled,writer_epoch FROM {schema}.control WHERE singleton",
        ).fetchone()
        if row is None or row[0] is not True:
            raise WritesPaused()
        return row[1]

    def create_room(self, actor):
        if actor.role != "customer":
            raise AccessDenied()
        room_id = str(uuid4())
        with self.connect() as conn:
            self.write_gate(conn)
            counselor = self.query(
                conn,
                "SELECT user_id FROM {schema}.users WHERE role='counselor' AND NOT disabled ORDER BY user_id LIMIT 1",
            ).fetchone()
            if counselor is None:
                raise AppError()
            self.query(
                conn,
                "INSERT INTO {schema}.rooms(room_id,customer_id,counselor_id) VALUES(%s,%s,%s)",
                (room_id, actor.user_id, counselor[0]),
            )
            self.audit(conn, actor.user_id, "room_created", room_id)
        return {"id": room_id}

    def messages(self, actor, room_id, *, after=0, limit=100):
        if (
            type(after) is not int
            or not 0 <= after <= 9223372036854775807
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise AppError()
        with self.connect() as conn:
            self.room(conn, actor, room_id)
            rows = self.query(
                conn,
                "SELECT message_id,sequence,author_id,content,created_at,client_request_id,environment,writer_epoch FROM {schema}.messages WHERE room_id=%s AND sequence>%s ORDER BY sequence LIMIT %s",
                (uuid(room_id), after, limit),
            ).fetchall()
        return [self.message_document(row) for row in rows]

    @staticmethod
    def message_document(row):
        return {
            "id": str(row[0]),
            "sequence": str(row[1]),
            "author_id": str(row[2]),
            "content": row[3],
            "created_at": row[4].isoformat(),
            "client_request_id": str(row[5]),
            "environment": row[6],
            "writer_epoch": str(row[7]),
        }

    @staticmethod
    def request_lock(conn, namespace, key):
        value = hashlib.sha256((namespace + ":" + key).encode()).digest()[:8]
        # Two-int advisory keys are separate from the one-bigint writer gate.
        pair = (
            int.from_bytes(value[:4], "big", signed=True),
            int.from_bytes(value[4:], "big", signed=True),
        )
        conn.execute("SELECT pg_advisory_xact_lock(%s,%s)", pair)

    def send(self, actor, room_id, request_id, content):
        room_id, request_id = uuid(room_id), uuid(request_id)
        try:
            content_size = len(content.encode("utf-8")) if type(content) is str else 0
        except UnicodeError as exc:
            raise AppError() from exc
        if not 1 <= content_size <= 8192:
            raise AppError()
        with self.connect() as conn:
            epoch = self.write_gate(conn)
            self.request_lock(conn, "message", actor.user_id + ":" + request_id)
            # Serialize this room before looking up retries. Duplicate requests
            # return their committed row and never consume another room sequence.
            self.room(conn, actor, room_id, lock=True)
            prior = self.query(
                conn,
                "SELECT message_id,sequence,author_id,content,created_at,client_request_id,environment,writer_epoch,room_id FROM {schema}.messages WHERE author_id=%s AND client_request_id=%s",
                (actor.user_id, request_id),
            ).fetchone()
            if prior:
                if str(prior[8]) != room_id or prior[3] != content:
                    raise Conflict()
                result = self.message_document(prior[:8])
            else:
                seq = self.query(
                    conn,
                    "UPDATE {schema}.rooms SET last_sequence=last_sequence+1 WHERE room_id=%s RETURNING last_sequence",
                    (room_id,),
                ).fetchone()[0]
                row = self.query(
                    conn,
                    "INSERT INTO {schema}.messages(room_id,author_id,client_request_id,sequence,content,writer_epoch,environment) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING message_id,sequence,author_id,content,created_at,client_request_id,environment,writer_epoch",
                    (
                        room_id,
                        actor.user_id,
                        request_id,
                        seq,
                        content,
                        epoch,
                        self.environment,
                    ),
                ).fetchone()
                self.audit(
                    conn, actor.user_id, "message_committed", room_id, request_id
                )
                result = self.message_document(row)
        # The context committed before this acknowledgement is returned.
        return result

    def prepare_attachment(self, actor, room_id, attachment_id, filename, content):
        with self.connect() as conn:
            return self._prepare_attachment(
                conn, actor, room_id, attachment_id, filename, content
            )

    def finish_attachment(self, actor, room_id, attachment_id):
        with self.connect() as conn:
            self._finish_attachment(conn, actor, room_id, attachment_id)

    def upload_attachment(
        self, actor, room_id, attachment_id, filename, content, put_object
    ):
        """Hold the instrumented writer gate across object I/O and DB commit.

        A failed DB commit can leave an unreferenced object; retries use the same
        immutable key. This is not distributed atomic commit or remote fencing
        if the DB connection dies while a storage request is still in flight.
        """
        with self.connect() as conn:
            result = self._prepare_attachment(
                conn, actor, room_id, attachment_id, filename, content
            )
            put_object(result["id"], content)
            self._finish_attachment(conn, actor, room_id, result["id"])
        return result

    def _prepare_attachment(
        self, conn, actor, room_id, attachment_id, filename, content
    ):
        room_id, attachment_id = uuid(room_id), uuid(attachment_id)
        if (
            type(content) is not bytes
            or not 1 <= len(content) <= 1048576
            or type(filename) is not str
            or not 1 <= len(filename) <= 128
            or any(ord(c) < 32 or ord(c) == 127 for c in filename)
        ):
            raise AppError()
        fingerprint = hashlib.sha256(content).hexdigest()
        self.write_gate(conn)
        self.request_lock(conn, "attachment", attachment_id)
        self.room(conn, actor, room_id, lock=True)
        prior = self.query(
            conn,
            "SELECT room_id,author_id,content_digest,filename FROM {schema}.attachments WHERE attachment_id=%s",
            (attachment_id,),
        ).fetchone()
        if prior:
            if (str(prior[0]), str(prior[1]), prior[2], prior[3]) != (
                room_id,
                actor.user_id,
                fingerprint,
                filename,
            ):
                raise Conflict()
        else:
            self.query(
                conn,
                "INSERT INTO {schema}.attachments(attachment_id,room_id,author_id,filename,content_digest,byte_length,state) VALUES(%s,%s,%s,%s,%s,%s,'prepared')",
                (
                    attachment_id,
                    room_id,
                    actor.user_id,
                    filename,
                    fingerprint,
                    len(content),
                ),
            )
        return {"id": attachment_id, "content_digest": fingerprint}

    def _finish_attachment(self, conn, actor, room_id, attachment_id):
        self.write_gate(conn)
        self.room(conn, actor, room_id)
        row = self.query(
            conn,
            "SELECT state FROM {schema}.attachments WHERE attachment_id=%s AND room_id=%s AND author_id=%s FOR UPDATE",
            (uuid(attachment_id), uuid(room_id), actor.user_id),
        ).fetchone()
        if row is None:
            raise AccessDenied()
        if row[0] == "ready":
            return
        if row[0] != "prepared":
            raise Conflict()
        self.query(
            conn,
            "UPDATE {schema}.attachments SET state='ready' WHERE attachment_id=%s",
            (uuid(attachment_id),),
        )
        self.audit(
            conn,
            actor.user_id,
            "attachment_ready",
            uuid(room_id),
            uuid(attachment_id),
        )

    def attachment(self, actor, room_id, attachment_id):
        with self.connect() as conn:
            self.room(conn, actor, room_id)
            row = self.query(
                conn,
                "SELECT attachment_id,filename,content_digest,byte_length FROM {schema}.attachments WHERE attachment_id=%s AND room_id=%s AND state='ready'",
                (uuid(attachment_id), uuid(room_id)),
            ).fetchone()
            if row is None:
                raise AccessDenied()
            return {
                "id": str(row[0]),
                "filename": row[1],
                "content_digest": row[2],
                "byte_length": row[3],
            }
