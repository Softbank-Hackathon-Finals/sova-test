"""Preview effect journal. SQLite is not the hosted PostgreSQL repository.

Each claim and completion uses a short database transaction and a revision CAS.
Unknown/in-flight effects retain a resource-scoped conflict barrier after restart.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import UTC, datetime

from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    EffectObservation,
    EffectRecord,
    EffectStatus,
    ResourceScope,
    canonical_json,
)


from sova.ports.effects import EffectConflict as EffectConflict


_ALLOWED = {
    EffectStatus.PREPARED: {EffectStatus.IN_FLIGHT, EffectStatus.NOT_APPLIED},
    EffectStatus.IN_FLIGHT: {
        EffectStatus.APPLIED,
        EffectStatus.NOT_APPLIED,
        EffectStatus.UNKNOWN,
    },
    EffectStatus.UNKNOWN: {EffectStatus.UNKNOWN, EffectStatus.APPLIED},
}


class SQLiteEffectJournal:
    def __init__(self, connection: sqlite3.Connection, *, lock=None):
        self.db = connection
        self.lock = lock or threading.RLock()
        with self.transaction():
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS sova_effects_v1 (
                    tenant_id TEXT NOT NULL, application_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL, resource_id TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
                    command_json TEXT NOT NULL, status TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK(revision >= 1),
                    observation_json TEXT,
                    PRIMARY KEY(tenant_id,application_id,idempotency_key),
                    CHECK(status IN ('prepared','in_flight','confirmed_applied',
                                     'confirmed_not_applied','unknown'))
                )
            """)
            self.db.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS sova_unresolved_effect_scope_v1
                ON sova_effects_v1(tenant_id,application_id,environment_id,resource_id)
                WHERE status IN ('prepared','in_flight','unknown')
            """)
            self.db.execute("""
                CREATE TABLE IF NOT EXISTS sova_effect_events_v1 (
                    seq INTEGER PRIMARY KEY, tenant_id TEXT NOT NULL,
                    application_id TEXT NOT NULL, idempotency_key TEXT NOT NULL,
                    revision INTEGER NOT NULL, status TEXT NOT NULL,
                    recorded_at TEXT NOT NULL, observation_json TEXT
                )
            """)

    @contextmanager
    def transaction(self):
        with self.lock:
            if self.db.in_transaction:
                raise EffectConflict(
                    "Effect journal requires its own transaction boundary"
                )
            self.db.execute("BEGIN IMMEDIATE")
            try:
                yield
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    @staticmethod
    def key(command):
        return (
            command.scope.tenant_id,
            command.scope.application_id,
            command.idempotency_key,
        )

    def _row(self, command):
        row = self.db.execute(
            "SELECT fingerprint,command_json,status,revision,observation_json "
            "FROM sova_effects_v1 WHERE tenant_id=? AND application_id=? AND idempotency_key=?",
            self.key(command),
        ).fetchone()
        if row and row[0] != command.fingerprint:
            raise EffectConflict(
                "Idempotency key was used with different command input"
            )
        return row

    @staticmethod
    def _record(row):
        observation = None
        if row[4]:
            data = json.loads(row[4])
            observation = EffectObservation(
                ResourceScope(**data["scope"]),
                data["command_digest"],
                EffectStatus(data["status"]),
                datetime.fromisoformat(data["observed_at"]),
                data["evidence_json"],
            )
        return EffectRecord(
            EffectCommand.from_document(json.loads(row[1])),
            EffectStatus(row[2]),
            row[3],
            observation,
        )

    def _event(self, command, revision, status, observation_json=None):
        self.db.execute(
            "INSERT INTO sova_effect_events_v1 "
            "(tenant_id,application_id,idempotency_key,revision,status,recorded_at,observation_json) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                *self.key(command),
                revision,
                str(status),
                datetime.now(UTC).isoformat(),
                observation_json,
            ),
        )

    def reserve(self, command):
        with self.transaction():
            row = self._row(command)
            if row:
                return self._record(row)
            try:
                self.db.execute(
                    "INSERT INTO sova_effects_v1 VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        *self.key(command)[:2],
                        command.scope.environment_id,
                        command.scope.resource_id,
                        command.idempotency_key,
                        command.fingerprint,
                        canonical_json(command.document, limit=16384),
                        str(EffectStatus.PREPARED),
                        1,
                        None,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise EffectConflict(
                    "Unresolved effect holds this resource scope"
                ) from error
            self._event(command, 1, EffectStatus.PREPARED)
            return self._record(self._row(command))

    def get(self, command):
        with self.lock:
            row = self._row(command)
            if not row:
                raise EffectConflict("Effect is not registered")
            return self._record(row)

    def unresolved(self, scope: ResourceScope) -> tuple[EffectRecord, ...]:
        with self.lock:
            rows = self.db.execute(
                "SELECT fingerprint,command_json,status,revision,observation_json "
                "FROM sova_effects_v1 WHERE tenant_id=? AND application_id=? "
                "AND environment_id=? AND resource_id=? "
                "AND status IN ('prepared','in_flight','unknown')",
                (
                    scope.tenant_id,
                    scope.application_id,
                    scope.environment_id,
                    scope.resource_id,
                ),
            ).fetchall()
            return tuple(self._record(row) for row in rows)

    def transition(
        self, command, expected_revision, expected_status, status, observation=None
    ):
        if type(expected_revision) is not int or expected_revision < 1:
            raise ContractError("Positive effect record revision required")
        if not isinstance(expected_status, EffectStatus) or not isinstance(
            status, EffectStatus
        ):
            raise ContractError("Typed effect states required")
        if status not in _ALLOWED.get(expected_status, set()):
            raise ContractError("Invalid effect transition")
        if observation and (
            observation.scope != command.scope
            or observation.command_digest != command.fingerprint
            or observation.status != status
        ):
            raise ContractError("Evidence binding does not match effect completion")
        if status == EffectStatus.APPLIED and observation is None:
            raise ContractError("Applied effects require readback evidence")
        raw = None
        if observation:
            raw = canonical_json(
                {
                    "scope": {
                        "tenant_id": observation.scope.tenant_id,
                        "application_id": observation.scope.application_id,
                        "environment_id": observation.scope.environment_id,
                        "resource_id": observation.scope.resource_id,
                    },
                    "command_digest": observation.command_digest,
                    "status": str(observation.status),
                    "observed_at": observation.observed_at.isoformat(),
                    "evidence_json": observation.evidence_json,
                },
                limit=16384,
            )
        with self.transaction():
            self._row(command)
            changed = self.db.execute(
                "UPDATE sova_effects_v1 SET status=?,revision=revision+1,observation_json=? "
                "WHERE tenant_id=? AND application_id=? AND idempotency_key=? "
                "AND fingerprint=? AND revision=? AND status=?",
                (
                    str(status),
                    raw,
                    *self.key(command),
                    command.fingerprint,
                    expected_revision,
                    str(expected_status),
                ),
            ).rowcount
            if changed != 1:
                raise EffectConflict("Effect revision or execution owner changed")
            self._event(command, expected_revision + 1, status, raw)
            return self._record(self._row(command))
