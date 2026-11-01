"""Atomic admission and at-least-once dispatch. No resource execution here."""

from uuid import uuid4
from datetime import timedelta

from psycopg.errors import UniqueViolation
from psycopg.types.json import Jsonb

from sova.domain.contracts import (
    ContractError,
    ResourceScope,
    canonical_json,
    identifier,
    EffectStatus,
)
from sova.domain.operations import (
    OperationRequest,
    OutboxDelivery,
    PublishReceipt,
    StoredOperation,
    OutboxEvent,
)
from sova.domain.workflows import OperationState, OperationStatus, OperationProfile
from sova.ports.operations import LeaseLost
from sova.ports.plans import RecordNotFound, RepositoryConflict


_SELECT = """SELECT operation_id,plan_id,plan_digest,approval_id,approval_revision,
    requested_by,idempotency_key,fingerprint,status,revision,updated_at,security_hold,
    (SELECT p.document->>'purpose' FROM sova_control.plans p
      WHERE p.tenant_id=operations.tenant_id AND p.application_id=operations.application_id AND p.plan_id=operations.plan_id)
    FROM sova_control.operations WHERE tenant_id=%s AND application_id=%s"""


class PostgresOperationRepository:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    @property
    def tenant_id(self):
        return self.lifecycle.tenant_id

    def _decode(self, app, row):
        if not row:
            raise RecordNotFound("Operation not found")
        request = OperationRequest(
            self.tenant_id, app, row[0], row[1], row[2], row[3], row[4], row[5], row[6]
        )
        if request.fingerprint != row[7]:
            raise ContractError("Stored operation fingerprint mismatch")
        state = OperationState(
            ResourceScope(self.tenant_id, app, "control", row[0]),
            row[0],
            row[2],
            OperationStatus(row[8]),
            row[9],
            row[10],
            row[11],
            OperationProfile.SECURITY_RESPONSE
            if row[12] == "security_response"
            else OperationProfile.MIGRATION_PHASE
            if row[12] == "migration_phase"
            else OperationProfile.MIGRATION,
        )
        return StoredOperation(request, state)

    def _get(self, conn, app, op, *, lock=False):
        row = conn.execute(
            _SELECT + " AND operation_id=%s" + (" FOR UPDATE" if lock else ""),
            (self.tenant_id, app, op),
        ).fetchone()
        return self._decode(app, row)

    def get(self, application_id, operation_id):
        with self.lifecycle.transaction() as conn:
            return self._get(conn, application_id, operation_id)

    def get_event(self, application_id, operation_id):
        with self.lifecycle.transaction() as conn:
            operation = self._get(conn, application_id, operation_id)
            row = conn.execute(
                "SELECT event_id,topic,payload FROM sova_control.operation_outbox WHERE tenant_id=%s AND application_id=%s AND operation_id=%s",
                (self.tenant_id, application_id, operation_id),
            ).fetchone()
            if row is None:
                raise RecordNotFound("Operation event not found")
            if row[2] != self._payload(operation.request):
                raise ContractError("Operation event differs from admitted request")
            return OutboxEvent(row[0], row[1], canonical_json(row[2]))

    def submit(self, request):
        if request.tenant_id != self.tenant_id:
            raise ContractError("Repository tenant scope mismatch")
        with self.lifecycle.transaction() as conn:
            existing = conn.execute(
                _SELECT + " AND idempotency_key=%s",
                (self.tenant_id, request.application_id, request.idempotency_key),
            ).fetchone()
            if existing:
                found = self._decode(request.application_id, existing)
                if found.request.fingerprint != request.fingerprint:
                    raise RepositoryConflict(
                        "Idempotency key has different operation input"
                    )
                return found
            plan = self.lifecycle._get_plan(
                conn, request.application_id, request.plan_id
            )
            # Keep admission and revocation ordered. Execution must still check
            # approval again after this transaction commits.
            conn.execute(
                "SELECT revision FROM sova_control.approvals WHERE tenant_id=%s AND application_id=%s AND approval_id=%s FOR SHARE",
                (self.tenant_id, request.application_id, request.approval_id),
            ).fetchone()
            approval = self.lifecycle._get_approval(
                conn, request.application_id, request.approval_id
            )
            if (
                approval.revoked
                or approval.revision != request.approval_revision
                or approval.plan_id != request.plan_id
                or plan.fingerprint != request.plan_digest
            ):
                raise ContractError("Approval or plan does not authorize admission")
            approval.approval.require_valid(plan, self.lifecycle.clock())
            try:
                inserted = conn.execute(
                    """INSERT INTO sova_control.operations
                    (tenant_id,application_id,operation_id,plan_id,plan_digest,approval_id,
                     approval_revision,requested_by,idempotency_key,fingerprint,status,revision,updated_at)
                    VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'registered',1,%s)
                    ON CONFLICT(tenant_id,application_id,idempotency_key) DO NOTHING RETURNING operation_id""",
                    (
                        self.tenant_id,
                        request.application_id,
                        request.operation_id,
                        request.plan_id,
                        request.plan_digest,
                        request.approval_id,
                        request.approval_revision,
                        request.requested_by,
                        request.idempotency_key,
                        request.fingerprint,
                        self.lifecycle.clock(),
                    ),
                ).fetchone()
            except UniqueViolation as error:
                raise RepositoryConflict("Operation ID already exists") from error
            if not inserted:
                found = self._decode(
                    request.application_id,
                    conn.execute(
                        _SELECT + " AND idempotency_key=%s",
                        (
                            self.tenant_id,
                            request.application_id,
                            request.idempotency_key,
                        ),
                    ).fetchone(),
                )
                if found.request.fingerprint != request.fingerprint:
                    raise RepositoryConflict(
                        "Idempotency key has different operation input"
                    )
                return found
            event_id = uuid4().hex
            payload = self._payload(request)
            conn.execute(
                """INSERT INTO sova_control.operation_outbox
                (tenant_id,application_id,operation_id,event_id,topic,payload)
                VALUES(%s,%s,%s,%s,'operation.requested.v1',%s)""",
                (
                    self.tenant_id,
                    request.application_id,
                    request.operation_id,
                    event_id,
                    Jsonb(payload),
                ),
            )
            self._event(
                conn,
                request.application_id,
                request.operation_id,
                1,
                OperationStatus.REGISTERED,
                request.requested_by,
            )
            return self._get(conn, request.application_id, request.operation_id)

    def _event(self, conn, app, op, revision, status, actor):
        conn.execute(
            """INSERT INTO sova_control.operation_events
            (tenant_id,application_id,operation_id,revision,status,actor_id)
            VALUES(%s,%s,%s,%s,%s,%s)""",
            (self.tenant_id, app, op, revision, str(status), actor),
        )

    @staticmethod
    def _payload(request):
        return {
            "tenant_id": request.tenant_id,
            "application_id": request.application_id,
            "operation_id": request.operation_id,
            "plan_id": request.plan_id,
            "plan_digest": request.plan_digest,
            "approval_id": request.approval_id,
            "approval_revision": request.approval_revision,
        }

    def _advance_locked(
        self, conn, current, status, *, expected_revision, actor_id, now
    ):
        if current.state.revision != expected_revision:
            raise RepositoryConflict("Operation revision changed")
        following = current.state.advance(
            status, expected_revision=expected_revision, now=now
        )
        conn.execute(
            """UPDATE sova_control.operations SET status=%s,revision=%s,updated_at=%s
            WHERE tenant_id=%s AND application_id=%s AND operation_id=%s""",
            (
                str(following.status),
                following.revision,
                following.updated_at,
                self.tenant_id,
                current.request.application_id,
                current.request.operation_id,
            ),
        )
        self._event(
            conn,
            current.request.application_id,
            current.request.operation_id,
            following.revision,
            status,
            actor_id,
        )
        if status in (
            OperationStatus.CANCELLED,
            OperationStatus.FAILED,
            OperationStatus.BLOCKED,
            OperationStatus.RESPONSE_VERIFIED,
            OperationStatus.PHASE_VERIFIED,
        ):
            conn.execute(
                """UPDATE sova_control.operation_outbox SET suppressed_at=clock_timestamp(),
                lease_token=NULL,lease_until=NULL,owner_id=NULL WHERE tenant_id=%s AND application_id=%s
                AND operation_id=%s AND published_at IS NULL""",
                (
                    self.tenant_id,
                    current.request.application_id,
                    current.request.operation_id,
                ),
            )
        return self._get(
            conn, current.request.application_id, current.request.operation_id
        )

    def advance(
        self, application_id, operation_id, status, *, expected_revision, actor_id
    ):
        identifier(actor_id, "actor_id")
        if status in {
            OperationStatus.RESPONSE_VERIFIED,
            OperationStatus.PHASE_VERIFIED,
        }:
            raise ContractError("Response completion requires an owned atomic receipt")
        with self.lifecycle.transaction() as conn:
            current = self._get(conn, application_id, operation_id, lock=True)
            return self._advance_locked(
                conn,
                current,
                status,
                expected_revision=expected_revision,
                actor_id=actor_id,
                now=self.lifecycle.clock(),
            )

    def advance_owned(self, ownership, lease, status, *, expected_revision, actor_id):
        if (
            actor_id != lease.owner_id
            or ownership.lifecycle is not self.lifecycle
            or lease.tenant_id != self.tenant_id
        ):
            raise ContractError("Exact execution owner required for state transition")
        if status in {
            OperationStatus.RESPONSE_VERIFIED,
            OperationStatus.PHASE_VERIFIED,
        }:
            raise ContractError("Response completion requires an atomic receipt")
        with self.lifecycle.transaction() as conn:
            _, now = ownership.require_current(conn, lease)
            current = self._get(
                conn, lease.application_id, lease.operation_id, lock=True
            )
            return self._advance_locked(
                conn,
                current,
                status,
                expected_revision=expected_revision,
                actor_id=actor_id,
                now=now,
            )

    def finish_response(self, ownership, lease, completion, *, expected_revision):
        from sova.domain.response_completion import ResponseCompletion
        from sova.domain.execution import ExecutionMode
        from sova.domain.security_response import ACTIONS
        from sova.adapters.postgres_effects import PostgresEffectJournal
        from sova.adapters.postgres_governance import (
            PostgresSecurityHolds,
            lock_security_hold_set,
        )

        if (
            not isinstance(completion, ResponseCompletion)
            or ownership.lifecycle is not self.lifecycle
            or lease.mode != ExecutionMode.MUTATE
        ):
            raise ContractError("Owned typed response completion required")
        command = completion.command
        if (
            lease.tenant_id,
            lease.application_id,
            lease.operation_id,
            lease.epoch,
            lease.owner_id,
        ) != (
            self.tenant_id,
            command.scope.application_id,
            command.operation_id,
            command.fencing_epoch,
            completion.owner_id,
        ):
            raise ContractError("Response completion owner/scope/epoch mismatch")
        if type(expected_revision) is not int or expected_revision < 1:
            raise ContractError("Positive completion revision required")
        with self.lifecycle.transaction() as conn:
            ownership.require_current(conn, lease)
            lock_security_hold_set(conn, self.tenant_id, lease.application_id)
            current = self._get(
                conn, lease.application_id, lease.operation_id, lock=True
            )
            if (
                current.state.profile != OperationProfile.SECURITY_RESPONSE
                or current.state.status != OperationStatus.VERIFYING
                or current.state.security_hold
                or current.state.revision != expected_revision
            ):
                raise RepositoryConflict(
                    "Response is not in the owned final verification state"
                )
            plan = self.lifecycle._get_plan(
                conn, lease.application_id, current.request.plan_id
            )
            if (
                tuple(s.action for s in plan.steps) != ACTIONS
                or plan.command(
                    "switch_route", operation_id=lease.operation_id, epoch=lease.epoch
                )
                != command
            ):
                raise ContractError("Completion differs from the exact response plan")
            conn.execute(
                "SELECT revision FROM sova_control.approvals WHERE tenant_id=%s AND application_id=%s AND approval_id=%s FOR SHARE",
                (self.tenant_id, lease.application_id, current.request.approval_id),
            ).fetchone()
            saved = self.lifecycle._get_approval(
                conn, lease.application_id, current.request.approval_id
            )
            if (
                saved.revoked
                or saved.revision != current.request.approval_revision
                or saved.plan_id != plan.plan_id
            ):
                raise ContractError(
                    "Response approval revoked or changed before completion"
                )
            holds = PostgresSecurityHolds(
                self.lifecycle.connect, tenant_id=self.tenant_id
            )._active(conn, lease.application_id)
            expected_holds = plan.steps[0].parameters_json
            import json

            expected_holds = json.loads(expected_holds).get("hold_ids")
            if (
                type(expected_holds) is not list
                or not expected_holds
                or {h.hold.hold_id for h in holds} != set(expected_holds)
                or any(
                    h.hold.scope != plan.steps[0].scope or not h.active for h in holds
                )
            ):
                raise ContractError("Response incident holds changed before completion")
            journal = PostgresEffectJournal(ownership, lease)
            receipts = []
            for step in plan.steps:
                expected = plan.command(
                    step.step_id, operation_id=lease.operation_id, epoch=lease.epoch
                )
                row = journal._row(conn, expected)
                if row is None:
                    raise ContractError("Response effect receipt is missing")
                receipt = journal._decode(row)
                if (
                    receipt.status != EffectStatus.APPLIED
                    or receipt.command != expected
                ):
                    raise ContractError(
                        "Response effects are not all applied in this epoch"
                    )
                receipts.append(receipt)
            _, database_now = ownership.require_current(conn, lease)
            saved.approval.require_valid(plan, database_now)
            observed = completion.observation.observed_at
            if (
                not receipts[-1].observation.observed_at
                <= observed
                <= database_now
                < min(completion.verified_until, observed + timedelta(seconds=15))
            ):
                raise ContractError(
                    "Final response readback or verification window expired"
                )
            if completion.verified_until > min(
                plan.valid_until, saved.approval.valid_until
            ):
                raise ContractError("Response completion exceeds approval validity")
            conn.execute(
                "INSERT INTO sova_control.security_response_completions (tenant_id,application_id,operation_id,digest,document) VALUES(%s,%s,%s,%s,%s)",
                (
                    self.tenant_id,
                    lease.application_id,
                    lease.operation_id,
                    completion.fingerprint,
                    Jsonb(completion.document),
                ),
            )
            finished = self._advance_locked(
                conn,
                current,
                OperationStatus.RESPONSE_VERIFIED,
                expected_revision=expected_revision,
                actor_id=lease.owner_id,
                now=database_now,
            )
            ownership._release_locked(conn, lease, completion.fingerprint)
            return finished, completion

    def get_response_completion(self, application_id, operation_id):
        from sova.adapters.response_completion_codec import decode_response_completion
        from sova.adapters.plan_codec import document_hash

        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                "SELECT digest,document FROM sova_control.security_response_completions WHERE tenant_id=%s AND application_id=%s AND operation_id=%s",
                (self.tenant_id, application_id, operation_id),
            ).fetchone()
            if row is None:
                raise RecordNotFound(
                    "Response completion not found; legacy receipt is not requalified"
                )
            current = self._get(conn, application_id, operation_id)
            if current.state.status != OperationStatus.RESPONSE_VERIFIED:
                raise ContractError("Response completion and operation disagree")
            plan = self.lifecycle._get_plan(
                conn, application_id, current.request.plan_id
            )
            proof = decode_response_completion(row[1], plan)
            if (
                proof.command.operation_id != operation_id
                or proof.fingerprint != row[0]
                or document_hash(row[1]) != row[0]
            ):
                raise ContractError("Response completion integrity/scope mismatch")
            return current, proof

    def claim(self, application_id, owner_id, *, lease_seconds=30):
        identifier(application_id, "application_id")
        identifier(owner_id, "owner_id")
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ContractError("Bounded outbox lease required")
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                """SELECT event_id FROM sova_control.operation_outbox
                WHERE tenant_id=%s AND application_id=%s AND published_at IS NULL AND suppressed_at IS NULL
                  AND (lease_until IS NULL OR lease_until<=clock_timestamp())
                ORDER BY created_at,event_id FOR UPDATE SKIP LOCKED LIMIT 1""",
                (self.tenant_id, application_id),
            ).fetchone()
            if not row:
                return None
            token = uuid4().hex
            result = conn.execute(
                """UPDATE sova_control.operation_outbox SET owner_id=%s,lease_token=%s,
                lease_until=clock_timestamp()+make_interval(secs=>%s),attempt=attempt+1
                WHERE tenant_id=%s AND application_id=%s AND event_id=%s
                RETURNING operation_id,event_id,attempt,lease_until,payload""",
                (
                    owner_id,
                    token,
                    lease_seconds,
                    self.tenant_id,
                    application_id,
                    row[0],
                ),
            ).fetchone()
            operation = self._get(conn, application_id, result[0])
            if result[4] != self._payload(operation.request):
                raise ContractError("Outbox payload does not match operation")
            return OutboxDelivery(
                self.tenant_id,
                application_id,
                result[0],
                result[1],
                owner_id,
                token,
                result[2],
                result[3],
                canonical_json(result[4]),
            )

    def acknowledge(self, delivery: OutboxDelivery, receipt: PublishReceipt) -> None:
        if (
            delivery.tenant_id != self.tenant_id
            or receipt.event_id != delivery.event_id
        ):
            raise ContractError("Outbox receipt scope mismatch")
        with self.lifecycle.transaction() as conn:
            updated = conn.execute(
                """UPDATE sova_control.operation_outbox SET published_at=clock_timestamp(),
                publisher_id=%s,message_id=%s,owner_id=NULL,lease_token=NULL,lease_until=NULL
                WHERE tenant_id=%s AND application_id=%s AND event_id=%s AND operation_id=%s
                  AND owner_id=%s AND lease_token=%s AND lease_until>clock_timestamp()
                  AND published_at IS NULL AND suppressed_at IS NULL RETURNING event_id""",
                (
                    receipt.publisher_id,
                    receipt.message_id,
                    self.tenant_id,
                    delivery.application_id,
                    delivery.event_id,
                    delivery.operation_id,
                    delivery.owner_id,
                    delivery.lease_token,
                ),
            ).fetchone()
            if not updated:
                raise LeaseLost("Outbox delivery lease lost or operation suppressed")
