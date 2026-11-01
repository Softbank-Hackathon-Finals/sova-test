"""Scoped lifecycle persistence. No migrations or implicit connection fallback.

Use a non-owner, non-superuser, NOBYPASSRLS role. The tenant context must be
selected by trusted authentication, not taken from a request document.
"""

from contextlib import contextmanager
from datetime import UTC, datetime

from psycopg.types.json import Jsonb

from sova.adapters.plan_codec import (
    decode_approval,
    decode_inspection,
    decode_plan,
    document_hash,
    encode_approval,
    encode_inspection,
)
from sova.domain.contracts import ContractError, identifier
from sova.ports.plans import RecordNotFound, RepositoryConflict, StoredApproval


class PostgresLifecycleRepository:
    def __init__(self, connect, *, tenant_id, clock=lambda: datetime.now(UTC)):
        identifier(tenant_id, "tenant_id")
        self.connect, self.tenant_id, self.clock = connect, tenant_id, clock

    @contextmanager
    def transaction(self):
        with self.connect() as conn:
            with conn.transaction():
                privileged = conn.execute("""SELECT rolsuper OR rolbypassrls OR EXISTS (
                    SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                    WHERE n.nspname='sova_control' AND c.relowner=pg_roles.oid)
                    FROM pg_roles WHERE rolname=current_user""").fetchone()
                if not privileged or privileged[0]:
                    raise ContractError(
                        "Lifecycle runtime role must not own or bypass row security"
                    )
                conn.execute(
                    "SELECT set_config('sova.tenant_id',%s,true)", (self.tenant_id,)
                )
                yield conn

    def require_scope(self, scope):
        if scope.tenant_id != self.tenant_id:
            raise ContractError("Repository tenant scope mismatch")

    @staticmethod
    def audit(conn, tenant, app, record, action, actor, revision):
        conn.execute(
            """INSERT INTO sova_control.lifecycle_audit
            (tenant_id,application_id,record_id,action,actor_id,revision)
            VALUES(%s,%s,%s,%s,%s,%s)""",
            (tenant, app, record, action, actor, revision),
        )

    def save_plan(self, plan):
        if plan.tenant_id != self.tenant_id:
            raise ContractError("Repository tenant scope mismatch")
        with self.transaction() as conn:
            changed = conn.execute(
                """INSERT INTO sova_control.plans
                (tenant_id,application_id,plan_id,digest,document) VALUES(%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING RETURNING plan_id""",
                (
                    self.tenant_id,
                    plan.application_id,
                    plan.plan_id,
                    plan.fingerprint,
                    Jsonb(plan.document),
                ),
            ).fetchone()
            row = conn.execute(
                "SELECT digest FROM sova_control.plans WHERE tenant_id=%s AND application_id=%s AND plan_id=%s",
                (self.tenant_id, plan.application_id, plan.plan_id),
            ).fetchone()
            if not row or row[0] != plan.fingerprint:
                raise RepositoryConflict(
                    "Plan ID already has different immutable content"
                )
            if changed:
                self.audit(
                    conn,
                    self.tenant_id,
                    plan.application_id,
                    plan.plan_id,
                    "plan_created",
                    plan.created_by,
                    1,
                )

    def _get_plan(self, conn, app, plan_id):
        row = conn.execute(
            "SELECT digest,document FROM sova_control.plans WHERE tenant_id=%s AND application_id=%s AND plan_id=%s",
            (self.tenant_id, app, plan_id),
        ).fetchone()
        if not row:
            raise RecordNotFound("Plan not found")
        plan = decode_plan(row[1])
        if (plan.tenant_id, plan.application_id, plan.plan_id, plan.fingerprint) != (
            self.tenant_id,
            app,
            plan_id,
            row[0],
        ):
            raise ContractError("Stored plan integrity or scope mismatch")
        return plan

    def get_plan(self, application_id, plan_id):
        with self.transaction() as conn:
            return self._get_plan(conn, application_id, plan_id)

    def save_inspection(self, inspection_id, inspection):
        identifier(inspection_id, "inspection_id")
        self.require_scope(inspection.scope)
        data = encode_inspection(inspection)
        fingerprint = document_hash(data)
        app = inspection.scope.application_id
        with self.transaction() as conn:
            conn.execute(
                """INSERT INTO sova_control.inspections
                (tenant_id,application_id,inspection_id,digest,document) VALUES(%s,%s,%s,%s,%s)
                ON CONFLICT DO NOTHING""",
                (self.tenant_id, app, inspection_id, fingerprint, Jsonb(data)),
            )
            row = conn.execute(
                "SELECT digest FROM sova_control.inspections WHERE tenant_id=%s AND application_id=%s AND inspection_id=%s",
                (self.tenant_id, app, inspection_id),
            ).fetchone()
            if not row or row[0] != fingerprint:
                raise RepositoryConflict(
                    "Inspection ID already has different immutable content"
                )

    def get_inspection(self, application_id, inspection_id):
        with self.transaction() as conn:
            row = conn.execute(
                "SELECT digest,document FROM sova_control.inspections WHERE tenant_id=%s AND application_id=%s AND inspection_id=%s",
                (self.tenant_id, application_id, inspection_id),
            ).fetchone()
            if not row:
                raise RecordNotFound("Inspection not found")
            value = decode_inspection(row[1])
            self.require_scope(value.scope)
            if (
                value.scope.application_id != application_id
                or document_hash(row[1]) != row[0]
            ):
                raise ContractError("Stored inspection integrity or scope mismatch")
            return value

    def save_approval(self, application_id, plan_id, approval_id, approval):
        identifier(approval_id, "approval_id")
        with self.transaction() as conn:
            plan = self._get_plan(conn, application_id, plan_id)
            approval.require_valid(plan, self.clock())
            data = encode_approval(approval)
            changed = conn.execute(
                """INSERT INTO sova_control.approvals
                (tenant_id,application_id,approval_id,plan_id,plan_digest,document)
                VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING approval_id""",
                (
                    self.tenant_id,
                    application_id,
                    approval_id,
                    plan_id,
                    approval.plan_digest,
                    Jsonb(data),
                ),
            ).fetchone()
            result = self._get_approval(conn, application_id, approval_id)
            if (
                result.plan_id != plan_id
                or result.approval != approval
                or result.revoked
            ):
                raise RepositoryConflict(
                    "Approval ID cannot be replaced or reactivated"
                )
            if changed:
                self.audit(
                    conn,
                    self.tenant_id,
                    application_id,
                    approval_id,
                    "approval_created",
                    approval.approved_by,
                    1,
                )
            return result

    def _get_approval(self, conn, app, approval_id):
        row = conn.execute(
            """SELECT plan_id,plan_digest,document,revision,revoked_at
            FROM sova_control.approvals WHERE tenant_id=%s AND application_id=%s AND approval_id=%s""",
            (self.tenant_id, app, approval_id),
        ).fetchone()
        if not row:
            raise RecordNotFound("Approval not found")
        approval = decode_approval(row[2])
        if approval.plan_digest != row[1]:
            raise ContractError("Stored approval integrity mismatch")
        plan = self._get_plan(conn, app, row[0])
        if (
            plan.fingerprint != approval.plan_digest
            or plan.purpose != approval.purpose
            or plan.created_by == approval.approved_by
        ):
            raise ContractError("Stored approval plan binding mismatch")
        return StoredApproval(approval_id, row[0], approval, row[3], row[4] is not None)

    def get_approval(self, application_id, approval_id):
        with self.transaction() as conn:
            return self._get_approval(conn, application_id, approval_id)

    def revoke_approval(
        self, application_id, approval_id, *, expected_revision, actor_id
    ):
        if type(expected_revision) is not int or expected_revision < 1:
            raise ContractError("Positive approval revision required")
        identifier(actor_id, "actor_id")
        with self.transaction() as conn:
            self._get_approval(conn, application_id, approval_id)
            changed = conn.execute(
                """UPDATE sova_control.approvals
                SET revoked_at=clock_timestamp(),revision=revision+1
                WHERE tenant_id=%s AND application_id=%s AND approval_id=%s
                  AND revision=%s AND revoked_at IS NULL RETURNING revision""",
                (self.tenant_id, application_id, approval_id, expected_revision),
            ).fetchone()
            if not changed:
                raise RepositoryConflict("Approval revision changed or already revoked")
            self.audit(
                conn,
                self.tenant_id,
                application_id,
                approval_id,
                "approval_revoked",
                actor_id,
                changed[0],
            )
            return self._get_approval(conn, application_id, approval_id)
