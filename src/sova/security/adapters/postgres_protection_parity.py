"""Append-only protection policies and plan-bound assessment history.

DB roles must separate policy publishing, evidence verification, and execution.
Stored reports are historical; a previous PASS is never a current execution grant.
"""

from datetime import datetime
from psycopg.types.json import Jsonb
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.plan_codec import document_hash
from sova.security.adapters.protection_codec import decode_protection_policy
from sova.domain.contracts import ContractError, identifier, digest
from sova.security.domain.protection_parity import assess_protection
from sova.security.domain.signed_evidence import evidence_document
from sova.ports.plans import RecordNotFound, RepositoryConflict


class PostgresProtectionParity:
    def __init__(self, connect, *, tenant_id):
        self.tenant_id = identifier(tenant_id)
        self._transactions = PostgresLifecycleRepository(connect, tenant_id=tenant_id)

    def _policy(self, app, row):
        if not row:
            raise RecordNotFound("Protection policy not found")
        policy = decode_protection_policy(row[2])
        if (
            policy.tenant_id,
            policy.application_id,
            policy.revision,
            policy.fingerprint,
        ) != (self.tenant_id, app, row[0], row[1]):
            raise ContractError("Protection policy integrity/scope mismatch")
        return policy

    def latest_policy(self, application_id):
        identifier(application_id)
        with self._transactions.transaction() as conn:
            return self._policy(
                application_id,
                conn.execute(
                    "SELECT revision,digest,document FROM sova_control.protection_policies WHERE tenant_id=%s AND application_id=%s ORDER BY revision DESC LIMIT 1",
                    (self.tenant_id, application_id),
                ).fetchone(),
            )

    def publish_policy(self, policy, *, actor, expected_revision):
        identifier(actor)
        if (
            policy.tenant_id != self.tenant_id
            or type(expected_revision) is not int
            or expected_revision < 0
            or policy.revision != expected_revision + 1
        ):
            raise ContractError("Exact protection publication revision/scope required")
        with self._transactions.transaction() as conn:
            key = document_hash(
                {
                    "tenant": self.tenant_id,
                    "app": policy.application_id,
                    "purpose": "protection-policy",
                }
            )
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))
            row = conn.execute(
                "SELECT revision,digest,document FROM sova_control.protection_policies WHERE tenant_id=%s AND application_id=%s ORDER BY revision DESC LIMIT 1",
                (self.tenant_id, policy.application_id),
            ).fetchone()
            if row and row[0] == policy.revision and row[1] == policy.fingerprint:
                return self._policy(policy.application_id, row)
            if (row[0] if row else 0) != expected_revision:
                raise RepositoryConflict("Protection policy publication lost CAS")
            now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
            if not policy.issued_at <= now < policy.valid_until:
                raise ContractError("Current protection policy required")
            conn.execute(
                "INSERT INTO sova_control.protection_policies (tenant_id,application_id,revision,digest,document,published_by) VALUES(%s,%s,%s,%s,%s,%s)",
                (
                    self.tenant_id,
                    policy.application_id,
                    policy.revision,
                    policy.fingerprint,
                    Jsonb(policy.document),
                    actor,
                ),
            )
        return policy

    def record_assessment(self, plan, policy, evidence, report):
        if (plan.tenant_id, plan.application_id, plan.revisions.policy) != (
            self.tenant_id,
            policy.application_id,
            policy.fingerprint,
        ):
            raise ContractError("Assessment plan/policy scope mismatch")
        expected = assess_protection(
            policy, evidence, now=datetime.fromisoformat(report["assessed_at"])
        )
        holds = report.get("active_holds")
        if type(holds) is not list or len(holds) > 256 or len(set(holds)) != len(holds):
            raise ContractError("Bounded unique active holds required")
        for hold in holds:
            identifier(hold)
        expected["active_holds"] = holds
        expected["accepted"] = expected["accepted"] and not holds
        if report != expected:
            raise ContractError("Protection assessment report was altered")
        document = {
            "schema_version": 1,
            "tenant_id": self.tenant_id,
            "application_id": policy.application_id,
            "plan_digest": plan.fingerprint,
            "policy_digest": policy.fingerprint,
            "evidence": [
                {
                    "evidence_id": e.evidence_id,
                    "digest": document_hash(evidence_document(e)),
                }
                for e in sorted(evidence, key=lambda e: e.evidence_id)
            ],
            "report": report,
        }
        fingerprint = document_hash(document)
        with self._transactions.transaction() as conn:
            # Resolve current policy in the same transaction as history insertion.
            row = conn.execute(
                "SELECT revision,digest,document FROM sova_control.protection_policies WHERE tenant_id=%s AND application_id=%s ORDER BY revision DESC LIMIT 1",
                (self.tenant_id, policy.application_id),
            ).fetchone()
            if self._policy(policy.application_id, row) != policy:
                raise RepositoryConflict(
                    "Protection policy changed before assessment recording"
                )
            if (
                datetime.fromisoformat(report["assessed_at"])
                > conn.execute("SELECT clock_timestamp()").fetchone()[0]
            ):
                raise ContractError("Future protection assessment")
            conn.execute(
                "INSERT INTO sova_control.protection_assessments (tenant_id,application_id,digest,policy_digest,plan_digest,assessed_at,document) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (
                    self.tenant_id,
                    policy.application_id,
                    fingerprint,
                    policy.fingerprint,
                    plan.fingerprint,
                    report["assessed_at"],
                    Jsonb(document),
                ),
            )
        return fingerprint

    def get_assessment(self, application_id, fingerprint):
        identifier(application_id)
        digest(fingerprint)
        with self._transactions.transaction() as conn:
            row = conn.execute(
                "SELECT document,policy_digest,plan_digest,assessed_at FROM sova_control.protection_assessments WHERE tenant_id=%s AND application_id=%s AND digest=%s",
                (self.tenant_id, application_id, fingerprint),
            ).fetchone()
            if not row:
                raise RecordNotFound("Protection assessment not found")
            doc = row[0]
            if document_hash(doc) != fingerprint or (
                doc.get("tenant_id"),
                doc.get("application_id"),
                doc.get("policy_digest"),
                doc.get("plan_digest"),
                datetime.fromisoformat(doc["report"]["assessed_at"]),
            ) != (self.tenant_id, application_id, row[1], row[2], row[3]):
                raise ContractError("Protection assessment integrity/scope mismatch")
            return doc
