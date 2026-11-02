"""Immutable postflight receipts for the fixed stateless qualification only.

A route effect proves CAS, not business availability. A missing receipt stays
unverified after restart; reading history never replays a route effect.
"""

import hashlib

from psycopg.types.json import Jsonb

from sova.domain.contracts import (
    ContractError,
    EffectCommand,
    canonical_json,
    digest,
    identifier,
)
from sova.ports.plans import RepositoryConflict


class RelocationReceipts:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle

    def save(
        self,
        application_id,
        *,
        operation_id,
        plan_digest,
        effect_digest,
        registration_digest,
        target,
        route_revision,
        postflight,
    ):
        for value in (application_id, operation_id):
            identifier(value)
        for value in (plan_digest, effect_digest, registration_digest):
            digest(value)
        if (
            target not in {"aws", "vm"}
            or type(route_revision) is not int
            or route_revision < 2
            or type(postflight) is not dict
            or postflight.get("ok") is not True
            or postflight.get("environment") != target
            or postflight.get("total") != 220
            or type(postflight.get("id")) is not str
            or len(postflight["id"]) != 32
        ):
            raise ContractError("Actual fixed-profile postflight required")
        document = {
            "profile": "eks-rke2-stateless-v1",
            "operation_id": operation_id,
            "plan_digest": plan_digest,
            "effect_digest": effect_digest,
            "registration_digest": registration_digest,
            "target": target,
            "route_revision": route_revision,
            "postflight": postflight,
            "full_migration_verified": False,
        }
        checksum = hashlib.sha256(canonical_json(document).encode()).hexdigest()
        with self.lifecycle.transaction() as conn:
            existing = conn.execute(
                """SELECT digest FROM sova_control.relocation_receipts
                WHERE tenant_id=%s AND application_id=%s AND operation_id=%s""",
                (self.lifecycle.tenant_id, application_id, operation_id),
            ).fetchone()
            if existing:
                if existing[0] != checksum:
                    raise RepositoryConflict("Postflight receipt is immutable")
                return
            # Check persisted effect and current CAS, independently of the caller's claim.
            bound = conn.execute(
                """SELECT e.command_document FROM sova_control.operations o
                JOIN sova_control.effects e USING(tenant_id,application_id,operation_id)
                JOIN sova_control.security_routes r USING(tenant_id,application_id)
                WHERE o.tenant_id=%s AND o.application_id=%s AND o.operation_id=%s
                AND o.plan_digest=%s AND e.fingerprint=%s AND e.status='confirmed_applied'
                AND r.route_id='quote-entry' AND r.plan_digest=o.plan_digest
                AND r.target_environment=%s AND r.revision=%s""",
                (
                    self.lifecycle.tenant_id,
                    application_id,
                    operation_id,
                    plan_digest,
                    effect_digest,
                    target,
                    route_revision,
                ),
            ).fetchone()
            if not bound:
                raise ContractError("Postflight does not match persisted route effect")
            command = EffectCommand.from_document(bound[0])
            if (
                command.fingerprint != effect_digest
                or command.adapter_id != "owned-stateless-route-cas"
                or command.action != "switch_route"
                or command.scope.environment_id != "local-entry"
                or command.scope.resource_id != "quote-entry"
                or command.parameters.get("target") != target
                or command.parameters.get("route_revision") != route_revision - 1
                or command.parameters.get("registration") != registration_digest
            ):
                raise ContractError("Postflight bound to a different kind of effect")
            conn.execute(
                """INSERT INTO sova_control.relocation_receipts
                (tenant_id,application_id,operation_id,digest,document) VALUES(%s,%s,%s,%s,%s)""",
                (
                    self.lifecycle.tenant_id,
                    application_id,
                    operation_id,
                    checksum,
                    Jsonb(document),
                ),
            )

    def history(self, application_id, registration_digest):
        identifier(application_id)
        digest(registration_digest)
        with self.lifecycle.transaction() as conn:
            rows = conn.execute(
                """SELECT c.digest,c.document,c.recorded_at FROM sova_control.relocation_receipts c
                WHERE tenant_id=%s AND application_id=%s ORDER BY recorded_at DESC LIMIT 20""",
                (self.lifecycle.tenant_id, application_id),
            ).fetchall()
            unresolved = conn.execute(
                """SELECT e.command_document,max(v.recorded_at) FROM sova_control.effects e
                JOIN sova_control.effect_events v USING(tenant_id,application_id,idempotency_key)
                LEFT JOIN sova_control.relocation_receipts c USING(tenant_id,application_id,operation_id)
                WHERE e.tenant_id=%s AND e.application_id=%s AND c.operation_id IS NULL
                AND e.status IN ('prepared','in_flight','unknown','confirmed_applied')
                GROUP BY e.fingerprint,e.command_document ORDER BY max(v.recorded_at) DESC LIMIT 20""",
                (self.lifecycle.tenant_id, application_id),
            ).fetchall()
        results = []
        for checksum, doc, recorded in rows:
            if hashlib.sha256(canonical_json(doc).encode()).hexdigest() != checksum:
                raise ContractError("Stored postflight receipt checksum mismatch")
            if doc["registration_digest"] != registration_digest:
                continue
            results.append(
                {
                    "id": doc["operation_id"],
                    "target": doc["target"],
                    "status": "succeeded",
                    "historical": True,
                    "receipt_digest": checksum,
                    "full_migration_verified": False,
                    "plan_digest": doc["plan_digest"],
                    "effect_digest": doc["effect_digest"],
                    "steps": [
                        {
                            "id": "postflight",
                            "label": "이전 실행의 경로·업무 응답 검증 기록 (현재 관측과 별도)",
                            "status": "succeeded",
                            "completed_at": recorded.timestamp(),
                        }
                    ],
                }
            )
        for document, recorded in unresolved:
            command = EffectCommand.from_document(document)
            if (
                command.adapter_id != "owned-stateless-route-cas"
                or command.action != "switch_route"
                or command.parameters.get("registration") != registration_digest
            ):
                continue
            results.append(
                {
                    "id": command.operation_id,
                    "target": command.parameters["target"],
                    "status": "needs_attention",
                    "historical": True,
                    "full_migration_verified": False,
                    "plan_digest": command.plan_digest,
                    "effect_digest": command.fingerprint,
                    "steps": [
                        {
                            "id": "missing-postflight",
                            "label": "업무 검증 영수증 없음 · 효과 재조회 및 운영자 검토 필요",
                            "status": "needs_attention",
                            "completed_at": recorded.timestamp(),
                        }
                    ],
                }
            )
        return sorted(
            results, key=lambda r: r["steps"][0]["completed_at"], reverse=True
        )[:20]
