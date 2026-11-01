"""Strict domain reconstruction at the persistence boundary."""

from datetime import datetime

from sova.domain.contracts import ContractError, ResourceScope, canonical_json
from sova.domain.evidence import Gate, RevisionSet, VerificationObligation
from sova.domain.plans import (
    Inspection,
    LifecyclePlan,
    PlanApproval,
    PlanPurpose,
    PlanStep,
)


def fields(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise ContractError("Stored document schema mismatch")
    return value


def decode_plan(value: dict) -> LifecyclePlan:
    fields(
        value,
        (
            "plan_id",
            "tenant_id",
            "application_id",
            "created_by",
            "purpose",
            "revisions",
            "valid_until",
            "steps",
            "obligations",
            "origin_plan_digest",
            "reason",
        ),
    )
    if type(value["steps"]) is not list or type(value["obligations"]) is not list:
        raise ContractError("Stored plan collections must be arrays")
    steps = []
    for item in value["steps"]:
        fields(
            item,
            (
                "step_id",
                "scope",
                "adapter_id",
                "action",
                "parameters_json",
                "expected_revision",
                "depends_on",
            ),
        )
        if type(item["depends_on"]) is not list:
            raise ContractError("Stored dependencies must be an array")
        steps.append(
            PlanStep(
                item["step_id"],
                ResourceScope(**item["scope"]),
                item["adapter_id"],
                item["action"],
                item["parameters_json"],
                item["expected_revision"],
                tuple(item["depends_on"]),
            )
        )
    obligations = []
    for item in value["obligations"]:
        fields(item, ("id", "scope", "due_gate", "verifier", "required"))
        if type(item["due_gate"]) is not int:
            raise ContractError("Stored gate must be an integer")
        obligations.append(
            VerificationObligation(
                item["id"],
                ResourceScope(**item["scope"]),
                Gate(item["due_gate"]),
                item["verifier"],
                item["required"],
            )
        )
    return LifecyclePlan(
        value["plan_id"],
        value["tenant_id"],
        value["application_id"],
        value["created_by"],
        PlanPurpose(value["purpose"]),
        RevisionSet(**value["revisions"]),
        datetime.fromisoformat(value["valid_until"]),
        tuple(steps),
        tuple(obligations),
        value["origin_plan_digest"],
        value["reason"],
    )


def encode_inspection(value: Inspection) -> dict:
    return {
        "scope": {
            name: getattr(value.scope, name)
            for name in ("tenant_id", "application_id", "environment_id", "resource_id")
        },
        "revisions": {
            name: getattr(value.revisions, name)
            for name in ("source", "configuration", "policy", "environment")
        },
        "observed_at": value.observed_at.isoformat(),
        "valid_until": value.valid_until.isoformat(),
        "facts_json": value.facts_json,
        "artifact_digest": value.artifact_digest,
    }


def decode_inspection(value: dict) -> Inspection:
    fields(
        value,
        (
            "scope",
            "revisions",
            "observed_at",
            "valid_until",
            "facts_json",
            "artifact_digest",
        ),
    )
    return Inspection(
        ResourceScope(**value["scope"]),
        RevisionSet(**value["revisions"]),
        datetime.fromisoformat(value["observed_at"]),
        datetime.fromisoformat(value["valid_until"]),
        value["facts_json"],
        value["artifact_digest"],
    )


def encode_approval(value: PlanApproval) -> dict:
    return {
        "plan_digest": value.plan_digest,
        "approved_by": value.approved_by,
        "purpose": str(value.purpose),
        "valid_until": value.valid_until.isoformat(),
    }


def decode_approval(value: dict) -> PlanApproval:
    fields(value, ("plan_digest", "approved_by", "purpose", "valid_until"))
    return PlanApproval(
        value["plan_digest"],
        value["approved_by"],
        PlanPurpose(value["purpose"]),
        datetime.fromisoformat(value["valid_until"]),
    )


def document_hash(value: dict) -> str:
    import hashlib

    return hashlib.sha256(canonical_json(value, limit=262144).encode()).hexdigest()
