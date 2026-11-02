"""Independent-authority fixtures; these facts are test inputs, not live proof."""

from dataclasses import replace
from datetime import timedelta
from sova.domain.protection_parity import (
    Availability,
    ProtectionEndpoint,
    ProtectionRequirement,
    ProtectionPolicy,
)
from sova.domain.governance import ControlFamily
from sova.domain.protection_profiles import ProtectionProfile, ProtectionObjective
from sova.domain.evidence import (
    EvidenceRecord,
    Gate,
    VerificationResult,
    VerificationObligation,
)
from sova.domain.plans import LifecyclePlan, PlanStep, PlanPurpose, PlanApproval


def protection_profile():
    return ProtectionProfile(
        "test-identity-denial-only",
        1,
        (
            ProtectionObjective(
                "cross-app-secret-denial",
                ControlFamily.IDENTITY,
                ("identity-denial-probe-v1",),
            ),
        ),
    )


def protection_bundle(scope, now):
    source = ProtectionEndpoint(
        scope,
        "aws",
        "iam-role",
        Availability.AVAILABLE,
        Availability.AVAILABLE,
        "a" * 64,
        "b" * 64,
        "c" * 64,
        "identity-denial-probe-v1",
    )
    target = replace(
        source,
        scope=replace(scope, environment_id="onprem", resource_id="target-resource"),
        provider="onprem",
        implementation="kubernetes-rbac",
        environment_digest="d" * 64,
    )
    requirement = ProtectionRequirement(
        "cross-app-secret-denial",
        ControlFamily.IDENTITY,
        "Another application must not read this application secret",
        source,
        target,
    )
    policy = ProtectionPolicy(
        scope.tenant_id,
        scope.application_id,
        1,
        (requirement,),
        now - timedelta(seconds=1),
        now + timedelta(minutes=5),
        protection_profile().fingerprint,
    )
    evidence = tuple(
        EvidenceRecord(
            "e:" + side,
            requirement.obligation(side).obligation_id,
            ep.scope,
            ep.revisions(policy.fingerprint),
            ep.verifier_version,
            now,
            now + timedelta(minutes=4),
            VerificationResult.PASS,
            "sanitized-test-proof",
            "f" * 64,
        )
        for side, ep in [("source", source), ("target", target)]
    )
    obligation = VerificationObligation(
        "plan-preflight", target.scope, Gate.PREFLIGHT, "plan-preflight-v1"
    )
    plan = LifecyclePlan(
        "parity-plan",
        scope.tenant_id,
        scope.application_id,
        "planner",
        PlanPurpose.CHANGE,
        target.revisions(policy.fingerprint),
        now + timedelta(minutes=3),
        (
            PlanStep(
                "isolate",
                target.scope,
                "test-ingress",
                "set_ingress",
                '{"blocked":true}',
                "r1",
            ),
        ),
        (obligation,),
    )
    approval = PlanApproval(
        plan.fingerprint, "approver", plan.purpose, plan.valid_until
    )
    preflight = EvidenceRecord(
        "plan-e",
        obligation.obligation_id,
        target.scope,
        plan.revisions,
        obligation.verifier_version,
        now,
        plan.valid_until,
        VerificationResult.PASS,
        "preflight-proof",
        "e" * 64,
    )
    return policy, evidence, plan, approval, preflight
