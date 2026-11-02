"""Rebind synthetic patch contracts to an isolated test tenant and clock."""

from dataclasses import fields, is_dataclass, replace
from datetime import datetime
import json
from pathlib import Path

from sova_security.adapters.modernization_codec import decode
from sova_security.contracts.commands import ResourceScope
from sova_security.domain.assessment import assess_risk
from sova_security.domain.patch_reassessment import reassess_patch


def patch_bundle(scope, now):
    data = json.loads(
        (
            Path(__file__).parent / "fixtures/security/synthetic-patch-v1.json"
        ).read_text()
    )

    def restore(value):
        return decode(json.dumps(value).encode())

    originals = tuple(restore(v) for v in data["inputs"])
    delta = now - originals[0].observed_at

    def shift(value):
        if isinstance(value, datetime):
            return value + delta
        if isinstance(value, ResourceScope):
            return scope
        if type(value) is tuple:
            return tuple(shift(v) for v in value)
        if is_dataclass(value):
            return replace(
                value, **{f.name: shift(getattr(value, f.name)) for f in fields(value)}
            )
        return value

    inventory, scan, exposure, policy = tuple(shift(v) for v in originals)
    scan = replace(scan, inventory_digest=inventory.fingerprint)
    exposure = replace(exposure, inventory_digest=inventory.fingerprint)
    inputs = (inventory, scan, exposure, policy)
    assessment = assess_risk(*inputs, now=now)
    request = shift(restore(data["request"]))
    proposal = replace(
        request.proposal,
        assessment_digest=assessment.fingerprint,
        inventory_digest=inventory.fingerprint,
        policy_digest=policy.fingerprint,
        findings=(assessment.decisions[0].fingerprint,),
    )
    request = replace(
        request,
        proposal=proposal,
        targets=(replace(request.targets[0], snapshot_digest=inventory.fingerprint),),
    )
    receipt = shift(restore(data["receipt"]))
    receipt = replace(
        receipt,
        request_digest=request.fingerprint,
        proposal_digest=proposal.fingerprint,
    )
    return inputs, assessment, request, receipt


def patch_rescan(inputs, baseline, proposal, artifact, at):
    """Synthetic fixed-package observations, not a real scanner invocation."""
    inventory = replace(
        inputs[0],
        source_digest=artifact.source_digest,
        image_digest=artifact.image_digest,
        configuration_digest=artifact.configuration_digest,
        resource_revision="resource-v2",
        observed_at=at,
        components=(replace(inputs[0].components[0], version="1.1"),),
    )
    scan = replace(
        inputs[1],
        inventory_digest=inventory.fingerprint,
        image_digest=inventory.image_digest,
        findings=(),
        observed_at=at,
    )
    exposure = replace(
        inputs[2],
        inventory_digest=inventory.fingerprint,
        resource_revision=inventory.resource_revision,
        observed_at=at,
    )
    after = (inventory, scan, exposure, inputs[3])
    result, assessment = reassess_patch(
        proposal,
        artifact,
        baseline,
        before_inputs=inputs,
        after_inputs=after,
        expected_policy_digest=inputs[3].fingerprint,
        not_before=at,
        now=at,
    )
    return result, assessment, after
