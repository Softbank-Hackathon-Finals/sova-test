from dataclasses import replace
import pytest
from protection_support import protection_bundle, protection_profile
from sova.domain.contracts import ContractError
from sova.domain.protection_profiles import production_protection_profile
from sova.adapters.protection_codec import decode_protection_policy


def test_profile_is_bound_into_policy_and_cannot_be_removed_by_approval(scope, now):
    policy, *_ = protection_bundle(scope, now)
    profile = protection_profile()
    profile.require_policy(policy)
    for changed in [
        replace(policy, profile_digest=None),
        replace(policy, profile_digest="f" * 64),
    ]:
        with pytest.raises(ContractError):
            profile.require_policy(changed)
    weakened = replace(
        policy,
        requirements=(
            replace(policy.requirements[0], requirement_id="different-objective"),
        ),
    )
    with pytest.raises(ContractError, match="omitted"):
        profile.require_policy(weakened)


def test_configuration_only_evidence_cannot_satisfy_runtime_protection_profile(
    scope, now
):
    policy, *_ = protection_bundle(scope, now)
    profile = protection_profile()
    req = policy.requirements[0]
    substituted = replace(
        req,
        target=replace(req.target, verifier_version="sova-kubernetes-configuration-v1"),
    )
    with pytest.raises(ContractError, match="Configuration"):
        profile.require_policy(replace(policy, requirements=(substituted,)))
    production = production_protection_profile()
    with pytest.raises(ContractError, match="omitted"):
        production.require_policy(
            replace(policy, profile_digest=production.fingerprint)
        )
    assert len(production.objectives) == 7
    assert {o.family.value for o in production.objectives} == {
        "identity",
        "secrets",
        "network",
        "encryption",
        "audit",
        "backup",
    }


def test_v2_profile_digest_is_required_and_v1_is_never_implicitly_qualified(scope, now):
    policy, *_ = protection_bundle(scope, now)
    data = policy.document
    data.pop("profile_digest")
    with pytest.raises(ContractError):
        decode_protection_policy(data)
    data["schema_version"] = 1
    decoded = decode_protection_policy(data)
    assert decoded.profile_digest is None
    with pytest.raises(ContractError):
        protection_profile().require_policy(decoded)
