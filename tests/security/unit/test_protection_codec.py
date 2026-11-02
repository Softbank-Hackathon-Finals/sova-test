from copy import deepcopy
import pytest
from protection_support import protection_bundle
from sova.adapters.protection_codec import decode_protection_policy
from sova.domain.contracts import ContractError


def test_policy_roundtrip_and_no_raw_provider_extension(scope, now):
    policy, *_ = protection_bundle(scope, now)
    assert decode_protection_policy(policy.document) == policy
    for where in ["root", "endpoint", "scope", "requirement"]:
        data = deepcopy(policy.document)
        target = {
            "root": data,
            "endpoint": data["requirements"][0]["target"],
            "scope": data["requirements"][0]["target"]["scope"],
            "requirement": data["requirements"][0],
        }[where]
        target["raw_provider_payload"] = {"SecretString": "do not copy"}
        with pytest.raises(ContractError):
            decode_protection_policy(data)


@pytest.mark.parametrize("version", [True, "1", 3, None])
def test_wrong_schema_versions_never_coerce(version, scope, now):
    policy, *_ = protection_bundle(scope, now)
    data = policy.document
    data["schema_version"] = version
    with pytest.raises(ContractError):
        decode_protection_policy(data)
