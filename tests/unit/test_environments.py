from dataclasses import replace
from datetime import timedelta

import pytest

from sova.domain.contracts import ContractError
from sova.domain.environments import BackendCapability, FeatureSupport as S, Provider


@pytest.fixture
def capability(now):
    return BackendCapability(
        Provider.AWS,
        "ecs_express",
        "http_container",
        S.SUPPORTED,
        True,
        "a" * 64,
        now + timedelta(minutes=1),
    )


def test_provider_backend_does_not_imply_other_backend_support(capability, now):
    assert capability.can_execute(profile_digest="a" * 64, now=now, live_ready=True)
    standard = replace(capability, backend="ecs_standard", implemented_by_sova=False)
    assert not standard.can_execute(profile_digest="a" * 64, now=now, live_ready=True)


@pytest.mark.parametrize(
    "changes",
    [
        {"provider_support": S.UNKNOWN},
        {"provider_support": S.UNSUPPORTED},
        {"implemented_by_sova": False},
        {"qualified_profile_digest": None, "qualification_valid_until": None},
    ],
)
def test_provider_implementation_qualification_are_independent(
    capability, now, changes
):
    assert not replace(capability, **changes).can_execute(
        profile_digest="a" * 64, now=now, live_ready=True
    )


def test_live_expiry_and_qualification_profile_are_checked(capability, now):
    assert not capability.can_execute(
        profile_digest="a" * 64, now=now, live_ready=False
    )
    assert not capability.can_execute(profile_digest="b" * 64, now=now, live_ready=True)
    assert not capability.can_execute(
        profile_digest="a" * 64,
        now=capability.qualification_valid_until,
        live_ready=True,
    )


def test_half_qualification_is_rejected(capability):
    with pytest.raises(ContractError):
        replace(capability, qualification_valid_until=None)
