from support import IngressAdapter
from datetime import UTC, datetime, timedelta

import pytest

from sova.domain.contracts import (
    EffectCommand,
    ResourceScope,
    canonical_json,
)


@pytest.fixture
def now(request):
    if request.node.get_closest_marker("postgres"):
        return datetime.now(UTC)
    return datetime(2026, 10, 31, 7, 0, tzinfo=UTC)


@pytest.fixture
def scope():
    return ResourceScope("tenant-a", "app-a", "environment-a", "owned-ingress")


@pytest.fixture
def command(scope, now):
    return EffectCommand(
        scope,
        "operation-1",
        "isolate",
        "test-ingress",
        "set_ingress",
        "operation-1:isolate",
        "a" * 64,
        "revision-1",
        1,
        now + timedelta(minutes=10),
        canonical_json({"blocked": True}),
    )


@pytest.fixture
def adapter():
    return IngressAdapter()


pytest_plugins = ["postgres_fixtures"]
