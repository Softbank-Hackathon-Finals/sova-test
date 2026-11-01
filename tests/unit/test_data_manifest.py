from dataclasses import replace
from datetime import timedelta

import pytest

from sova.domain.contracts import ContractError
from sova.domain.evidence import RevisionSet
from sova.domain.data_manifest import compare_manifests, manifest_rows


@pytest.fixture
def manifests(scope, now):
    def make(rows, **changes):
        args = dict(
            scope=scope,
            revisions=RevisionSet(*("a" * 64,) * 4),
            dataset_id="messages",
            columns=("id", "room", "body"),
            primary_key=("id",),
            boundary_id="final-boundary-1",
            observed_at=now - timedelta(seconds=1),
            valid_until=now + timedelta(minutes=2),
        )
        args.update(changes)
        return manifest_rows(rows, **args)

    return make


ROWS = [
    {"id": 1, "room": "room-a", "body": "민감한 상담 내용"},
    {"id": 2, "room": "room-a", "body": "reply"},
]


def test_order_independent_data_comparison_does_not_grant_cutover(
    manifests, scope, now
):
    a = manifests(ROWS)
    b = manifests(list(reversed(ROWS)), scope=replace(scope, environment_id="target"))
    result = compare_manifests(a, b, now=now)
    assert result["content_equal"] and not result["cutover_authorized"]
    assert "민감한" not in repr(a)


def test_same_row_count_with_altered_content_is_detected(manifests, scope, now):
    a = manifests(ROWS)
    b = manifests(
        [ROWS[0], {**ROWS[1], "body": "corrupted"}],
        scope=replace(scope, environment_id="target"),
    )
    result = compare_manifests(a, b, now=now)
    assert result["checks"]["row_count"] and result["checks"]["keys_digest"]
    assert not result["content_equal"] and not result["checks"]["content_digest"]


def test_same_count_with_different_primary_keys_is_detected(manifests, scope, now):
    a = manifests(ROWS)
    b = manifests(
        [ROWS[0], {**ROWS[1], "id": 3}], scope=replace(scope, environment_id="target")
    )
    assert not compare_manifests(a, b, now=now)["checks"]["keys_digest"]


@pytest.mark.parametrize(
    "rows",
    [
        [ROWS[0], ROWS[0]],
        [{**ROWS[0], "id": None}],
        [{**ROWS[0], "id": True}],
        [{"id": 1}],
        [{**ROWS[0], "extra": "unregistered"}],
    ],
)
def test_unsupported_rows_fail_closed(manifests, rows):
    with pytest.raises(ContractError):
        manifests(rows)


@pytest.mark.parametrize(
    "change", [{"tenant_id": "other"}, {"application_id": "other"}, {}]
)
def test_cross_scope_or_same_environment_cannot_be_compared(
    manifests, scope, now, change
):
    a = manifests(ROWS)
    b = manifests(ROWS, scope=replace(scope, **change))
    with pytest.raises(ContractError):
        compare_manifests(a, b, now=now)


def test_boundary_drift_and_expired_manifest_are_not_comparable(manifests, scope, now):
    a = manifests(ROWS)
    b = manifests(
        ROWS,
        scope=replace(scope, environment_id="target"),
        boundary_id="different-final-boundary",
    )
    with pytest.raises(ContractError, match="boundary"):
        compare_manifests(a, b, now=now)
    b = replace(b, boundary_id=a.boundary_id, valid_until=now)
    with pytest.raises(ContractError, match="expired"):
        compare_manifests(a, b, now=now)


def test_capacity_and_schema_drift_fail_closed(manifests, scope, now):
    with pytest.raises(ContractError, match="capacity"):
        manifests(ROWS, maximum_rows=1)
    a = manifests(ROWS)
    b = manifests(
        ROWS,
        scope=replace(scope, environment_id="target"),
        columns=("room", "id", "body"),
    )
    assert not compare_manifests(a, b, now=now)["checks"]["schema_digest"]


def test_different_normalization_versions_never_share_a_data_equality_claim(
    manifests, scope, now
):
    source = manifests(ROWS)
    target = replace(
        source,
        scope=replace(scope, environment_id="target"),
        normalization_version="postgres-lossless-v2",
    )
    with pytest.raises(ContractError):
        compare_manifests(source, target, now=now)
