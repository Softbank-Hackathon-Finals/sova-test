from dataclasses import replace
from datetime import timedelta

import pytest

from sova.application.examples import example_graph
from sova.domain.contracts import ContractError, ResourceScope
from sova.domain.dependency_requirements import (
    compile_dependency_program,
    dependency_check_catalog,
)
from sova.domain.evidence import Gate, RevisionSet
from sova.domain.system_graph import (
    ResourceKind,
    Portability,
    SystemResource,
)


def compile(graph, now, **changes):
    args = dict(
        graph=graph,
        source_scope=ResourceScope(
            graph.tenant_id, graph.application_id, "source", "application"
        ),
        target_scope=ResourceScope(
            graph.tenant_id, graph.application_id, "target", "application"
        ),
        revisions=RevisionSet(*("a" * 64,) * 4),
        issued_at=now,
        valid_until=now + timedelta(minutes=10),
        now=now,
    )
    args.update(changes)
    return compile_dependency_program(**args)


def test_database_and_writer_cannot_disappear_behind_generic_six_area_passes(now):
    graph = example_graph(now)
    result = compile(graph, now)
    checks = result["dependency_checks"]
    assert any(row["check"] == "data-boundary" for row in checks)
    assert any(
        row["check"] == "writer-fencing" and row["dependency_id"] == "database"
        for row in checks
    )
    assert len(result["program"].requirements) > 24
    assert not result["execution_authorized"] and not result["target_mapping_complete"]
    assert not result["program"].assess((), Gate.PREFLIGHT, now=now)["gate_accepted"]


@pytest.mark.parametrize("kind", list(ResourceKind))
def test_each_resource_kind_creates_its_own_nonoptional_checks(now, kind):
    graph = example_graph(now)
    node = replace(graph.resources[0], kind=kind)
    graph = replace(graph, resources=(node,), relations=())
    result = compile(graph, now)
    checks = [
        r
        for r in result["program"].requirements
        if ":dependency:" in r.obligation.obligation_id
    ]
    assert checks and all(r.obligation.required for r in checks)
    assert all(
        row["qualification"] == "unverified" for row in dependency_check_catalog(graph)
    )


def test_new_inventory_revision_or_declared_requirement_invalidates_program_digest(now):
    graph = example_graph(now)
    before = compile(graph, now)["program"].fingerprint
    assert compile(replace(graph, revision=2), now)["program"].fingerprint != before
    node = replace(
        graph.resources[0], requirements=("unrecognized-special-requirement",)
    )
    changed = replace(graph, resources=(node, *graph.resources[1:]))
    result = compile(changed, now)
    assert result["program"].fingerprint != before
    assert any(
        row.get("declared_requirement") == "unrecognized-special-requirement"
        for row in result["dependency_checks"]
    )


def test_expired_cross_tenant_or_outliving_program_blocked(now):
    graph = example_graph(now)
    with pytest.raises(ContractError):
        compile(graph, now, valid_until=graph.valid_until + timedelta(seconds=1))
    with pytest.raises(ContractError):
        compile(
            graph, now, source_scope=ResourceScope("different", "app", "source", "app")
        )
    with pytest.raises(ContractError):
        compile(
            replace(graph, valid_until=now + timedelta(seconds=1)),
            now + timedelta(seconds=2),
        )


def test_large_inventory_is_blocked_without_silently_truncating_obligations(now):
    graph = example_graph(now)
    nodes = tuple(
        SystemResource(
            "db-" + str(i),
            "database",
            ResourceScope(
                graph.tenant_id, graph.application_id, "source", "db-" + str(i)
            ),
            ResourceKind.DATABASE,
            "pg",
            "local",
            "v1",
            Portability.UNKNOWN,
        )
        for i in range(80)
    )
    with pytest.raises(ContractError, match="capacity"):
        compile(replace(graph, resources=nodes, relations=()), now)
