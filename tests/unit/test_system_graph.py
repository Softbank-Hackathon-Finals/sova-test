from dataclasses import replace
from datetime import timedelta
import json

import pytest

from sova.adapters.registration.graph_codec import decode_graph, json_document
from sova.application.examples import example_graph
from sova.application.portability import assess_portability
from sova.domain.contracts import ContractError
from sova.domain.system_graph import RelationKind, SystemRelation
from sova.interfaces.cli import main


def test_roundtrip_and_digest_stable_under_order(now):
    graph = example_graph(now)
    assert decode_graph(json_document(json.dumps(graph.document))) == graph
    assert (
        replace(
            graph,
            resources=tuple(reversed(graph.resources)),
            relations=tuple(reversed(graph.relations)),
        ).fingerprint
        == graph.fingerprint
    )
    assert replace(graph, revision=2).fingerprint != graph.fingerprint


def test_cycles_grouped_dependencies_first(now):
    graph = example_graph(now)
    graph = replace(
        graph,
        relations=graph.relations
        + (SystemRelation("database", "api", RelationKind.CALLS, True),),
    )
    assert graph.movement_groups() == (("api", "database"), ("entry",))
    assert graph.impact_candidates({"database"}) == ("api", "entry")


def test_no_silent_cross_tenant_or_unregistered_links(now):
    graph = example_graph(now)
    with pytest.raises(ContractError):
        replace(graph, application_id="other")
    with pytest.raises(ContractError):
        replace(
            graph,
            relations=(SystemRelation("entry", "missing", RelationKind.CALLS, True),),
        )
    with pytest.raises(ContractError):
        replace(graph, resources=graph.resources + (graph.resources[0],))
    with pytest.raises(ContractError):
        graph.impact_candidates({"unregistered"})


@pytest.mark.parametrize(
    "raw", ['{"a":1,"a":2}', '{"x":NaN}', "[" * 30 + "0" + "]" * 30, '"\ud800"']
)
def test_registration_rejects_ambiguous_unbounded_json(raw):
    with pytest.raises(ContractError):
        json_document(raw)


def test_invalid_requirements_fail_as_contract_error(now):
    with pytest.raises(ContractError):
        replace(example_graph(now).resources[0], requirements=({},))


def test_assessment_not_approval_and_unknown_not_portable(now):
    graph = example_graph(now)
    result = assess_portability(
        graph, target_environment="onprem", target_backend="kubernetes", now=now
    )
    assert result["executable"] is False
    assert result["graph_digest"] == graph.fingerprint
    assert result["target"]["readiness"] == "unverified"
    assert (
        next(i for i in result["lock_in_map"] if i["node_id"] == "database")[
            "recommendation"
        ]
        == "inspect-before-planning"
    )
    assert result["rehearsal"]["runtime_implemented"] is False
    with pytest.raises(ContractError):
        assess_portability(
            graph,
            target_environment="onprem",
            target_backend="kubernetes",
            now=now + timedelta(hours=1),
        )
    with pytest.raises(ContractError):
        assess_portability(
            graph,
            target_environment="onprem",
            target_backend="kubernetes",
            now=now - timedelta(seconds=1),
        )


def test_cli_invalid_file_never_echoes_raw_input(tmp_path, capsys):
    path = tmp_path / "invalid.json"
    path.write_text('{"secret":"private-input"}')
    assert main(["inspect", str(path)]) == 2
    captured = capsys.readouterr()
    assert "private-input" not in captured.err + captured.out


def test_cli_example_assess_flow(tmp_path, capsys):
    assert main(["example"]) == 0
    path = tmp_path / "registration.json"
    path.write_text(capsys.readouterr().out)
    assert main(["inspect", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["live_verified"] is False
    assert (
        main(
            [
                "assess",
                str(path),
                "--target-environment",
                "onprem",
                "--target-backend",
                "kubernetes",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["executable"] is False
