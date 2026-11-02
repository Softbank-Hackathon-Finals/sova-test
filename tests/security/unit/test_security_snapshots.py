from dataclasses import replace
from datetime import timedelta
import pytest
from security_support import security_snapshot
from sova.adapters.security_codec import decode_snapshot, decode_event
from sova.domain.contracts import ContractError
from sova.domain.evidence import RevisionSet
from sova.domain.security_events import SecurityEvent, SecurityEventKind


def test_security_snapshot_roundtrip_and_exact_revision_binding(scope, now):
    snapshot = security_snapshot(scope, now)
    assert decode_snapshot(snapshot.document).fingerprint == snapshot.fingerprint
    assert (
        snapshot.findings[0]
        .evidence(RevisionSet("a" * 64, "b" * 64, "c" * 64, "d" * 64))
        .artifact_digest
        == snapshot.findings[0].fingerprint
    )
    with pytest.raises(ContractError):
        replace(
            snapshot,
            findings=(replace(snapshot.findings[0], resource_revision="other"),),
        )
    with pytest.raises(ContractError):
        replace(
            snapshot,
            findings=(
                replace(snapshot.findings[0], valid_until=now + timedelta(hours=1)),
            ),
        )
    with pytest.raises(ContractError):
        replace(snapshot, findings=(snapshot.findings[0], snapshot.findings[0]))


def test_event_codec_rejects_arbitrary_command_and_secret_fields(scope, now):
    snapshot = security_snapshot(scope, now)
    node = snapshot.graph.resources[0]
    event = SecurityEvent(
        "e1",
        node.scope,
        snapshot.fingerprint,
        snapshot.graph.fingerprint,
        SecurityEventKind.OBSERVED,
        (node.node_id,),
        now,
        '{"basis":"configuration"}',
    )
    assert decode_event(event.document) == event
    with pytest.raises(ContractError):
        replace(event, details_json='{"command":"run arbitrary command"}')
    with pytest.raises(ContractError):
        replace(event, details_json='{"secret":"not allowed"}')
    with pytest.raises(ContractError):
        replace(event, node_ids=(node.node_id, node.node_id))
