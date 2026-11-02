from dataclasses import replace
from datetime import timedelta
from uuid import uuid4
import pytest
from security_support import security_snapshot
from sova.adapters.postgres_security_events import PostgresSecurityObservations
from sova.domain.contracts import ContractError
from sova.domain.security_events import SecurityEvent, SecurityEventKind
from sova.ports.plans import RecordNotFound, RepositoryConflict

pytestmark = pytest.mark.postgres


@pytest.fixture
def setup(postgres_bundle, now):
    lifecycle = postgres_bundle[0]
    scope = postgres_bundle[3].scope
    repo = PostgresSecurityObservations(
        lifecycle.connect, tenant_id=lifecycle.tenant_id
    )
    snapshot = security_snapshot(scope, now)
    return lifecycle, repo, snapshot


def event(snapshot, now):
    node = snapshot.graph.resources[0]
    return SecurityEvent(
        "event",
        node.scope,
        snapshot.fingerprint,
        snapshot.graph.fingerprint,
        SecurityEventKind.OBSERVED,
        (node.node_id,),
        now,
        '{"basis":"configuration"}',
    )


def test_immutable_observations_events_and_restart(setup, now):
    lifecycle, repo, snapshot = setup
    repo.save_snapshot(snapshot)
    repo.save_snapshot(snapshot)
    first = repo.append_event(event(snapshot, now))
    assert repo.append_event(event(snapshot, now)) == first
    restarted = PostgresSecurityObservations(
        lifecycle.connect, tenant_id=lifecycle.tenant_id
    )
    assert (
        restarted.get_snapshot(snapshot.graph.application_id, snapshot.fingerprint)
        == snapshot
    )
    assert (
        restarted.latest_snapshot(
            snapshot.graph.application_id,
            snapshot.graph.resources[0].scope.environment_id,
        )
        == snapshot
    )
    assert restarted.list_events(snapshot.graph.application_id) == (
        (first, event(snapshot, now)),
    )
    assert restarted.list_events(snapshot.graph.application_id, after=first) == ()
    with pytest.raises(RepositoryConflict):
        repo.append_event(
            replace(event(snapshot, now), kind=SecurityEventKind.HOLD_OPENED)
        )


def test_unregistered_subject_or_revision_cannot_create_movement_event(setup, now):
    _, repo, snapshot = setup
    repo.save_snapshot(snapshot)
    for changed in (
        replace(event(snapshot, now), node_ids=("other",)),
        replace(event(snapshot, now), graph_digest="0" * 64),
        replace(
            event(snapshot, now),
            scope=replace(snapshot.graph.resources[0].scope, resource_id="other"),
        ),
    ):
        with pytest.raises(ContractError):
            repo.append_event(changed)


def test_tenant_and_app_isolation(setup, now):
    lifecycle, repo, snapshot = setup
    repo.save_snapshot(snapshot)
    repo.append_event(event(snapshot, now))
    other = PostgresSecurityObservations(
        lifecycle.connect, tenant_id="other-" + uuid4().hex
    )
    with pytest.raises(RecordNotFound):
        other.get_snapshot(snapshot.graph.application_id, snapshot.fingerprint)
    with pytest.raises(ContractError):
        other.save_snapshot(snapshot)
    assert other.list_events(snapshot.graph.application_id) == ()
    assert repo.list_events("other-app") == ()


def test_delayed_old_snapshot_does_not_replace_newer_and_ties_fail_closed(setup, now):
    _, repo, old = setup
    newer = security_snapshot(
        old.graph.resources[0].scope, now - timedelta(seconds=1), revision="6"
    )
    older = security_snapshot(old.graph.resources[0].scope, now - timedelta(seconds=2))
    repo.save_snapshot(newer)
    repo.save_snapshot(older)
    assert (
        repo.latest_snapshot(
            old.graph.application_id, old.graph.resources[0].scope.environment_id
        )
        == newer
    )
    ambiguous = replace(newer, collection_digest="f" * 64)
    repo.save_snapshot(ambiguous)
    with pytest.raises(ContractError):
        repo.latest_snapshot(
            old.graph.application_id, old.graph.resources[0].scope.environment_id
        )


def test_recent_history_is_bounded_scoped_and_continues_from_latest_cursor(setup, now):
    lifecycle, repo, snapshot = setup
    repo.save_snapshot(snapshot)
    sequences = [
        repo.append_event(replace(event(snapshot, now), event_id="event-" + str(i)))
        for i in range(6)
    ]
    app = snapshot.graph.application_id
    recent = repo.list_events(app, recent=True, limit=3)
    assert [seq for seq, _ in recent] == sequences[-3:]
    assert [seq for seq, _ in repo.list_events(app, limit=3)] == sequences[:3]
    last = repo.append_event(replace(event(snapshot, now), event_id="new-event"))
    assert [seq for seq, _ in repo.list_events(app, after=recent[-1][0])] == [last]
    assert not repo.list_events("other-app", recent=True)
    other = PostgresSecurityObservations(lifecycle.connect, tenant_id="other-tenant")
    assert not other.list_events(app, recent=True)
    with pytest.raises(ContractError):
        repo.list_events(app, after=last, recent=True)
