"""Collect scoped posture, persist immutable evidence, raise deduplicated holds."""

from datetime import UTC, datetime
from sova.security.adapters.security_codec import snapshot_from_collection
from sova.domain.contracts import ContractError, canonical_json
from sova.security.domain.security_events import SecurityEvent, SecurityEventKind
from sova.domain.evidence import VerificationResult


class SecurityCollector:
    def __init__(
        self,
        observations,
        holds,
        *,
        collect,
        authorize,
        actor_id,
        blocking_controls,
        clock=lambda: datetime.now(UTC),
    ):
        self.observations = observations
        self.holds = holds
        self.collect = collect
        self.authorize = authorize
        self.actor_id = actor_id
        self.clock = clock
        if type(blocking_controls) is not frozenset or not blocking_controls:
            raise ContractError("Explicit immutable security trigger policy required")
        self.blocking_controls = blocking_controls

    def run_once(self):
        snapshot = snapshot_from_collection(self.collect())
        snapshot.graph.require_current(self.clock())
        if (
            self.observations.tenant_id != snapshot.graph.tenant_id
            or self.holds.tenant_id != snapshot.graph.tenant_id
        ):
            raise ContractError("Security collector tenant mismatch")
        self.authorize(self.actor_id, snapshot.graph, "security:record")
        self.observations.save_snapshot(snapshot)
        nodes = {r.scope: r.node_id for r in snapshot.graph.resources}

        def emit(kind, scope, details, event_id, recorded_at=None):
            event = SecurityEvent(
                event_id,
                scope,
                snapshot.fingerprint,
                snapshot.graph.fingerprint,
                kind,
                (nodes[scope],),
                recorded_at or self.clock(),
                canonical_json(details),
            )
            return self.observations.append_event(event)

        first = snapshot.graph.resources[0]
        emit(
            SecurityEventKind.OBSERVED,
            first.scope,
            {"basis": "configuration"},
            "observation:" + snapshot.fingerprint,
            snapshot.graph.observed_at,
        )
        raised = []
        for finding in snapshot.findings:
            if (
                finding.control_id not in self.blocking_controls
                or finding.result != VerificationResult.FAIL
            ):
                continue
            self.authorize(self.actor_id, finding.scope, "security:hold")
            stored, created = self.holds.open_incident(
                finding.scope, "posture:" + finding.control_id, self.actor_id
            )
            raised.append(stored.hold.hold_id)
            if created:
                emit(
                    SecurityEventKind.HOLD_OPENED,
                    finding.scope,
                    {
                        "basis": "configuration",
                        "hold_id": stored.hold.hold_id,
                        "result": "policy-violation",
                    },
                    "hold:" + stored.hold.hold_id,
                    stored.hold.raised_at,
                )
        return {
            "snapshot_digest": snapshot.fingerprint,
            "graph_digest": snapshot.graph.fingerprint,
            "active_trigger_holds": sorted(set(raised)),
            "configuration_findings": len(snapshot.findings),
            "runtime_security_verified": False,
        }
