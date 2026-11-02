"""Narrow stateless response profile; no data/session migration qualification."""

from dataclasses import dataclass
from datetime import datetime
import hashlib

from sova.domain.contracts import ContractError, canonical_json, digest, identifier, utc
from sova.domain.evidence import Gate, RevisionSet, VerificationObligation
from sova.domain.plans import LifecyclePlan, PlanPurpose, PlanStep
from sova.security.domain.security_events import SecuritySnapshot
from sova.domain.system_graph import ResourceKind

ACTIONS = (
    "apply_isolation",
    "activate_replacement",
    "verify_replacement",
    "switch_route",
)


@dataclass(frozen=True, slots=True)
class StatelessResponseProfile:
    profile_id: str
    image_digest: str
    configuration_digest: str
    no_durable_state: bool
    no_session_state: bool
    no_background_writers: bool
    registered_by: str
    valid_until: datetime

    def __post_init__(self):
        identifier(self.profile_id)
        identifier(self.registered_by)
        digest(self.image_digest)
        digest(self.configuration_digest)
        if any(
            value is not True
            for value in (
                self.no_durable_state,
                self.no_session_state,
                self.no_background_writers,
            )
        ):
            raise ContractError("Only explicitly admitted stateless response supported")
        object.__setattr__(self, "valid_until", utc(self.valid_until))

    @property
    def document(self):
        return {
            "profile_id": self.profile_id,
            "image_digest": self.image_digest,
            "configuration_digest": self.configuration_digest,
            "no_durable_state": True,
            "no_session_state": True,
            "no_background_writers": True,
            "registered_by": self.registered_by,
            "valid_until": self.valid_until.isoformat(),
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class SecurityResponseBinding:
    source: SecuritySnapshot
    target: SecuritySnapshot
    source_node: str
    target_node: str
    hold_ids: tuple[str, ...]
    profile: StatelessResponseProfile
    policy_digest: str

    def __post_init__(self):
        if (
            not isinstance(self.source, SecuritySnapshot)
            or not isinstance(self.target, SecuritySnapshot)
            or not isinstance(self.profile, StatelessResponseProfile)
        ):
            raise ContractError("Typed response binding required")
        digest(self.policy_digest)
        if type(self.hold_ids) is not tuple or not 1 <= len(self.hold_ids) <= 32:
            raise ContractError("Explicit active incident hold IDs required")
        for hold_id in self.hold_ids:
            identifier(hold_id)
        if len(set(self.hold_ids)) != len(self.hold_ids):
            raise ContractError("Duplicate incident holds")
        source = self.source_resource
        target = self.target_resource
        if source.scope.resource_id == target.scope.resource_id:
            raise ContractError(
                "Environment aliases cannot share the same physical workload"
            )
        if (
            source.kind != ResourceKind.SERVICE
            or target.kind != ResourceKind.SERVICE
            or source.backend != "kubernetes"
            or target.backend != "kubernetes"
        ):
            raise ContractError(
                "Current response profile requires Kubernetes service workloads"
            )
        if (source.scope.tenant_id, source.scope.application_id) != (
            target.scope.tenant_id,
            target.scope.application_id,
        ) or source.scope.environment_id == target.scope.environment_id:
            raise ContractError(
                "Distinct environments of the same tenant/application required"
            )
        if not source.node_id.startswith(
            "deployment:"
        ) or not target.node_id.startswith("deployment:"):
            raise ContractError(
                "Only explicitly stateless Deployment response supported"
            )

    def resource(self, snapshot, node):
        found = next((r for r in snapshot.graph.resources if r.node_id == node), None)
        if found is None:
            raise ContractError("Unregistered response resource")
        return found

    @property
    def source_resource(self):
        return self.resource(self.source, self.source_node)

    @property
    def target_resource(self):
        return self.resource(self.target, self.target_node)

    @property
    def document(self):
        return {
            "source_snapshot": self.source.fingerprint,
            "target_snapshot": self.target.fingerprint,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "hold_ids": sorted(self.hold_ids),
            "profile_digest": self.profile.fingerprint,
            "policy_digest": self.policy_digest,
        }

    @property
    def fingerprint(self):
        return hashlib.sha256(canonical_json(self.document).encode()).hexdigest()

    def compile(self, *, plan_id, created_by, now, valid_until):
        now = utc(now)
        valid_until = utc(valid_until)
        self.source.graph.require_current(now)
        self.target.graph.require_current(now)
        if (
            not now
            < valid_until
            <= min(
                self.source.graph.valid_until,
                self.target.graph.valid_until,
                self.profile.valid_until,
            )
        ):
            raise ContractError("Response approval exceeds evidence/profile validity")
        revisions = RevisionSet(
            self.profile.image_digest,
            self.fingerprint,
            self.policy_digest,
            hashlib.sha256(
                canonical_json(
                    {
                        "source": self.source.graph.fingerprint,
                        "target": self.target.graph.fingerprint,
                    }
                ).encode()
            ).hexdigest(),
        )
        steps = []
        for index, action in enumerate(ACTIONS):
            resource = self.source_resource if index == 0 else self.target_resource
            steps.append(
                PlanStep(
                    action,
                    resource.scope,
                    "sova-stateless-security-response",
                    action,
                    canonical_json(self.document),
                    resource.resource_revision,
                    () if index == 0 else (ACTIONS[index - 1],),
                )
            )
        obligations = tuple(
            VerificationObligation(
                "response:" + name,
                self.source_resource.scope,
                Gate.PREFLIGHT,
                "sova-security-response-admission-v1",
            )
            for name in (
                "ownership",
                "stateless-profile",
                "clean-artifact",
                "preserved-observation",
                "target-protection",
            )
        )
        return LifecyclePlan(
            plan_id,
            self.source.graph.tenant_id,
            self.source.graph.application_id,
            created_by,
            PlanPurpose.SECURITY_RESPONSE,
            revisions,
            valid_until,
            tuple(steps),
            obligations,
            reason="bounded incident containment and stateless replacement",
        )
