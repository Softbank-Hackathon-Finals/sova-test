"""Compose the existing security monitor with durable authenticated input heads."""

from sova.domain.contracts import ContractError
from sova.monitoring.contracts import MonitorInputSet
from sova.monitoring.runner import ScheduledSecurityMonitor
from sova_security.application.assessment import AssessmentService
from sova_security.application.boundary import require_accept, require_authentication
from sova_security.application.continuous_security import ContinuousSecurityMonitor
from sova_security.domain.assessment import (
    AssetInventory,
    VulnerabilityScan,
    ExposureObservation,
    RiskPolicy,
)
from sova_security.domain.continuous_security import RuntimeSecurityBaseline


class RegisteredMonitoring:
    def __init__(
        self,
        *,
        repository,
        artifacts,
        holds,
        authenticate_monitor_input,
        authenticate_assessment_input,
        authorize,
        clock,
    ):
        self.repository, self.artifacts, self.holds = repository, artifacts, holds
        self.authenticate_monitor_input = authenticate_monitor_input
        self.authenticate_assessment_input = authenticate_assessment_input
        self.authorize, self.clock = authorize, clock

    def _registration(self, scope, job_id):
        r = self.repository.get_registration(scope.application_id, job_id)
        if r.scope != scope:
            raise ContractError("Monitor job resource scope changed")
        return r

    def _current_set(self, registration):
        r = registration
        if self._registration(r.scope, r.job_id) != r:
            raise ContractError("Current registered monitor required")
        require_authentication(
            lambda value: self.authenticate_monitor_input(r.actor_id, value), r
        )
        value = self.repository.latest_inputs(r.scope.application_id, r.job_id)
        if value.scope != r.scope or not value.observed_at <= self.clock() < min(
            value.valid_until, r.valid_until
        ):
            raise ContractError("Fresh scope-bound monitoring input head required")
        require_authentication(
            lambda subject: self.authenticate_monitor_input(r.actor_id, subject), value
        )
        return value

    def _values(self, registration, selection):
        values = []
        for fingerprint, kind in zip(
            selection.input_digests,
            (AssetInventory, VulnerabilityScan, ExposureObservation, RiskPolicy),
            strict=True,
        ):
            stored = self.artifacts.get(registration.scope, fingerprint)
            if (
                stored.revoked
                or not isinstance(stored.value, kind)
                or stored.value.scope != registration.scope
            ):
                raise ContractError("Current typed monitoring artifact required")
            values.append(stored.value)
        return tuple(values)

    def current_inputs(self, registration):
        selection = self._current_set(registration)
        values = self._values(registration, selection)
        if self._current_set(registration) != selection:
            raise ContractError("Monitoring input head changed during lookup")
        return values

    def publish_inputs(self, actor, selection):
        if not isinstance(selection, MonitorInputSet):
            raise ContractError("Typed monitoring input set required")
        r = self._registration(selection.scope, selection.job_id)
        require_accept(
            self.authorize, actor, r.scope, "security:publish-monitor-inputs"
        )
        require_authentication(
            lambda value: self.authenticate_monitor_input(actor, value), r
        )
        require_authentication(
            lambda value: self.authenticate_monitor_input(actor, value), selection
        )
        values = self._values(r, selection)
        for value in values:
            require_accept(self.authenticate_assessment_input, actor, r.scope, value)
        self.repository.publish_inputs(selection)
        # Persisted selection is still not an approval, and must remain current.
        require_accept(
            self.authorize, actor, r.scope, "security:publish-monitor-inputs"
        )
        require_authentication(
            lambda value: self.authenticate_monitor_input(actor, value), selection
        )
        if self.repository.latest_inputs(r.scope.application_id, r.job_id) != selection:
            raise ContractError("Monitoring input publication changed")

    def monitor(self, registration):
        r = registration

        def baseline(scope):
            if scope != r.scope:
                raise ContractError("Monitoring baseline scope mismatch")
            stored = self.artifacts.get(scope, r.baseline_digest)
            if stored.revoked or not isinstance(stored.value, RuntimeSecurityBaseline):
                raise ContractError("Authenticated runtime baseline required")
            return stored.value

        return ContinuousSecurityMonitor(
            assessment_service=AssessmentService(
                authorize=self.authorize,
                authenticate_input=self.authenticate_assessment_input,
                current_inputs=lambda _: self.current_inputs(r),
                clock=self.clock,
            ),
            current_inputs=lambda _: self.current_inputs(r),
            baseline_provider=baseline,
            authenticate_baseline=lambda value: self.authenticate_monitor_input(
                r.actor_id, value
            ),
            artifacts=self.artifacts,
            holds=self.holds,
            authorize=self.authorize,
            clock=self.clock,
        )

    def runner(self, registration):
        return ScheduledSecurityMonitor(
            repository=self.repository,
            current_registration=lambda job: self._registration(
                registration.scope, job
            ),
            authenticate_registration=lambda value: self.authenticate_monitor_input(
                registration.actor_id, value
            ),
            authorize=self.authorize,
            monitor_factory=self.monitor,
            clock=self.clock,
        )
