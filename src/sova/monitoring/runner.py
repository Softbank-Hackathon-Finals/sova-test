"""One bounded due tick for CronJob/systemd; no background thread or executor."""

from sova.domain.contracts import ContractError
from sova.monitoring.contracts import MonitorRegistration
from sova_security.application.boundary import require_accept, require_authentication
from sova_security.domain.continuous_security import ContinuousSecurityReview


class ScheduledSecurityMonitor:
    def __init__(
        self,
        *,
        repository,
        current_registration,
        authenticate_registration,
        authorize,
        monitor_factory,
        clock,
    ):
        self.repository = repository
        self.current_registration = current_registration
        self.authenticate_registration = authenticate_registration
        self.authorize = authorize
        self.monitor_factory = monitor_factory
        self.clock = clock

    def _authority(self, registration):
        if not isinstance(registration, MonitorRegistration):
            raise ContractError("Typed monitor registration required")
        registration.require_current(self.clock())
        require_authentication(self.authenticate_registration, registration)
        require_accept(
            self.authorize,
            registration.actor_id,
            registration.scope,
            "security:monitor",
        )
        if self.current_registration(registration.job_id) != registration:
            raise ContractError("Monitor registration revoked/changed")

    def register(self, registration):
        self._authority(registration)
        require_accept(
            self.authorize,
            registration.actor_id,
            registration.scope,
            "security:register-monitor",
        )
        self.repository.register(registration)
        self._authority(registration)

    def run_due(self, registration, owner_id, *, lease_seconds=120):
        self._authority(registration)
        claim = self.repository.claim(
            registration, owner_id, lease_seconds=lease_seconds
        )
        if claim is None:
            return None
        try:
            self._authority(registration)
            monitor = self.monitor_factory(registration)
            # Bind the accepted baseline before the security module performs its
            # own current-input authentication and conservative hold creation.
            baseline = monitor.baseline_provider(registration.scope)
            if baseline.fingerprint != registration.baseline_digest:
                raise ContractError("Scheduled baseline differs from registration")
            review = monitor.run_once(registration.actor_id, scope=registration.scope)
            if (
                not isinstance(review, ContinuousSecurityReview)
                or review.scope != registration.scope
                or review.baseline_digest != registration.baseline_digest
                or not review.observed_at <= self.clock() < review.valid_until
            ):
                raise ContractError("Current registered security review required")
            self._authority(registration)
        except Exception:
            # Never persist exception text: collectors may include credentials or
            # arbitrary remote bytes. A failed tick is unknown, never healthy.
            self.repository.complete(claim, outcome="failed", review_digest=None)
            raise
        # Do not retry completion after a lost DB response. The next tick reads
        # durable state; only the current token may finish this run.
        self.repository.complete(
            claim,
            outcome="attention" if review.triggers else "observed",
            review_digest=review.fingerprint,
        )
        return review
