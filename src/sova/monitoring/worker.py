"""Fixed PostgreSQL monitoring worker for a registered CronJob/systemd task.

No deployment credentials, dynamic plugins, shell commands or alert destinations.
Private host policy identifies one service actor/scope and accepted signer roles.
"""

import argparse
from datetime import UTC, datetime
import hashlib
import json
from uuid import uuid4

from sova.adapters.kubernetes.https import private_text
from sova.adapters.registration.graph_codec import json_document
from sova.adapters.postgres_monitoring import PostgresMonitorRepository
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.domain.contracts import ContractError, ResourceScope
from sova.monitoring.authority import SignedMonitorAuthority
from sova.monitoring.composition import RegisteredMonitoring
from sova_security.adapters.assessment_evidence import AssessmentInputAuthority
from sova_security.adapters.ed25519_evidence import Ed25519EvidenceVerifier
from sova_security.adapters.modernization_codec import kind_of
from sova_security.adapters.postgres_governance import PostgresSecurityHolds
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
from sova_security.application.signed_evidence import SignedEvidenceAuthority
from sova_security.contracts.evidence import RevisionSet

ACTIONS = frozenset(
    {
        "security:monitor",
        "security:assess",
        "security:hold",
        "security:authenticate-assessment-input",
        "security:authenticate-monitor-input",
    }
)


def load_worker(config_file):
    import psycopg
    from psycopg.conninfo import conninfo_to_dict

    raw = private_text(config_file)
    config = json_document(raw)
    required = {
        "schema_version",
        "scope",
        "job_id",
        "actor_id",
        "dsn_file",
        "revisions",
        "issuers",
    }
    if (
        set(config) != required
        or type(config["schema_version"]) is not int
        or config["schema_version"] != 1
    ):
        raise ContractError("Exact monitor worker configuration required")
    scope = ResourceScope(**config["scope"])
    revisions = RevisionSet(**config["revisions"])
    issuers = config["issuers"]
    if (
        type(issuers) is not dict
        or not 1 <= len(issuers) <= 16
        or any(
            type(v) is not list
            or not 1 <= len(v) <= 8
            or any(type(i) is not str for i in v)
            for v in issuers.values()
        )
    ):
        raise ContractError("Bounded explicit monitor issuer roles required")
    issuers = {k: tuple(v) for k, v in issuers.items()}
    dsn = private_text(config["dsn_file"])
    connection = conninfo_to_dict(dsn)
    if (
        not connection.get("host")
        or not connection.get("dbname")
        or not connection.get("user")
        or "service" in connection
        or "options" in connection
    ):
        raise ContractError("Explicit monitor database identity required")
    if not connection["host"].startswith("/") and (
        connection.get("sslmode") != "verify-full" or not connection.get("sslrootcert")
    ):
        raise ContractError(
            "Remote monitor database requires verified TLS and explicit CA"
        )

    def connect():
        return psycopg.connect(
            dsn,
            connect_timeout=5,
            passfile="/dev/null",
            password=connection.get("password", ""),
            hostaddr=connection.get("hostaddr", ""),
            options="-c statement_timeout=10000 -c lock_timeout=3000",
        )

    def authorize(actor, subject, action):
        if (
            actor != config["actor_id"]
            or subject != scope
            or action not in ACTIONS
            or private_text(config_file) != raw
            or private_text(config["dsn_file"]) != dsn
        ):
            raise ContractError("Monitor service identity/policy changed or denied")

    def clock():
        return datetime.now(UTC)

    lifecycle = PostgresLifecycleRepository(
        connect, tenant_id=scope.tenant_id, clock=clock
    )
    repository = PostgresMonitorRepository(lifecycle)
    r = repository.get_registration(scope.application_id, config["job_id"])
    if r.scope != scope or r.actor_id != config["actor_id"]:
        raise ContractError("Monitor worker registration identity mismatch")
    registry = PostgresVerifierRegistry(
        connect, tenant_id=scope.tenant_id, application_id=scope.application_id
    )
    signed = PostgresSignedEvidence(connect, tenant_id=scope.tenant_id)
    authority = SignedEvidenceAuthority(
        signed, Ed25519EvidenceVerifier(registry.resolve), clock=clock
    )
    monitor_auth = SignedMonitorAuthority(
        authority=authority,
        current_revisions=lambda _: revisions,
        issuers_for=lambda _, kind: issuers.get(kind, ()),
        authorize=authorize,
    )
    input_auth = AssessmentInputAuthority(
        envelope_provider=lambda actor, subject, value: signed.find_envelope(
            subject,
            artifact_digest=value.fingerprint,
            verifier_version="sova.security.assessment-input." + kind_of(value),
        ),
        current_revisions=lambda _: revisions,
        issuers_for=lambda _, kind: issuers.get(kind, ()),
        resolve_trust=registry.resolve,
        authorize=authorize,
        clock=clock,
    )
    service = RegisteredMonitoring(
        repository=repository,
        artifacts=PostgresSecurityArtifacts(connect, tenant_id=scope.tenant_id),
        holds=PostgresSecurityHolds(connect, tenant_id=scope.tenant_id),
        authenticate_monitor_input=monitor_auth.authenticate,
        authenticate_assessment_input=input_auth,
        authorize=authorize,
        clock=clock,
    )
    return service, r, hashlib.sha256(raw.encode()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        service, r, config_digest = load_worker(args.config)
        result = service.runner(r).run_due(r, "cron-" + uuid4().hex)
        print(
            json.dumps(
                {
                    "status": "not-due"
                    if result is None
                    else "attention"
                    if result.triggers
                    else "observed",
                    "review_digest": None if result is None else result.fingerprint,
                    "configuration_digest": config_digest,
                }
            )
        )
        return 0
    except Exception:
        # Full exceptions can contain DSN, remote responses and secret values.
        print(json.dumps({"status": "failed", "reason": "monitor-tick-unverified"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
