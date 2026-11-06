"""Actual private PG/TLS process; synthetic issuer and security observations.

Qualification support is read from the explicitly pinned producer checkout.
Production imports still use the installed package, never producer src paths.
"""

from contextlib import contextmanager, ExitStack
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
import importlib.util
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
from sova_security.adapters.postgres_modernization import PostgresSecurityArtifacts
from sova_security.adapters.postgres_signed_evidence import PostgresSignedEvidence
from sova_security.adapters.postgres_verifier_registry import PostgresVerifierRegistry
from sova_security.adapters.review_https import BearerCredential, HTTPSJSONTransport
from sova_security.domain.program_evidence import ProgramEvidenceRoute, ProgramSource
from sova_security.domain.security_program import checks_for, ProgramPhase
from sova_security.domain.signed_evidence import VerifierTrust
from sova_security.domain.verifier_registry import VerifierTrustChange


@pytest.fixture(scope="module")
def producer_support():
    location = os.environ.get("SOVA_SECURITY_TEST_SOURCE")
    if not location:
        pytest.skip("Explicit qualified security test source required for real service chain")
    root = Path(location).resolve()
    manifest = json.loads((Path(__file__).parents[1] / "integration/security/manifest.json").read_text())
    git = ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root)]
    assert subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip() == manifest["qualified_package_source"]
    assert not subprocess.check_output(git + ["status", "--porcelain"])
    old_path, old_modules = list(sys.path), set(sys.modules)
    sys.path[:0] = [str(root / "tests"), str(root / "tests/integration")]
    try:
        from tls_review_support import review_process, tls_server
        from tokenreview_tls_support import LocalTokenReview
        spec = importlib.util.spec_from_file_location("qualified_security_database", root / "tests/integration/test_postgres_boundary.py")
        boundary = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(boundary)
        yield SimpleNamespace(review_process=review_process, tls_server=tls_server, issuer=LocalTokenReview,
            database=boundary.database.__wrapped__)
    finally:
        sys.path[:] = old_path
        for name in set(sys.modules) - old_modules:
            filename = getattr(sys.modules[name], "__file__", None)
            if filename and Path(filename).resolve().is_relative_to(root / "tests"):
                sys.modules.pop(name, None)


@pytest.fixture(scope="module")
def security_database(producer_support):
    yield from producer_support.database()


class ProgramPublisher:
    """Independent synthetic producer with real signatures and live PG routes."""

    def __init__(self, connect, program, records, *, now):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.program, self.records = program, records
        self.artifacts = PostgresSecurityArtifacts(connect, tenant_id=program.target.tenant_id)
        self.signed = PostgresSignedEvidence(connect, tenant_id=program.target.tenant_id)
        self.registry = PostgresVerifierRegistry(connect, tenant_id=program.target.tenant_id,
            application_id=program.target.application_id)
        self.signer = Ed25519EvidenceSigner(Ed25519PrivateKey.generate(), issuer_id=uuid4().hex, key_id="test-key")
        trust = VerifierTrust(self.signer.issuer_id, self.signer.key_id, self.signer.public_key_hex,
            (program.target,), tuple("test-producer:" + b.check_id for b in program.bindings),
            now - timedelta(seconds=1), program.valid_until)
        self.change = VerifierTrustChange(program.target.tenant_id, program.target.application_id,
            1, trust, "registrar", "independent-reviewer", "synthetic-sova-chain", now, now + timedelta(minutes=1))
        self.registry.publish(self.change)
        self.artifacts.register(program.target, program, actor_id="registrar")
        self.routes = {}

    def publish(self, phase, *, observed_at):
        selected = {c.check_id for c in checks_for(self.program.kind) if c.phase == phase}
        for binding, record in zip(self.program.bindings, self.records, strict=True):
            if binding.check_id not in selected:
                continue
            prior = self.routes.get(binding.check_id)
            if prior is not None:
                self.artifacts.revoke(self.program.target, prior.fingerprint, expected_revision=1,
                    actor_id="registrar", reason="new-test-observation")
            original = replace(record, evidence_id=uuid4().hex, observed_at=observed_at,
                obligation_id="producer:" + binding.check_id, verifier_version="test-producer:" + binding.check_id)
            self.signed.save_envelope(self.signer.sign(original, issued_at=datetime.now(UTC)))
            route = ProgramEvidenceRoute(self.program.fingerprint, binding.check_id,
                (ProgramSource(self.signer.issuer_id, original),))
            self.artifacts.register(self.program.target, route, actor_id="registrar")
            self.routes[binding.check_id] = route

    def revoke(self):
        self.registry.publish(replace(self.change, revision=2, trust=replace(self.change.trust, revoked=True)))


@contextmanager
def independent_service(support, database, directory, registration, records, principal):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from sova_security.adapters.review_database import reader_statements

    dsn, registrar, password = database
    with psycopg.connect(dsn, autocommit=True) as admin:
        assert admin.info.host.startswith("/"), "Explicit private service DB socket required"
    def write():
        return psycopg.connect(dsn, user=registrar, password=password)
    now, scope = datetime.now(UTC), registration.scope
    publisher = ProgramPublisher(write, registration.program, records, now=now)
    publisher.publish(ProgramPhase.PREFLIGHT, observed_at=now)
    publisher.artifacts.register(scope, registration, actor_id="registrar")
    reader, reader_password = "sova_review_" + uuid4().hex, secrets.token_urlsafe(32)
    with psycopg.connect(dsn, autocommit=True) as admin:
        for statement in reader_statements(role=reader, tenant_id=scope.tenant_id):
            admin.execute(statement)
        admin.execute(sql.SQL("ALTER ROLE {} PASSWORD {}").format(sql.Identifier(reader), sql.Literal(reader_password)))
    def mount(name, value):
        path = directory / name
        path.write_text(value)
        path.chmod(0o600)
        return str(path)
    issuer = support.issuer(now)
    try:
        with support.tls_server(issuer, directory, name="issuer") as (issuer_origin, issuer_ca):
            grants = dict(schema_version=1, grants=[dict(username=issuer.username, uid=issuer.uid,
                subject_id=principal.subject_id, tenant_id=principal.tenant_id, scopes=[asdict(s) for s in principal.scopes],
                modes=list(principal.modes), issued_at=principal.issued_at.isoformat(), valid_until=principal.valid_until.isoformat())])
            config = dict(schema_version=1, tenant_id=scope.tenant_id,
                database_dsn_file=mount("database.dsn", make_conninfo(dsn, user=reader, password=reader_password)),
                tokenreview_origin=issuer_origin, tokenreview_ca_file=str(issuer_ca),
                reviewer_token_file=mount("reviewer.token", issuer.reviewer_token), audience=issuer.audience,
                grants_file=mount("grants.json", json.dumps(grants)), local_audit_file=str(directory / "audit.jsonl"))
            config_path = mount("config.json", json.dumps(config))
            with ExitStack() as service:
                origin, ca = service.enter_context(support.review_process(config_path, directory))
                context = ssl.create_default_context(cafile=str(ca))
                # Closing the producer's context is idempotent, including fault
                # injection before the outer cleanup. Docker stops only its own
                # generated container; process mode stops only its child.
                yield SimpleNamespace(publisher=publisher, stop=service.close, issuer=issuer,
                    credential=BearerCredential(issuer.client_token, now + timedelta(minutes=2)),
                    transport=HTTPSJSONTransport(origin, tls_context=context, timeout=5))
    finally:
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(reader)))
            admin.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(reader)))
