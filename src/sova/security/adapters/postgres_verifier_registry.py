"""App-scoped append-only trust registry. Resolve current state on every use."""

from psycopg.types.json import Jsonb
from sova.adapters.postgres_plans import PostgresLifecycleRepository
from sova.adapters.plan_codec import document_hash
from sova.security.adapters.verifier_registry_codec import decode_trust_change
from sova.domain.contracts import ContractError, identifier
from sova.ports.plans import RecordNotFound, RepositoryConflict


class PostgresVerifierRegistry:
    def __init__(self, connect, *, tenant_id, application_id):
        self.tenant_id = identifier(tenant_id)
        self.application_id = identifier(application_id)
        self._transactions = PostgresLifecycleRepository(connect, tenant_id=tenant_id)

    def _latest(self, conn, issuer_id, key_id):
        row = conn.execute(
            "SELECT revision,digest,document FROM sova_control.verifier_trust_events WHERE tenant_id=%s AND application_id=%s AND issuer_id=%s AND key_id=%s ORDER BY revision DESC LIMIT 1",
            (self.tenant_id, self.application_id, issuer_id, key_id),
        ).fetchone()
        if not row:
            return None
        change = decode_trust_change(row[2])
        if (
            change.tenant_id,
            change.application_id,
            change.trust.issuer_id,
            change.trust.key_id,
            change.revision,
            change.fingerprint,
        ) != (self.tenant_id, self.application_id, issuer_id, key_id, row[0], row[1]):
            raise ContractError("Verifier trust integrity/scope mismatch")
        return change

    def latest(self, issuer_id, key_id):
        identifier(issuer_id)
        identifier(key_id)
        with self._transactions.transaction() as conn:
            change = self._latest(conn, issuer_id, key_id)
            if change is None:
                raise RecordNotFound("Verifier trust not found")
            return change

    def resolve(self, issuer_id, key_id):
        return self.latest(issuer_id, key_id).trust

    def publish(self, change):
        if (change.tenant_id, change.application_id) != (
            self.tenant_id,
            self.application_id,
        ):
            raise ContractError("Verifier trust registry scope mismatch")
        with self._transactions.transaction() as conn:
            key = document_hash(
                {
                    "tenant": self.tenant_id,
                    "app": self.application_id,
                    "issuer": change.trust.issuer_id,
                    "key": change.trust.key_id,
                }
            )
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (key,))
            prior = self._latest(conn, change.trust.issuer_id, change.trust.key_id)
            if prior == change:
                return prior
            if prior and prior.revision >= change.revision:
                raise RepositoryConflict("Verifier trust publication lost CAS")
            change.require_successor(prior)
            change.require_current(
                conn.execute("SELECT clock_timestamp()").fetchone()[0]
            )
            conn.execute(
                "INSERT INTO sova_control.verifier_trust_events (tenant_id,application_id,issuer_id,key_id,revision,digest,document) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (
                    self.tenant_id,
                    self.application_id,
                    change.trust.issuer_id,
                    change.trust.key_id,
                    change.revision,
                    change.fingerprint,
                    Jsonb(change.document),
                ),
            )
            return change
