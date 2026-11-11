"""Signed, bound response evidence on the team security envelope contract.

Every verification readback becomes a `sova_security` EvidenceRecord, signed
with Ed25519 and bound to:

- the approved plan digest (`revisions.configuration`),
- the observed environment: both cluster UIDs, owned namespace UIDs and the
  current pod UIDs and image IDs (`revisions.environment`),
- the runner code that produced it (`revisions.source`),
- the scenario's verification contract (`revisions.policy`),
- the run, the scenario scope and a short validity window.

`response finalize` accepts only a verifiable, unexpired PASS envelope from a
fresh readback whose bindings still match the plan and the environment seen at
`response verify`. Anything else holds; nothing is retried.

The signer is this runner's own key on this Mac. It authenticates what the
runner observed and makes later tampering detectable. It is not an
independent verifier identity, and the key is not in a hardware or KMS store.
"""

from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sova_security.adapters.ed25519_evidence import (
    Ed25519EvidenceSigner,
    Ed25519EvidenceVerifier,
)
from sova_security.contracts.commands import (
    ContractError,
    ResourceScope,
    canonical_json,
)
from sova_security.contracts.evidence import (
    EvidenceRecord,
    RevisionSet,
    VerificationResult,
)
from sova_security.domain.signed_evidence import EvidenceEnvelope, VerifierTrust

from .contracts import SCENARIOS, SIGNALS
from .provision import private_json

ISSUER = "sova-workload-response-runner"
VERIFIER_VERSION = "sova.workload-response.readback.v1"
TTL = timedelta(minutes=5)
TRUST_DAYS = 30


def sha(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def files_digest():
    here = Path(__file__).parent
    return sha(
        {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(here.glob("*.py"))
            if not path.name.startswith("test_")
        }
    )


# The code this process loaded, fixed at import. Editing files under a running
# runner does not change what it runs; a new process with other code does.
LOADED = files_digest()


def producer_digest():
    return LOADED


def contract_digest(scenario):
    return sha(
        {
            "verifier": VERIFIER_VERSION,
            "scenario": scenario,
            "signal": list(SIGNALS.get(scenario, ("qualification-record", "all"))),
        }
    )


class ResponseEvidence:
    """Owns the signing key, the verifier trust and the evidence store."""

    def __init__(self, root, *, tenant, namespace, clock=lambda: datetime.now(UTC)):
        self.root = Path(root)
        self.clock = clock
        self.tenant = tenant
        self.namespace = namespace
        self.key_path = self.root / "evidence-signing.private.json"
        if not self.key_path.exists():
            key = Ed25519PrivateKey.generate()
            private_json(
                self.key_path,
                {
                    "private_key_hex": key.private_bytes_raw().hex(),
                    "created_at": clock().isoformat(),
                },
            )
        stored = json.loads(self.key_path.read_text())
        if os.stat(self.key_path).st_mode & 0o077:
            raise ContractError("Evidence signing key must be private (0600)")
        key = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(stored["private_key_hex"])
        )
        created = datetime.fromisoformat(stored["created_at"])
        public = key.public_key().public_bytes_raw().hex()
        self.key_id = "ed25519-" + public[:16]
        self.signer = Ed25519EvidenceSigner(key, issuer_id=ISSUER, key_id=self.key_id)
        self.trust = VerifierTrust(
            ISSUER,
            self.key_id,
            public,
            tuple(self.scope(s) for s in sorted(SCENARIOS) + ["qualification"]),
            (VERIFIER_VERSION,),
            created - timedelta(seconds=1),
            created + timedelta(days=TRUST_DAYS),
        )
        private_json(
            self.root / "evidence-trust.json",
            {
                "issuer_id": ISSUER,
                "key_id": self.key_id,
                "public_key_hex": public,
                "verifier_version": VERIFIER_VERSION,
                "valid_until": self.trust.valid_until.isoformat(),
            },
        )
        self.verifier = Ed25519EvidenceVerifier(self.resolve)
        (self.root / "evidence").mkdir(mode=0o700, exist_ok=True)

    def resolve(self, issuer_id, key_id):
        if (issuer_id, key_id) != (ISSUER, self.key_id):
            raise ContractError("Unknown evidence issuer")
        return self.trust

    def scope(self, scenario):
        return ResourceScope(
            self.tenant, "workload-response", "runner", self.namespace + "/" + scenario
        )

    def issue(
        self, *, run_id, scenario, stage, revision, plan_digest, environment, checks
    ):
        """Sign the readback and immediately verify the round trip."""
        now = self.clock()
        passed = bool(checks) and all(item["passed"] for item in checks)
        record = EvidenceRecord(
            f"{run_id}.{scenario}.{stage}.r{revision}",
            "workload-response." + scenario,
            self.scope(scenario),
            RevisionSet(
                producer_digest(),
                plan_digest,
                contract_digest(scenario),
                environment,
            ),
            VERIFIER_VERSION,
            now,
            now + TTL,
            VerificationResult.PASS if passed else VerificationResult.FAIL,
            f"checks.{run_id}.{stage}.r{revision}",
            sha(checks),
        )
        envelope = self.signer.sign(record, issued_at=now)
        self.verifier.verify(envelope, expected_record=record, now=now)
        path = self.root / "evidence" / (record.evidence_id + ".json")
        private_json(path, envelope.document)
        return {
            "evidence_id": record.evidence_id,
            "stage": stage,
            "result": str(record.result),
            "fingerprint": envelope.fingerprint,
            "plan_digest": plan_digest,
            "environment_digest": environment,
            "valid_until": record.valid_until.isoformat(),
            "issuer": ISSUER,
            "key_id": self.key_id,
        }

    def load(self, evidence_id):
        document = json.loads(
            (self.root / "evidence" / (evidence_id + ".json")).read_text()
        )
        return envelope_from_document(document)

    def accept(self, receipt, *, plan_digest, environment, now=None):
        """Re-verify a stored envelope against the current plan and environment."""
        envelope = self.load(receipt["evidence_id"])
        record = envelope.evidence
        self.verifier.verify(envelope, expected_record=record, now=now or self.clock())
        if envelope.fingerprint != receipt["fingerprint"]:
            raise ContractError("Evidence differs from the recorded receipt")
        if record.result is not VerificationResult.PASS:
            raise ContractError("Evidence is not a PASS")
        if record.revisions.configuration != plan_digest:
            raise ContractError("Evidence is bound to another plan")
        if record.revisions.environment != environment:
            raise ContractError("Environment drifted since the evidence")
        if record.revisions.source != producer_digest():
            raise ContractError("Runner code changed since the evidence")
        return record


def envelope_from_document(document):
    evidence = document["evidence"]
    scope = evidence["scope"]
    revisions = evidence["revisions"]
    record = EvidenceRecord(
        evidence["evidence_id"],
        evidence["obligation_id"],
        ResourceScope(
            scope["tenant_id"],
            scope["application_id"],
            scope["environment_id"],
            scope["resource_id"],
        ),
        RevisionSet(
            revisions["source"],
            revisions["configuration"],
            revisions["policy"],
            revisions["environment"],
        ),
        evidence["verifier_version"],
        datetime.fromisoformat(evidence["observed_at"]),
        datetime.fromisoformat(evidence["valid_until"]),
        VerificationResult(evidence["result"]),
        evidence["artifact_id"],
        evidence["artifact_digest"],
        evidence.get("justification"),
        evidence.get("approved_by"),
    )
    envelope = EvidenceEnvelope(
        document["issuer_id"],
        document["key_id"],
        datetime.fromisoformat(document["issued_at"]),
        record,
        document["signature"],
    )
    canonical_json(envelope.document, limit=16384)
    return envelope
