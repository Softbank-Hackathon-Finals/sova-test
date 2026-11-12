"""SECURITY_HOLD for the response runner on the team governance contract.

A security hold is not the runner's own `held` (SAFE_HOLD, an unconfirmed
effect). The console operator raises it on suspicion of compromise. While it
is active every effect is refused, including `response reset`, which would
reopen writers. Only a `HoldRelease` releases it, and only when:

- a registered approver signed it with its own Ed25519 key,
- the approver is neither the operator who raised the hold nor the requester,
- it binds this hold, its scope and the current revisions (runner code,
  plan, hold, observed environment) and is still valid.

After release no earlier approval or signed evidence is reused: an
unapproved plan is planned again, an approved one is verified again.

Keys bind identities; they are not proof of a human or of a login. The
approver key must live outside this runner's state, under its owner.
"""

from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import re
import secrets

from sova_security.adapters.ed25519_evidence import Ed25519EvidenceSigner
from sova_security.adapters.hold_release_evidence import (
    VERIFIER_VERSION as RELEASE_VERIFIER,
    HoldReleaseAuthority,
    hold_release_record,
)
from sova_security.contracts.commands import ContractError, ResourceScope
from sova_security.contracts.evidence import RevisionSet
from sova_security.domain.governance import HoldRelease, SecurityHold, StoredHold
from sova_security.domain.signed_evidence import VerifierTrust

from .evidence import envelope_from_document, producer_digest, sha
from .manifests import NAMESPACES, PROFILE
from .provision import private_json

OPERATOR = "console-operator"
APPROVERS = "security-approvers.json"
HOLD_STATUS = "security-hold.json"
REASON = re.compile(r"[a-z0-9][a-z0-9-]{2,63}")
APPROVAL = re.compile(r"[a-z0-9][a-z0-9-]{7,63}")


def hold_scope():
    return ResourceScope(
        PROFILE["owner"], "workload-response", PROFILE["name"], NAMESPACES["source"]
    )


def scope_from(document):
    return ResourceScope(
        document["tenant_id"],
        document["application_id"],
        document["environment_id"],
        document["resource_id"],
    )


def hold_from(document):
    return SecurityHold(
        document["hold_id"],
        scope_from(document["scope"]),
        document["raised_by"],
        document["reason"],
        datetime.fromisoformat(document["raised_at"]),
    )


def release_from(document):
    return HoldRelease(
        document["hold_id"],
        scope_from(document["scope"]),
        RevisionSet(**document["revisions"]),
        document["expected_revision"],
        document["requested_by"],
        document["approved_by"],
        document["reason"],
        document["evidence_id"],
        document["evidence_digest"],
        datetime.fromisoformat(document["approved_at"]),
        datetime.fromisoformat(document["valid_until"]),
    )


class SecurityGate:
    def __init__(self, runtime, clock=lambda: datetime.now(UTC)):
        self.runtime = runtime
        self.clock = clock

    @property
    def root(self):
        return Path(self.runtime.root)

    @property
    def record(self):
        return self.runtime.state.get("security") or {}

    def active(self):
        return bool(self.record.get("active"))

    def revisions(self, hold_document):
        plan = self.runtime.state.get("plan") or {}
        return RevisionSet(
            producer_digest(),
            plan.get("digest") or sha({"plan": None}),
            sha(hold_document),
            self.runtime.environment_digest(),
        )

    def export(self):
        """Publish what an approver signs: the hold and current revisions."""
        if not self.active():
            return
        hold = self.record["hold"]
        revisions = self.revisions(hold)
        private_json(
            self.root / HOLD_STATUS,
            {
                "hold": hold,
                "revision": 1,
                "requested_by": OPERATOR,
                "revisions": asdict(revisions),
                "evidence_id": "observation." + hold["hold_id"],
                "evidence_digest": revisions.environment,
                "exported_at": self.clock().isoformat(),
            },
        )

    def raise_hold(self, reason):
        if self.active():
            raise ContractError("Security hold already active")
        if not REASON.fullmatch(reason):
            raise ContractError("Hold reason must be a short lowercase token")
        hold = SecurityHold(
            "sh-" + secrets.token_hex(6), hold_scope(), OPERATOR, reason, self.clock()
        )
        self.runtime.state["security"] = {
            "active": True,
            "state": "SECURITY_HOLD",
            "hold": hold.document,
            "previous_phase": self.runtime.state["phase"],
            "acknowledged_at": self.clock().isoformat(),
        }
        self.export()
        return hold

    def approvers(self):
        try:
            return json.loads((self.root / APPROVERS).read_text())
        except (OSError, ValueError):
            return {}

    def trust(self, issuer_id, key_id):
        entry = self.approvers().get(issuer_id)
        if not entry or entry["key_id"] != key_id:
            raise ContractError("Unregistered security approver key")
        return VerifierTrust(
            issuer_id,
            key_id,
            entry["public_key_hex"],
            (hold_scope(),),
            (RELEASE_VERIFIER,),
            datetime.fromisoformat(entry["valid_from"]),
            datetime.fromisoformat(entry["valid_until"]),
            bool(entry.get("revoked", False)),
        )

    def authorize(self, principal, scope, action):
        hold = self.record.get("hold") or {}
        if (
            action != "security:release-approve"
            or principal not in self.approvers()
            or principal in {hold.get("raised_by"), OPERATOR}
            or scope != hold_scope()
        ):
            raise ContractError("Principal may not approve this hold release")
        return True

    def release(self, approval_id):
        if not self.active():
            raise ContractError("No active security hold")
        if not APPROVAL.fullmatch(approval_id):
            raise ContractError("Invalid approval id")
        stored = json.loads(
            (self.root / "releases" / (approval_id + ".json")).read_text()
        )
        request = release_from(stored["request"])
        envelope = envelope_from_document(stored["envelope"])
        hold = hold_from(self.record["hold"])
        if request.requested_by != OPERATOR:
            raise ContractError("Release must be requested by the console operator")
        HoldReleaseAuthority(
            envelope_provider=lambda _request: envelope,
            current_revisions=lambda _scope: self.revisions(self.record["hold"]),
            resolve_trust=self.trust,
            authorize=self.authorize,
            clock=self.clock,
        )(request)
        request.require_valid(hold, 1, self.clock())
        released = StoredHold(hold, 2, request)
        self.runtime.state["security"] = {
            "active": False,
            "state": "RELEASED",
            "hold": hold.document,
            "release": released.document,
            "release_fingerprint": envelope.fingerprint,
        }
        # No earlier approval or signed evidence is reused after a hold.
        state = self.runtime.state
        state.get("evidence", {}).pop("signed", None)
        if state["phase"] in {"planned", "awaiting_approval"}:
            state["phase"], state["plan"], state["approved"] = "detected", None, False
        elif state["phase"] in {"executing", "verifying"}:
            state["phase"], state["checks"] = "executing", []
        try:
            (self.root / HOLD_STATUS).unlink()
        except FileNotFoundError:
            pass
        return released


def approve(
    state_root, key_path, approver, reason, minutes=15, clock=lambda: datetime.now(UTC)
):
    """Approver-side: sign a HoldRelease for the currently exported hold."""
    state_root = Path(state_root)
    status = json.loads((state_root / HOLD_STATUS).read_text())
    key = json.loads(Path(key_path).read_text())
    if key["approver"] != approver:
        raise ContractError("Key belongs to another approver")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(key["private_key_hex"])
    )
    hold = status["hold"]
    now = clock()
    request = HoldRelease(
        hold["hold_id"],
        scope_from(hold["scope"]),
        RevisionSet(**status["revisions"]),
        status["revision"],
        status["requested_by"],
        approver,
        reason,
        status["evidence_id"],
        status["evidence_digest"],
        now,
        now + timedelta(minutes=minutes),
    )
    approval_id = "rel-" + secrets.token_hex(6)
    record = hold_release_record(request, evidence_id=approval_id)
    envelope = Ed25519EvidenceSigner(
        private, issuer_id=approver, key_id=key["key_id"]
    ).sign(record, issued_at=now)
    (state_root / "releases").mkdir(mode=0o700, exist_ok=True)
    private_json(
        state_root / "releases" / (approval_id + ".json"),
        {"request": request.document, "envelope": envelope.document},
    )
    return approval_id
