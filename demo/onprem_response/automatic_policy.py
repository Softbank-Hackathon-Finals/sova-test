"""Finite preauthorization for an owned outbound tripwire, never generic HTTP 403."""

from datetime import datetime

from sova.domain.contracts import ContractError

TRIGGER = "owned-forbidden-egress-tripwire.v1"


def validate_trigger(*, attack, intent, actor_uid, activated_at, valid_until, at):
    """TerminalTrial must first verify the actual Pod/owner/IP and peer audit.

    These predicates qualify only that fixed fixture's outbound attempt. They do
    not classify a real application as compromised or consume untrusted alerts.
    """
    if not isinstance(attack, dict) or not isinstance(intent, dict):
        raise ContractError("Verified outbound tripwire required")
    try:
        observed = datetime.fromisoformat(attack["observed_at"])
        issued = datetime.fromisoformat(activated_at)
        until = datetime.fromisoformat(valid_until)
        valid = (
            all(x.utcoffset() is not None for x in (observed, issued, until, at))
            and issued <= observed <= at < until
            and (at - observed).total_seconds() <= 30
            and attack["kind"] == "controlled_unauthorized_internal_http_attempt"
            and attack["actor_pod_uid"] == actor_uid
            and attack["actor_identity_verified"] is True
            and attack["independent_audit_verified"] is True
            and attack["upstream_status"] == 403
            and attack["nonce"] == intent["nonce"]
        )
    except (KeyError, TypeError, ValueError):
        valid = False
    if not valid:
        raise ContractError(
            "Fresh registered outbound tripwire and active policy required"
        )
