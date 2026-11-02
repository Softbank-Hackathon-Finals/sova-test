from dataclasses import replace
from datetime import timedelta
import pytest
from sova.domain.contracts import ContractError
from sova.domain.signed_evidence import VerifierTrust
from sova.domain.verifier_registry import VerifierTrustChange
from sova.adapters.verifier_registry_codec import decode_trust_change
from sova.application.verifier_registry import VerifierRegistryAdministration


def trust_change(scope, now):
    trust = VerifierTrust(
        "issuer",
        "key-1",
        "a" * 64,
        (scope,),
        ("probe-v1",),
        now,
        now + timedelta(minutes=5),
    )
    return VerifierTrustChange(
        scope.tenant_id,
        scope.application_id,
        1,
        trust,
        "requester",
        "approver",
        "register independent probe",
        now,
        now + timedelta(minutes=1),
    )


def test_exact_codec_and_independent_app_scoped_approval(scope, now):
    change = trust_change(scope, now)
    assert decode_trust_change(change.document) == change
    change.require_current(now)
    change.require_successor(None)
    with pytest.raises(ContractError):
        replace(change, approved_by=change.requested_by)
    with pytest.raises(ContractError):
        replace(
            change,
            trust=replace(
                change.trust, allowed_scopes=(replace(scope, application_id="other"),)
            ),
        )
    with pytest.raises(ContractError):
        change.require_current(change.approval_until)


def test_revoked_key_cannot_return_and_rotation_requires_new_id(scope, now):
    first = trust_change(scope, now)
    revoke = replace(first, revision=2, trust=replace(first.trust, revoked=True))
    revoke.require_successor(first)
    with pytest.raises(ContractError, match="reactivated"):
        replace(first, revision=3).require_successor(revoke)
    with pytest.raises(ContractError, match="new key ID"):
        replace(
            first, revision=2, trust=replace(first.trust, public_key_hex="b" * 64)
        ).require_successor(first)
    rotated = replace(
        first, trust=replace(first.trust, key_id="key-2", public_key_hex="b" * 64)
    )
    rotated.require_successor(None)


def test_administration_authenticates_exact_change_and_authorizes_both_roles(
    scope, now
):
    change = trust_change(scope, now)
    calls = []

    class Repo:
        tenant_id = scope.tenant_id
        application_id = scope.application_id

        def publish(self, c):
            calls.append(("published", c.fingerprint))
            return c

    service = VerifierRegistryAdministration(
        Repo(),
        authorize=lambda *args: calls.append(args),
        authenticate_approval=lambda c: calls.append(("authenticated", c.fingerprint)),
        clock=lambda: now,
    )
    assert service.publish("requester", change) == change
    assert calls[0][-1] == "verifier-trust:request"
    assert calls[1] == ("authenticated", change.fingerprint)
    assert calls[2][-1] == "verifier-trust:approve"
    with pytest.raises(ContractError):
        service.publish("other", change)
