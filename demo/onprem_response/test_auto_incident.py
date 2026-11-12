"""Preauthorization abuse cases; local protocol tests, not cluster evidence."""

from datetime import timedelta
import json
from types import SimpleNamespace

import pytest

from sova.domain.contracts import ContractError

from .auto_incident import AutoIncidentTrial
from .auto_supervisor import AutoIncidentSupervisor
from .automatic_policy import validate_trigger
from .controls import seal
from .incident import IncidentTrial
from .supervisor import write_json
from .test_incident import skeleton
from .trial import now


def trigger_args():
    at = now()
    return dict(
        attack={
            "kind": "controlled_unauthorized_internal_http_attempt",
            "actor_pod_uid": "old-api",
            "actor_identity_verified": True,
            "independent_audit_verified": True,
            "upstream_status": 403,
            "nonce": "a" * 32,
            "observed_at": at.isoformat(),
        },
        intent={"nonce": "a" * 32},
        actor_uid="old-api",
        activated_at=(at - timedelta(seconds=1)).isoformat(),
        valid_until=(at + timedelta(minutes=2)).isoformat(),
        at=at,
    )


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "generic_http_403"},
        {"actor_pod_uid": "another-pod"},
        {"actor_identity_verified": False},
        {"independent_audit_verified": False},
        {"upstream_status": 200},
        {"nonce": "b" * 32},
        {"observed_at": "2000-01-01T00:00:00+00:00"},
        {"observed_at": "2099-01-01T00:00:00+00:00"},
        {"observed_at": "2026-01-01T00:00:00"},
    ],
)
def test_403_alone_wrong_actor_audit_nonce_and_stale_are_not_triggers(change):
    args = trigger_args()
    args["attack"].update(change)
    with pytest.raises(ContractError):
        validate_trigger(**args)


def test_only_an_attempt_after_authorization_and_before_expiry_is_eligible():
    args = trigger_args()
    validate_trigger(**args)
    args["activated_at"] = (args["at"] + timedelta(seconds=1)).isoformat()
    with pytest.raises(ContractError):
        validate_trigger(**args)
    args = trigger_args()
    args["valid_until"] = args["at"].isoformat()
    with pytest.raises(ContractError):
        validate_trigger(**args)


def automatic_skeleton(tmp_path):
    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    t = skeleton(root)
    t.__class__ = AutoIncidentTrial
    t.policy_offer, t.policy_grant = None, None
    t.auto_dispatched, t.auto_dispatching, t.policy_revoked = False, False, False
    t.source_revision = "f" * 40
    t.hmac_key = b"k" * 32
    t.plan_binding = {"plan_id": "fixture", "plan_digest": "e" * 64}
    t.attack_attempted, t.attack = False, None
    t.prepare_plan("respond")
    t.policy_offer = {
        "plan_id": "policy-a",
        "plan_digest": "d" * 64,
        "response_plan_digest": t.pending_plan.fingerprint,
        "actor_pod_uid": t.old_pods["api"],
        "components": list(t.components),
        "namespace_uids": dict(t.api.uids),
        "valid_until": t.deadline.isoformat(),
    }
    t.phase = "awaiting_arm"
    t.assert_current_scope = lambda: None
    return t


def arm(t):
    t.arm({"request_id": "b" * 32})
    args = trigger_args()
    args["attack"]["observed_at"] = now().isoformat()
    t.attack = args["attack"]
    write_json(t.root / "attempt-intent.private.json", args["intent"])


def test_unarmed_and_post_event_policy_never_dispatch(tmp_path):
    t = automatic_skeleton(tmp_path)
    calls = []
    t.accept_plan = lambda _: calls.append(True)
    with pytest.raises(ContractError, match="inactive"):
        t.bind_response(None, None, None)
    t.attack_attempted = True
    with pytest.raises(ContractError, match="before"):
        t.arm({"request_id": "b" * 32})
    assert calls == []
    assert not (t.root / "automatic-dispatch-intent.private.json").exists()


@pytest.mark.parametrize(
    "alter", ["plan", "components", "namespace", "revoked", "expired", "missing_audit"]
)
def test_changed_or_revoked_scope_has_zero_dispatch(tmp_path, alter):
    t = automatic_skeleton(tmp_path)
    arm(t)
    if alter == "plan":
        t.policy_offer["response_plan_digest"] = "e" * 64
    if alter == "components":
        t.components = ("api",)
    if alter == "namespace":
        t.api.uids = {"other": "other"}
    if alter == "revoked":
        t.policy_revoked = True
    if alter == "expired":
        t.deadline = now() - timedelta(seconds=1)
    if alter == "missing_audit":
        t.attack["independent_audit_verified"] = False
    calls = []
    t.accept_plan = lambda _: calls.append(True)
    with pytest.raises(ContractError):
        t.bind_response(None, None, None)
    assert calls == []


def test_eligible_event_dispatches_once_and_keeps_exact_plan(tmp_path):
    t = automatic_skeleton(tmp_path)
    arm(t)
    called = []
    t.accept_plan = lambda approval: called.append(approval)
    digest = t.pending_plan.fingerprint
    t.bind_response(None, None, None)
    assert len(called) == 1 and called[0]["automatic"] is True
    assert called[0]["response_plan_digest"] == digest
    assert t.auto_dispatched and not t.auto_dispatching
    with pytest.raises(ContractError, match="Single exact"):
        t.bind_response(None, None, None)
    assert len(called) == 1
    assert (
        json.loads((t.root / "automatic-dispatch-intent.private.json").read_text())[
            "event_nonce"
        ]
        == "a" * 32
    )


def test_existing_uncertain_dispatch_never_repeats_effect(tmp_path):
    t = automatic_skeleton(tmp_path)
    arm(t)
    write_json(t.root / "automatic-dispatch-intent.private.json", {"result": "unknown"})
    called = []
    t.accept_plan = lambda _: called.append(True)
    with pytest.raises(FileExistsError):
        t.bind_response(None, None, None)
    assert called == []


def test_policy_stop_is_rechecked_before_each_effect(tmp_path, monkeypatch):
    t = automatic_skeleton(tmp_path)
    arm(t)
    t.auto_dispatching = True
    calls = []
    monkeypatch.setattr(
        IncidentTrial, "authorize", lambda *a: calls.append(True) or True
    )
    command = SimpleNamespace(plan_digest=t.pending_plan.fingerprint)
    assert t.authorize(command, None, now(), True)
    write_json(
        tmp_path / "stop.private.json",
        seal(
            t.hmac_key,
            action="stop",
            request_id="c" * 32,
            binding=t.plan_binding,
            revision=t.source_revision,
            expires_at=t.deadline.isoformat(),
        ),
    )
    with pytest.raises(ContractError, match="inactive"):
        t.authorize(command, None, now(), True)
    assert calls == [True]


def test_policy_cannot_authorize_recovery(tmp_path, monkeypatch):
    t = automatic_skeleton(tmp_path)
    arm(t)
    t.auto_dispatching = True
    monkeypatch.setattr(
        IncidentTrial, "authorize", lambda *a: pytest.fail("recovery escaped policy")
    )
    with pytest.raises(ContractError, match="Recovery"):
        t.authorize(SimpleNamespace(plan_digest="e" * 64), None, now(), True)


def test_precompiled_plan_does_not_change_terminal_attempt_binding(tmp_path):
    t = automatic_skeleton(tmp_path)
    envelope = seal(
        t.hmac_key,
        action="attempt",
        request_id="a" * 32,
        binding=t.plan_binding,
        revision=t.source_revision,
        expires_at=t.deadline.isoformat(),
    )
    write_json(tmp_path / "attempt.private.json", envelope)
    assert t.command(tmp_path, "attempt")["request_id"] == "a" * 32
    with pytest.raises(ValueError):
        t.policy_command(tmp_path, "attempt")


def test_policy_approval_is_signed_exact_scope_and_wrong_body_creates_no_control(
    tmp_path,
):
    import threading

    manager = object.__new__(AutoIncidentSupervisor)
    manager.root, manager.session_id = tmp_path, "0" * 32
    manager.lock, manager.requests = threading.RLock(), {}
    manager.settings = SimpleNamespace(producer_revision="f" * 40)
    (manager.session / "state").mkdir(parents=True, mode=0o700)
    state = manager.session / "state"
    offer = {
        "plan_id": "policy-a",
        "plan_digest": "d" * 64,
        "valid_until": (now() + timedelta(minutes=2)).isoformat(),
    }
    write_json(state / "auto-policy-offer.private.json", offer)
    key = state / "feed-key.private"
    key.write_bytes(b"k" * 32)
    key.chmod(0o600)
    current = {
        "pending_kind": "arm",
        "can_respond": True,
        "session_id": manager.session_id,
        "plan_digest": offer["plan_digest"],
    }
    manager.status = lambda: dict(current)
    body = dict(
        action="respond",
        request_id="a" * 32,
        approved=True,
        session_id=manager.session_id,
        plan_digest=offer["plan_digest"],
    )
    for change in (
        {"approved": False},
        {"plan_digest": "e" * 64},
        {"session_id": "1" * 32},
        {"extra_scope": "shared-db"},
    ):
        with pytest.raises(ValueError):
            manager.act(body | change)
        assert not (manager.session / "arm.private.json").exists()
    assert manager.act(body) == {"accepted": True, "duplicate": False}
    assert manager.act(body) == {"accepted": True, "duplicate": True}
    current.update(pending_kind="respond", can_respond=False, plan_digest="e" * 64)
    assert manager.act(body) == {"accepted": True, "duplicate": True}
    from .controls import read

    assert (
        read(
            manager.session / "arm.private.json",
            key=key.read_bytes(),
            binding=offer,
            revision=manager.settings.producer_revision,
            at=now(),
            deadline=now() + timedelta(minutes=3),
            actions=frozenset({"arm"}),
        )["action"]
        == "arm"
    )
    with pytest.raises(ValueError, match="conflict"):
        manager.act(body | {"approved": False})
