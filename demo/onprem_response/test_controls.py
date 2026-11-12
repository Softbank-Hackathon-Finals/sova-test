import copy
from datetime import UTC, datetime, timedelta

import pytest

from onprem_response.controls import read, seal
from onprem_response.supervisor import write_json

KEY = b"k" * 32
BINDING = {"plan_id": "owned-unit-trial", "plan_digest": "a" * 64}
REVISION = "b" * 40


@pytest.mark.parametrize(
    "change",
    [
        None,
        "plan",
        "source",
        "tamper",
        "expired",
        "foreign_action",
        "public",
        "symlink",
    ],
)
def test_control_bound_to_exact_owned_trial(tmp_path, change):
    at = datetime.now(UTC)
    expiry = at + timedelta(seconds=30)
    binding = copy.deepcopy(BINDING)
    envelope = seal(
        KEY,
        action="respond",
        request_id="c" * 32,
        binding=binding,
        revision=REVISION,
        expires_at=expiry.isoformat(),
    )
    if change == "plan":
        binding["plan_digest"] = "d" * 64
    if change == "source":
        envelope["body"]["producer_revision"] = "d" * 40
    if change == "tamper":
        envelope["body"]["request_id"] = "d" * 32
    if change == "expired":
        at = expiry + timedelta(seconds=1)
    if change == "foreign_action":
        envelope = seal(
            KEY,
            action="delete_anything",
            request_id="c" * 32,
            binding=binding,
            revision=REVISION,
            expires_at=expiry.isoformat(),
        )
    path = tmp_path / "command.private.json"
    write_json(path, envelope)
    if change == "public":
        path.chmod(0o644)
    if change == "symlink":
        path.rename(tmp_path / "other")
        path.symlink_to(tmp_path / "other")

    def verify():
        return read(
            path,
            key=KEY,
            binding=binding,
            revision=REVISION,
            at=at,
            deadline=expiry + timedelta(seconds=30),
        )

    if change is None:
        assert verify()["action"] == "respond"
    else:
        with pytest.raises((ValueError, OSError)):
            verify()


def test_feed_signature_cannot_approve_response(tmp_path):
    import hashlib
    import hmac
    from onprem_response.controls import canonical

    envelope = seal(
        KEY,
        action="respond",
        request_id="c" * 32,
        binding=BINDING,
        revision=REVISION,
        expires_at=(datetime.now(UTC) + timedelta(seconds=20)).isoformat(),
    )
    envelope["signature"] = hmac.new(
        KEY, canonical(envelope["body"]), hashlib.sha256
    ).hexdigest()
    path = tmp_path / "command.private.json"
    write_json(path, envelope)
    with pytest.raises(ValueError):
        read(
            path,
            key=KEY,
            binding=BINDING,
            revision=REVISION,
            at=datetime.now(UTC),
            deadline=datetime.now(UTC) + timedelta(minutes=1),
        )
