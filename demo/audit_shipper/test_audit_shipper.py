"""Deterministic checks for the audit shipper; real AWS runs are separate."""

import base64
import hashlib
import json
import sqlite3
from types import SimpleNamespace

import pytest

from .ship import Aws, ShipError, selected, ship
from .worm import check


def state(tmp_path):
    root = tmp_path / "state"
    (root / "evidence").mkdir(parents=True)
    (root / "evidence" / "run.isolate.verify.r3.json").write_text('{"signature": "ab"}')
    (root / "support-record-sq-1.json").write_text("{}")
    for secret in (
        "settings.private.json",
        "evidence-signing.private.json",
        "operator-access.json",
        "kubeconfig.private",
        "rotation.private.json",
    ):
        (root / secret).write_text("PRIVATE-DO-NOT-SHIP")
    (root / "evidence" / "leak.private.json").write_text("PRIVATE-DO-NOT-SHIP")
    db = sqlite3.connect(root / "responses.sqlite")
    db.execute(
        "CREATE TABLE journal(seq integer PRIMARY KEY AUTOINCREMENT, at text, kind text, body text)"
    )
    db.execute(
        "INSERT INTO journal(at,kind,body) VALUES(?,?,?)",
        ("t", "event", json.dumps({"phase": "held"})),
    )
    db.commit()
    return root


class FakeS3:
    def __init__(self, *, denied=(), checksum_ok=True, locked=True):
        self.denied, self.checksum_ok, self.locked = set(denied), checksum_ok, locked
        self.objects, self.calls = {}, []

    def __call__(self, args, **kwargs):
        args = args[1:-4]  # drop "aws" and the region/output tail
        self.calls.append(args)
        verb = args[1]
        if verb in self.denied:
            return SimpleNamespace(
                returncode=254, stdout="", stderr="An error occurred (AccessDenied)"
            )
        value = {}
        if verb == "put-object":
            body = open(args[args.index("--body") + 1], "rb").read()
            digest = hashlib.sha256(body).digest() if self.checksum_ok else b"\0" * 32
            version = "v" + str(len(self.objects))
            self.objects[version] = body
            value = {
                "VersionId": version,
                "ChecksumSHA256": base64.b64encode(digest).decode(),
            }
        elif verb == "get-object-retention":
            value = {
                "Retention": {
                    "Mode": "GOVERNANCE" if self.locked else "",
                    "RetainUntilDate": "2099-01-01T00:00:00Z",
                }
            }
        elif verb == "get-object":
            open(args[-1], "wb").write(
                self.objects[args[args.index("--version-id") + 1]]
            )
        return SimpleNamespace(returncode=0, stdout=json.dumps(value), stderr="")


def test_only_allowlisted_non_private_files_leave_the_state(tmp_path):
    names = [relative for relative, _path in selected(state(tmp_path))]
    assert names == ["evidence/run.isolate.verify.r3.json", "support-record-sq-1.json"]


def test_ship_records_checksummed_locked_versions_and_skips_unchanged(tmp_path):
    root = state(tmp_path)
    s3 = FakeS3()
    writer = Aws("ap-northeast-2", runner=s3)
    shipped = ship(root, "bucket", writer, "hybrid/state", tmp_path / "manifest.json")
    keys = [r["key"] for r in shipped]
    assert "hybrid/state/evidence/run.isolate.verify.r3.json" in keys
    assert any(k.startswith("hybrid/state/journal/journal-") for k in keys)
    assert not any(b"PRIVATE-DO-NOT-SHIP" in body for body in s3.objects.values())
    assert (
        ship(root, "bucket", writer, "hybrid/state", tmp_path / "manifest.json") == []
    )


@pytest.mark.parametrize("fake", [FakeS3(checksum_ok=False), FakeS3(locked=False)])
def test_unverified_checksum_or_missing_lock_fails_the_upload(tmp_path, fake):
    with pytest.raises(ShipError):
        ship(state(tmp_path), "bucket", Aws("r", runner=fake), "p", tmp_path / "m.json")


def test_worm_check_passes_only_on_access_denied_and_intact_original(tmp_path):
    s3 = FakeS3(denied={"put-object-retention", "delete-object"})
    writer = Aws("r", runner=s3)
    receipt = ship(
        state(tmp_path), "bucket", Aws("r", runner=FakeS3()), "p", tmp_path / "m.json"
    )[0]
    s3.objects[receipt["version_id"]] = (
        state(tmp_path / "again") / "evidence" / "run.isolate.verify.r3.json"
    ).read_bytes()
    assert check(writer, "bucket", receipt)["verdict"] == "PASS"
    allowed = FakeS3(denied={"put-object-retention"})
    allowed.objects = s3.objects
    assert check(Aws("r", runner=allowed), "bucket", receipt)["verdict"] == "FAIL"
