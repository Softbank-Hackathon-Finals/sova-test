import os

import pytest

from examples.consultation.private_files import private_text


def test_private_secret_is_bounded_and_read_from_one_verified_descriptor(
    tmp_path, monkeypatch
):
    path = tmp_path / "secret"
    path.write_text(" synthetic credential ")
    path.chmod(0o600)
    assert private_text(path) == "synthetic credential"
    replacement = tmp_path / "replacement"
    replacement.write_text("untrusted replacement")
    replacement.chmod(0o644)
    original_open = os.open

    def swap_after_open(name, flags):
        fd = original_open(name, flags)
        path.unlink()
        path.symlink_to(replacement)
        return fd

    monkeypatch.setattr(os, "open", swap_after_open)
    assert private_text(path) == "synthetic credential"


@pytest.mark.parametrize(
    "content,mode",
    [(b"secret", 0o644), (b"x" * 16385, 0o600), (b"", 0o600), (b"\xff", 0o600)],
)
def test_public_empty_invalid_or_oversize_secret_is_rejected(tmp_path, content, mode):
    path = tmp_path / "secret"
    path.write_bytes(content)
    path.chmod(mode)
    with pytest.raises((ValueError, OSError)):
        private_text(path)


def test_secret_symlink_is_rejected(tmp_path):
    original = tmp_path / "original"
    original.write_text("private value")
    original.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(original)
    with pytest.raises(OSError):
        private_text(link)


def test_secret_fifo_is_rejected_without_waiting_for_a_writer(tmp_path):
    path = tmp_path / "pipe"
    os.mkfifo(path, 0o600)
    with pytest.raises(ValueError):
        private_text(path)
