"""Bounded credential files, verified by opened descriptor, never by URL."""

import os
import stat


def private_text(path):
    # Verify the opened descriptor, not a path that may be replaced between
    # lstat and read. Secret rotation must atomically replace private files.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) & 0o077
        ):
            raise ValueError("Owner-private secret file required")
        raw = source.read(16385)
    if not 1 <= len(raw) <= 16384:
        raise ValueError("Bounded private secret file required")
    value = raw.decode("utf-8").strip()
    if not value:
        raise ValueError("Nonempty private secret file required")
    return value
