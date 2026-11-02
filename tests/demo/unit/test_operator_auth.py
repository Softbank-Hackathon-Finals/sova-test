from datetime import timedelta
import json
from concurrent.futures import ThreadPoolExecutor

import pytest

from operator_auth import OperatorAuth, write_bootstrap_file
from sova.domain.contracts import ContractError


def test_explicit_owner_session_lasts_until_deadline_but_bootstrap_stays_short(now):
    clock = [now]
    until = now + timedelta(hours=4)
    auth = OperatorAuth(deadline=until, session_until=until, clock=lambda: clock[0])
    grant = auth.issue_bootstrap()
    token, session = auth.exchange(grant)
    assert session.expires_at == until
    assert auth.bootstrap_until == now + timedelta(minutes=5)
    clock[0] += timedelta(hours=3)
    assert auth.authenticate(token) == session
    with pytest.raises(ContractError):
        auth.exchange(grant)
    clock[0] = until
    assert auth.authenticate(token) is None


def test_long_session_requires_explicit_opt_in_and_cannot_outlive_runtime(now):
    with pytest.raises(ContractError):
        OperatorAuth(deadline=now + timedelta(hours=4), clock=lambda: now)
    with pytest.raises(ContractError):
        OperatorAuth(
            deadline=now + timedelta(hours=4),
            session_until=now + timedelta(hours=5),
            clock=lambda: now,
        )


def test_bootstrap_is_consumed_atomically_and_sessions_expire(now):
    clock = [now]
    auth = OperatorAuth(deadline=now + timedelta(hours=1), clock=lambda: clock[0])
    grant = auth.issue_bootstrap()

    def exchange():
        try:
            return auth.exchange(grant)
        except ContractError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: exchange(), range(2)))
    assert sum(item is not None for item in results) == 1
    token, session = next(item for item in results if item is not None)
    assert auth.authenticate(grant) is None
    assert auth.authenticate(token) == session
    assert token not in repr(auth._sessions)
    clock[0] = session.expires_at
    assert auth.authenticate(token) is None


def test_expired_bootstrap_revocation_and_invalid_credentials(now):
    clock = [now]
    auth = OperatorAuth(deadline=now + timedelta(minutes=20), clock=lambda: clock[0])
    grant = auth.issue_bootstrap()
    with pytest.raises(ContractError):
        auth.exchange("wrong" * 10)
    token, _ = auth.exchange(grant)
    auth.revoke(token)
    assert auth.authenticate(token) is None
    for value in [None, {}, "", "가" * 40, "x" * 129]:
        assert auth.authenticate(value) is None
    auth = OperatorAuth(deadline=now + timedelta(minutes=20), clock=lambda: clock[0])
    grant = auth.issue_bootstrap()
    clock[0] += timedelta(minutes=5)
    with pytest.raises(ContractError):
        auth.exchange(grant)


def test_attempt_budget_does_not_create_unbounded_sessions(now):
    auth = OperatorAuth(deadline=now + timedelta(hours=1), clock=lambda: now)
    grant = auth.issue_bootstrap()
    for _ in range(8):
        with pytest.raises(ContractError):
            auth.exchange("x" * 43)
    with pytest.raises(ContractError, match="rate limited"):
        auth.exchange(grant)
    assert not auth._sessions


def test_owner_file_is_private_exclusive_and_refuses_symlink(tmp_path, now):
    root = tmp_path / "private"
    root.mkdir(mode=0o700)
    path = write_bootstrap_file(
        root, origin="http://127.0.0.1:8792", token="x" * 43, expires_at=now
    )
    assert path.stat().st_mode & 0o777 == 0o600
    assert json.loads(path.read_text())["url"].endswith("/#" + "x" * 43)
    with pytest.raises(FileExistsError):
        write_bootstrap_file(
            root, origin="http://127.0.0.1:8792", token="y" * 43, expires_at=now
        )
    path.unlink()
    destination = tmp_path / "do-not-touch"
    destination.write_text("untouched")
    path.symlink_to(destination)
    with pytest.raises(OSError):
        write_bootstrap_file(
            root, origin="http://127.0.0.1:8792", token="y" * 43, expires_at=now
        )
    assert destination.read_text() == "untouched"
    root.chmod(0o755)
    with pytest.raises(ContractError):
        write_bootstrap_file(
            root, origin="http://127.0.0.1:8792", token="y" * 43, expires_at=now
        )
