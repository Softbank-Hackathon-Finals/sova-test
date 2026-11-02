"""Console restarts read history; terminal labels alone are not new receipts.

Provider/repository boundaries are doubles here. Actual PostgreSQL+k3s restart
qualification is recorded separately; this fixes the projection behavior in CI.
"""

from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import security_console
from security_support import security_snapshot
from sova.domain.contracts import EffectObservation, EffectStatus
from sova.domain.response_completion import ResponseCompletion
from sova.domain.security_response import (
    SecurityResponseBinding,
    StatelessResponseProfile,
)
from sova.domain.workflows import OperationStatus
from sova.ports.plans import RecordNotFound


@pytest.mark.parametrize("case", ["complete", "legacy", "missing-effect"])
def test_recovery_requires_atomic_receipt_and_does_not_repeat_effects(
    case, scope, now, tmp_path, monkeypatch
):
    deadline = now + timedelta(minutes=5)
    source = security_snapshot(scope, now)
    target = security_snapshot(replace(scope, environment_id="target"), now)
    profile = StatelessResponseProfile(
        "owned-local-stateless-test",
        "a" * 64,
        "f" * 64,
        True,
        True,
        True,
        "operator",
        deadline,
    )
    binding = SecurityResponseBinding(
        source,
        target,
        "deployment:api",
        "deployment:api",
        ("incident",),
        profile,
        "c" * 64,
    )
    plan = binding.compile(
        plan_id="response",
        created_by="planner",
        now=now,
        valid_until=now + timedelta(minutes=2),
    )
    operation_id = "operation"
    command = plan.command("switch_route", operation_id=operation_id, epoch=2)
    proof = ResponseCompletion(
        command,
        EffectObservation(
            command.scope, command.fingerprint, EffectStatus.APPLIED, now, "{}"
        ),
        "worker",
        plan.valid_until,
    )
    operation = SimpleNamespace(
        request=SimpleNamespace(
            plan_digest=plan.fingerprint, operation_id=operation_id
        ),
        state=SimpleNamespace(status=OperationStatus.RESPONSE_VERIFIED, revision=7),
    )
    receipts = []
    for step in plan.steps:
        c = plan.command(step.step_id, operation_id=operation_id, epoch=2)
        receipts.append(
            (
                c.document,
                c.fingerprint,
                "confirmed_applied",
                {"observed_at": now.isoformat()},
            )
        )
    if case == "missing-effect":
        receipts.pop()

    @contextmanager
    def transaction():
        yield SimpleNamespace(
            execute=lambda *_: SimpleNamespace(fetchall=lambda: receipts)
        )

    lifecycle = SimpleNamespace(get_plan=lambda *_: plan, transaction=transaction)

    def completion(*_):
        if case == "legacy":
            raise RecordNotFound("Legacy terminal status has no atomic receipt")
        return operation, proof

    operations = SimpleNamespace(
        get=lambda *_: operation, get_response_completion=completion
    )
    adapter = SimpleNamespace(apply=Mock())
    monkeypatch.setattr(
        security_console,
        "PostgresLifecycleRepository",
        lambda *_args, **_kwargs: lifecycle,
    )
    monkeypatch.setattr(
        security_console, "PostgresOperationRepository", lambda *_: operations
    )
    monkeypatch.setattr(
        security_console, "OwnedKubernetesResponse", lambda **_: adapter
    )
    tmp_path.chmod(0o700)
    reference = tmp_path / "prepared-reference.json"
    reference.write_text(
        json.dumps({"plan_id": plan.plan_id, "operation_id": operation_id})
    )
    reference.chmod(0o600)
    console = object.__new__(security_console.SecurityConsole)
    console.root, console.tenant, console.app = (
        tmp_path,
        scope.tenant_id,
        scope.application_id,
    )
    console.worker_connect = lambda: None
    console.clean = {
        "image": "example@sha256:" + profile.image_digest,
        "configuration_digest": profile.configuration_digest,
    }
    console.deadline, console.operator = deadline, "operator"
    console.registrations = {
        "blue": SimpleNamespace(namespace_uid="source"),
        "green": SimpleNamespace(namespace_uid="target"),
    }
    console.probe, console.routes = SimpleNamespace(probe_port=1), object()
    console.read_observations = SimpleNamespace(
        get_snapshot=lambda _app, digest: (
            source if digest == source.fingerprint else target
        )
    )
    console.operation = console.prepared = None
    console.recover_read_only()
    adapter.apply.assert_not_called()
    if case == "missing-effect":
        assert console.phase == "read_only_recovery_unverified" and console.error
        assert console.operation is None
    else:
        assert console.operation["read_only_recovered"]
        assert all(s["historical"] for s in console.steps)
        assert console.operation["completion_receipt"] == (
            "recorded" if case == "complete" else "unavailable"
        )
        assert bool(console.error) is (case == "legacy")
