"""Real SQLite effect CAS with synthetic artifacts; no real image deployment."""

from dataclasses import replace
from datetime import timedelta
import json
from pathlib import Path
import sqlite3

import pytest

from sova.adapters.sqlite_effects import SQLiteEffectJournal
from sova.application.effects import EffectExecutor
from sova.application.plans import ApprovedPlanExecutor
from sova.application.stored_plans import StoredPlanExecutor
from sova.domain.contracts import ContractError, EffectObservation, EffectStatus
from sova.domain.plans import PlanApproval
from sova.ports.plans import StoredApproval
from sova.security.application.patch_execution import (
    PatchPlanExecutionService,
    PatchPostflightRequired,
)
from sova_security.adapters.modernization_codec import decode
from sova_security.adapters.patch_evidence import patch_rehearsal_records
from sova_security.application.patch_execution import PatchExecutionGuard
from sova_security.application.remediation import RehearsalAdmissionService
from sova_security.contracts.evidence import VerificationResult as R
from sova_security.domain.patch_execution import compile_patch, PatchRuntimeObservation
from security_patch_support import patch_rescan


@pytest.fixture
def setup_patch(tmp_path, now):
    data = json.loads(
        (
            Path(__file__).parents[1] / "fixtures/security/synthetic-patch-v1.json"
        ).read_text()
    )

    def restore(value):
        return decode(json.dumps(value).encode())

    inputs = tuple(restore(v) for v in data["inputs"])
    assessment, request, receipt = (
        restore(data[k]) for k in ("assessment", "request", "receipt")
    )
    state = {
        "at": now + timedelta(seconds=4),
        "binding": None,
        "revoked": False,
        "hold": False,
        "calls": 0,
        "timeout": False,
        "runtime": R.PASS,
        "trusted": True,
        "holds": [],
    }
    scope = request.proposal.scope
    inventories, adapters = (inputs[0],), {scope: "registered-oci-adapter"}
    admission = RehearsalAdmissionService(
        authorize=lambda *_: None,
        authenticate_input=lambda *_: None,
        authenticate_receipt=lambda *_: None,
        current_inputs=lambda _: inputs,
        current_request=lambda *_: request,
        current_assessment=lambda *_: assessment,
        target_inventory=lambda _: inputs[0],
        clock=lambda: state["at"],
    )
    decision = admission.verify("operator", request=request, receipt=receipt)
    plan, binding = compile_patch(
        request,
        receipt,
        decision,
        inventories=inventories,
        adapters=adapters,
        plan_id="registered-patch",
        created_by="operator",
        now=state["at"],
    )
    state["binding"] = binding
    records = patch_rehearsal_records(
        plan, binding, request, receipt, evidence_prefix="verified"
    )
    saved = StoredApproval(
        "approval",
        plan.plan_id,
        PlanApproval(
            plan.fingerprint, "independent-reviewer", plan.purpose, plan.valid_until
        ),
        1,
        False,
    )

    class Repository:
        def get_plan(self, *_):
            return plan

        def get_approval(self, *_):
            return replace(saved, revoked=state["revoked"])

    class Adapter:
        adapter_id = "registered-oci-adapter"

        def validate(self, command):
            if command != plan.command("patch-1", operation_id="op", epoch=1):
                raise ContractError("Command differs from registered intent")

        def apply(self, command):
            state["calls"] += 1
            if state["timeout"]:
                raise TimeoutError("Synthetic lost response after effect")

        def readback(self, command, at):
            return EffectObservation(
                scope,
                command.fingerprint,
                EffectStatus.APPLIED,
                at,
                '{"synthetic_registered_artifact":true}',
            )

    conn = sqlite3.connect(tmp_path / "patch-effects.sqlite")
    journal = SQLiteEffectJournal(conn)
    guard = PatchExecutionGuard(
        admission=admission,
        binding_for=lambda _: state["binding"],
        inputs_for=lambda _: (request, receipt, inventories, adapters),
        authenticate_binding=lambda *_: None,
        authorize=lambda *_: None,
        require_no_holds=lambda _: not state["hold"],
        clock=lambda: state["at"],
    )
    base = ApprovedPlanExecutor(
        EffectExecutor(journal, authorize=lambda *_: None, clock=lambda: state["at"]),
        required_obligations=lambda _: plan.obligations,
        authenticate_approval=lambda *_: None,
        authenticate_evidence=lambda _: None,
        clock=lambda: state["at"],
    )

    def observe(command, current_binding):
        state["reassessment"], _, _ = patch_rescan(
            inputs,
            assessment,
            request.proposal,
            current_binding.artifacts[0],
            state["at"],
        )
        return PatchRuntimeObservation(
            scope,
            plan.fingerprint,
            command.fingerprint,
            current_binding.artifacts[0],
            "resource-v2",
            "runtime-verifier",
            "e" * 64,
            R.PASS,
            R.PASS,
            state["runtime"],
            state["at"],
            binding.valid_until,
            state["reassessment"].fingerprint,
        )

    def hold(command, reason):
        state["holds"].append((command.fingerprint, reason))
        state["hold"] = True

    service = PatchPlanExecutionService(
        stored_executor=StoredPlanExecutor(Repository(), base),
        patch_guard=guard,
        binding_for=lambda _: state["binding"],
        observe_runtime=observe,
        reassessment_for=lambda _: state["reassessment"],
        authenticate_runtime=lambda *_: state["trusted"],
        authenticate_binding=lambda *_: None,
        authorize=lambda *_: None,
        record_hold=hold,
        clock=lambda: state["at"],
    )
    state["at"] += timedelta(seconds=1)

    def run():
        return service.execute_step(
            "operator",
            scope.application_id,
            plan.plan_id,
            "approval",
            "patch-1",
            operation_id="op",
            epoch=1,
            evidence=records,
            adapter=Adapter(),
        )

    yield state, run, journal, plan
    conn.close()


def test_verified_patch_reuses_existing_durable_effect_and_approval(setup_patch):
    state, run, _, _ = setup_patch
    assert run().effect.status == EffectStatus.APPLIED
    state["at"] += timedelta(seconds=1)
    assert run().observation.protection == R.PASS
    assert state["calls"] == 1  # Historical effect readback, never a second apply.


@pytest.mark.parametrize("case", ["approval-revoked", "active-hold", "binding-revoked"])
def test_patch_cannot_bypass_stored_approval_or_incident_hold(setup_patch, case):
    state, run, _, _ = setup_patch
    state[
        {
            "approval-revoked": "revoked",
            "active-hold": "hold",
            "binding-revoked": "binding",
        }[case]
    ] = None if case == "binding-revoked" else True
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 0


@pytest.mark.parametrize(
    "case", ["lost-response", "failed-postflight", "untrusted-proof"]
)
def test_uncertainty_and_failed_revalidation_hold_without_reapply(setup_patch, case):
    state, run, journal, plan = setup_patch
    if case == "lost-response":
        state["timeout"] = True
    if case == "failed-postflight":
        state["runtime"] = R.FAIL
    if case == "untrusted-proof":
        state["trusted"] = False
    with pytest.raises(PatchPostflightRequired):
        run()
    record = journal.get(plan.command("patch-1", operation_id="op", epoch=1))
    assert record.status == (
        EffectStatus.UNKNOWN if case == "lost-response" else EffectStatus.APPLIED
    )
    assert state["holds"]
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 1
