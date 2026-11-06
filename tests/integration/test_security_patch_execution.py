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
    state["service"] = service
    state["scope"] = scope

    def run():
        return state["service"].execute_step(
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


def attach_architecture_program(state, plan, *, missing=None):
    """Synthetic producer facts, real stored-plan and SQLite effect execution."""
    from sova.interfaces.security_program import example_program
    from sova.security.application.security_program import with_security_program
    from sova_security.application.security_program import SecurityProgramService
    from sova_security.contracts.evidence import EvidenceRecord
    from sova_security.domain.security_program import ProgramKind, obligation_id

    scope = state["scope"]
    example = example_program(ProgramKind.PATCH, state["at"]).program
    bindings = tuple(replace(
        b, revisions=plan.revisions,
        obligation=replace(b.obligation, scope=scope,
                           obligation_id=obligation_id(plan.fingerprint, b.check_id)),
    ) for b in example.bindings)
    program = replace(example, source=scope, target=scope, subject_digest=plan.fingerprint,
                      bindings=bindings, valid_until=plan.valid_until)
    records = tuple(EvidenceRecord(
        "architecture:" + b.check_id, b.obligation.obligation_id, scope, b.revisions,
        b.obligation.verifier_version, state["at"], plan.valid_until, R.PASS,
        "synthetic:" + b.check_id, "d" * 64,
    ) for b in bindings if b.check_id != missing)
    state["program_records"] = records
    state["program_trusted"] = True
    program_service = SecurityProgramService(
        program_for=lambda *_: program,
        evidence_for=lambda *_: state["program_records"],
        authenticate_program=lambda _: state["program_trusted"],
        authenticate_evidence=lambda _: state["program_trusted"],
        authorize=lambda *_: True, require_no_holds=lambda _: not state["hold"],
        clock=lambda: state["at"],
    )
    service = state["service"]
    original = service.stored
    service.stored = with_security_program(original, program_service, actor="operator", scope=scope)
    assert original.executor.governance_guard is None  # Shared executor is not mutated.
    return program_service


def test_document_program_and_patch_guards_share_the_existing_executor(setup_patch):
    state, run, _, plan = setup_patch
    attach_architecture_program(state, plan)
    assert run().effect.status == EffectStatus.APPLIED
    assert run().effect.status == EffectStatus.APPLIED
    assert state["calls"] == 1


def test_patch_program_factory_preserves_shared_service_and_requires_both_phases(setup_patch):
    from sova.security.application.security_program import with_patch_security_program

    state, run, _, plan = setup_patch
    original = state["service"]
    original_stored = original.stored
    program_service = attach_architecture_program(state, plan)
    original.stored = original_stored
    configured = with_patch_security_program(original, program_service, scope=state["scope"])
    assert original.program_service is None
    assert original.stored is original_stored
    assert configured.stored is original_stored
    state["service"] = configured
    assert run().program_review.passed
    assert state["calls"] == 1
    with pytest.raises(ContractError, match="silently replaced"):
        with_patch_security_program(configured, program_service, scope=state["scope"])


@pytest.mark.parametrize("case", ["pass", "missing", "failed", "old", "expires-during-review", "runtime-revoked-during-review"])
def test_document_postflight_is_required_after_effect_and_never_replays(setup_patch, case):
    from sova.application.stored_plans import StoredPlanExecutor
    from sova.domain.evidence import VerificationResult
    from sova_security.domain.security_program import ProgramPhase

    state, run, journal, plan = setup_patch
    original = state["service"].stored
    program_service = attach_architecture_program(state, plan)
    # Use the service's per-call integration instead of the preflight-only wrapper.
    state["service"].stored = StoredPlanExecutor(original.repository, original.executor)
    state["service"].program_service = program_service
    state["service"].program_scope = state["scope"]
    if case == "missing":
        state["program_records"] = tuple(r for r in state["program_records"] if not r.obligation_id.endswith(":audit-trail"))
    elif case == "failed":
        state["program_records"] = tuple(replace(r, result=VerificationResult.FAIL)
            if r.obligation_id.endswith(":recovery-verification") else r for r in state["program_records"])
    elif case == "old":
        state["at"] += timedelta(seconds=10)
    elif case in {"expires-during-review", "runtime-revoked-during-review"}:
        original_review = program_service.review

        def review_with_change(*args, **kwargs):
            report = original_review(*args, **kwargs)
            if kwargs["phase"] == ProgramPhase.POSTFLIGHT:
                if case == "expires-during-review":
                    state["at"] = plan.valid_until
                else:
                    state["trusted"] = False
            return report

        program_service.review = review_with_change
    if case == "pass":
        result = run()
        assert result.program_review.passed
        assert result.program_review.phase == ProgramPhase.POSTFLIGHT
        assert not state["hold"]
    else:
        with pytest.raises(PatchPostflightRequired):
            run()
        assert state["hold"]
        with pytest.raises(ContractError):
            run()
    record = journal.get(plan.command("patch-1", operation_id="op", epoch=1))
    assert record.status == EffectStatus.APPLIED
    assert state["calls"] == 1


@pytest.mark.parametrize("check", ["identity-boundary", "proposal-scope", "sandbox-isolation", "resource-budget", "recovery-assets", "approval-binding"])
def test_document_control_gap_causes_zero_external_mutations(setup_patch, check):
    state, run, _, plan = setup_patch
    attach_architecture_program(state, plan, missing=check)
    with pytest.raises(ContractError, match="preflight"):
        run()
    assert state["calls"] == 0


def test_passing_document_checks_do_not_bypass_patch_or_human_approval(setup_patch):
    state, run, _, plan = setup_patch
    attach_architecture_program(state, plan)
    state["revoked"] = True
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 0


def test_program_revocation_is_rechecked_on_later_dispatch(setup_patch):
    state, run, _, plan = setup_patch
    attach_architecture_program(state, plan)
    assert run().effect.status == EffectStatus.APPLIED
    state["program_trusted"] = False
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 1


def test_uncertain_apply_with_program_is_held_not_retried(setup_patch):
    state, run, _, plan = setup_patch
    attach_architecture_program(state, plan)
    state["timeout"] = True
    with pytest.raises(PatchPostflightRequired):
        run()
    assert state["hold"]
    with pytest.raises(ContractError):
        run()
    assert state["calls"] == 1


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
