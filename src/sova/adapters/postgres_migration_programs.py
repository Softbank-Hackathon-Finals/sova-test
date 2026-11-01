"""Immutable phase bindings; trusted publisher and read-only worker are separate.

Use an authenticated server-side action registry. Stored reason/phase labels
alone never grant a lower gate. No schema creation or role grants happen here.
"""

from psycopg.types.json import Jsonb

from sova.adapters.migration_codec import decode_migration_program
from sova.application.migration_phases import (
    MigrationPhase,
    compile_migration_phase,
    phase_action_digest,
)
from sova.domain.contracts import ContractError, digest, identifier
from sova.ports.plans import RecordNotFound, RepositoryConflict


class PostgresMigrationProgramRepository:
    def __init__(self, lifecycle):
        self.lifecycle = lifecycle
        self.tenant_id = lifecycle.tenant_id

    def save_program(self, program, *, actor_id):
        identifier(actor_id, "program publisher")
        self.lifecycle.require_scope(program.source_scope)
        with self.lifecycle.transaction() as conn:
            inserted = conn.execute(
                "INSERT INTO sova_control.migration_programs(tenant_id,application_id,program_digest,document,issued_at,valid_until,created_by) VALUES(%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING program_digest",
                (
                    self.tenant_id,
                    program.source_scope.application_id,
                    program.fingerprint,
                    Jsonb(program.document),
                    program.issued_at,
                    program.valid_until,
                    actor_id,
                ),
            ).fetchone()
            current = self._get_program(
                conn, program.source_scope.application_id, program.fingerprint
            )
            if current != program:
                raise RepositoryConflict("Stored migration program differs")
            if inserted:
                self.lifecycle.audit(
                    conn,
                    self.tenant_id,
                    program.source_scope.application_id,
                    program.fingerprint,
                    "migration_program_created",
                    actor_id,
                    1,
                )

    def _get_program(self, conn, application_id, program_digest):
        digest(program_digest)
        row = conn.execute(
            "SELECT document,issued_at,valid_until FROM sova_control.migration_programs WHERE tenant_id=%s AND application_id=%s AND program_digest=%s",
            (self.tenant_id, application_id, program_digest),
        ).fetchone()
        if row is None:
            raise RecordNotFound("Migration program not found")
        program = decode_migration_program(row[0])
        if (
            program.source_scope.tenant_id,
            program.source_scope.application_id,
            program.fingerprint,
            program.issued_at,
            program.valid_until,
        ) != (self.tenant_id, application_id, program_digest, row[1], row[2]):
            raise ContractError("Stored migration program integrity mismatch")
        return program

    def get_program(self, application_id, program_digest):
        with self.lifecycle.transaction() as conn:
            return self._get_program(conn, application_id, program_digest)

    @staticmethod
    def _compile(program, phase, plan, registry):
        binding = compile_migration_phase(
            program,
            phase,
            plan_id=plan.plan_id,
            created_by=plan.created_by,
            steps=plan.steps,
            action_registry=registry,
            valid_until=plan.valid_until,
        )
        if binding.plan != plan:
            raise ContractError("Stored phase plan differs from trusted compiler")
        return binding

    def finish_phase(
        self,
        operations,
        ownership,
        lease,
        completion,
        *,
        expected_revision,
        action_registry,
    ):
        from datetime import timedelta
        from sova.adapters.postgres_effects import PostgresEffectJournal
        from sova.adapters.postgres_governance import (
            PostgresSecurityHolds,
            lock_security_hold_set,
        )
        from sova.domain.contracts import EffectStatus
        from sova.domain.execution import ExecutionMode
        from sova.domain.phase_completion import PhaseCompletion
        from sova.domain.workflows import OperationProfile, OperationStatus

        if (
            not isinstance(completion, PhaseCompletion)
            or operations.lifecycle is not self.lifecycle
            or ownership.lifecycle is not self.lifecycle
            or lease.mode != ExecutionMode.MUTATE
        ):
            raise ContractError("Owned typed phase completion required")
        if (
            completion.tenant_id,
            completion.application_id,
            completion.operation_id,
            completion.epoch,
            completion.owner_id,
        ) != (
            self.tenant_id,
            lease.application_id,
            lease.operation_id,
            lease.epoch,
            lease.owner_id,
        ):
            raise ContractError("Phase completion scope/owner/epoch mismatch")
        if type(expected_revision) is not int or expected_revision < 1:
            raise ContractError("Positive phase revision required")
        with self.lifecycle.transaction() as conn:
            ownership.require_current(conn, lease)
            lock_security_hold_set(conn, self.tenant_id, lease.application_id)
            current = operations._get(
                conn, lease.application_id, lease.operation_id, lock=True
            )
            if (
                current.state.profile != OperationProfile.MIGRATION_PHASE
                or current.state.status != OperationStatus.VERIFYING
                or current.state.revision != expected_revision
                or current.state.security_hold
            ):
                raise RepositoryConflict("Phase is not in owned verification state")
            binding = self._get_binding(
                conn,
                lease.application_id,
                current.request.plan_id,
                action_registry=action_registry,
            )
            plan = binding.plan
            if (
                completion.plan_digest,
                completion.program_digest,
                completion.phase,
            ) != (plan.fingerprint, binding.program.fingerprint, binding.phase):
                raise ContractError("Completion differs from bound program/phase")
            conn.execute(
                "SELECT revision FROM sova_control.approvals WHERE tenant_id=%s AND application_id=%s AND approval_id=%s FOR SHARE",
                (self.tenant_id, lease.application_id, current.request.approval_id),
            ).fetchone()
            saved = self.lifecycle._get_approval(
                conn, lease.application_id, current.request.approval_id
            )
            if (
                saved.revoked
                or saved.revision != current.request.approval_revision
                or saved.plan_id != plan.plan_id
            ):
                raise ContractError("Phase approval revoked or changed")
            holds = PostgresSecurityHolds(
                self.lifecycle.connect, tenant_id=self.tenant_id
            )._active(conn, lease.application_id)
            if holds:
                raise ContractError("Security hold blocks phase completion")
            if len(completion.observations) != len(plan.steps):
                raise ContractError("Every phase effect needs a fresh final readback")
            journal = PostgresEffectJournal(ownership, lease)
            _, database_now = ownership.require_current(conn, lease)
            saved.approval.require_valid(plan, database_now)
            if completion.verified_until > min(
                plan.valid_until, saved.approval.valid_until, lease.valid_until
            ):
                raise ContractError(
                    "Phase completion exceeds an authorization lifetime"
                )
            for step, observed in zip(plan.steps, completion.observations, strict=True):
                command = plan.command(
                    step.step_id, operation_id=lease.operation_id, epoch=lease.epoch
                )
                row = journal._row(conn, command)
                if row is None:
                    raise ContractError("Phase effect receipt is missing")
                receipt = journal._decode(row)
                if (
                    receipt.status != EffectStatus.APPLIED
                    or receipt.command != command
                    or observed.command_digest != command.fingerprint
                    or observed.scope != command.scope
                ):
                    raise ContractError("Phase effects do not match final readbacks")
                if (
                    not receipt.observation.observed_at
                    <= observed.observed_at
                    <= database_now
                    < min(
                        completion.verified_until,
                        observed.observed_at + timedelta(seconds=15),
                    )
                ):
                    raise ContractError("Final phase readback is stale or future")
            conn.execute(
                "INSERT INTO sova_control.migration_phase_completions(tenant_id,application_id,operation_id,digest,document) VALUES(%s,%s,%s,%s,%s)",
                (
                    self.tenant_id,
                    lease.application_id,
                    lease.operation_id,
                    completion.fingerprint,
                    Jsonb(completion.document),
                ),
            )
            self.lifecycle.audit(
                conn,
                self.tenant_id,
                lease.application_id,
                lease.operation_id,
                "migration_phase_completed",
                lease.owner_id,
                current.state.revision + 1,
            )
            finished = operations._advance_locked(
                conn,
                current,
                OperationStatus.PHASE_VERIFIED,
                expected_revision=expected_revision,
                actor_id=lease.owner_id,
                now=database_now,
            )
            ownership._release_locked(conn, lease, completion.fingerprint)
            return finished, completion

    def get_phase_completion(self, operations, application_id, operation_id):
        from sova.adapters.phase_completion_codec import decode_phase_completion
        from sova.domain.workflows import OperationProfile, OperationStatus

        if operations.lifecycle is not self.lifecycle:
            raise ContractError("Same scoped operation repository required")
        with self.lifecycle.transaction() as conn:
            row = conn.execute(
                "SELECT digest,document FROM sova_control.migration_phase_completions WHERE tenant_id=%s AND application_id=%s AND operation_id=%s",
                (self.tenant_id, application_id, operation_id),
            ).fetchone()
            if row is None:
                raise RecordNotFound("Phase completion not found")
            completion = decode_phase_completion(row[1])
            operation = operations._get(conn, application_id, operation_id)
            plan = self.lifecycle._get_plan(
                conn, application_id, operation.request.plan_id
            )
            binding = conn.execute(
                "SELECT program_digest,phase FROM sova_control.migration_phase_bindings WHERE tenant_id=%s AND application_id=%s AND plan_id=%s",
                (self.tenant_id, application_id, plan.plan_id),
            ).fetchone()
            if (
                completion.fingerprint != row[0]
                or (
                    completion.tenant_id,
                    completion.application_id,
                    completion.operation_id,
                    completion.plan_digest,
                )
                != (self.tenant_id, application_id, operation_id, plan.fingerprint)
                or binding != (completion.program_digest, str(completion.phase))
                or operation.state.profile != OperationProfile.MIGRATION_PHASE
                or operation.state.status != OperationStatus.PHASE_VERIFIED
            ):
                raise ContractError("Historical phase completion integrity mismatch")
            return operation, completion

    def save_binding(self, binding, *, action_registry, actor_id):
        identifier(actor_id, "phase publisher")
        plan = binding.plan
        registry_digest = phase_action_digest(action_registry)
        with self.lifecycle.transaction() as conn:
            stored_plan = self.lifecycle._get_plan(
                conn, plan.application_id, plan.plan_id
            )
            program = self._get_program(
                conn, plan.application_id, binding.program.fingerprint
            )
            compiled = self._compile(
                program, binding.phase, stored_plan, action_registry
            )
            if compiled != binding:
                raise ContractError("Phase binding differs from persisted program/plan")
            inserted = conn.execute(
                "INSERT INTO sova_control.migration_phase_bindings(tenant_id,application_id,plan_id,plan_digest,program_digest,phase,action_registry_digest,created_by) VALUES(%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING plan_id",
                (
                    self.tenant_id,
                    plan.application_id,
                    plan.plan_id,
                    plan.fingerprint,
                    program.fingerprint,
                    str(binding.phase),
                    registry_digest,
                    actor_id,
                ),
            ).fetchone()
            row = conn.execute(
                "SELECT plan_digest,program_digest,phase,action_registry_digest FROM sova_control.migration_phase_bindings WHERE tenant_id=%s AND application_id=%s AND plan_id=%s",
                (self.tenant_id, plan.application_id, plan.plan_id),
            ).fetchone()
            if row != (
                plan.fingerprint,
                program.fingerprint,
                str(binding.phase),
                registry_digest,
            ):
                raise RepositoryConflict("Phase binding cannot be replaced")
            if inserted:
                self.lifecycle.audit(
                    conn,
                    self.tenant_id,
                    plan.application_id,
                    plan.plan_id,
                    "migration_phase_bound",
                    actor_id,
                    1,
                )

    def get_binding(self, application_id, plan_id, *, action_registry):
        with self.lifecycle.transaction() as conn:
            return self._get_binding(
                conn, application_id, plan_id, action_registry=action_registry
            )

    def _get_binding(self, conn, application_id, plan_id, *, action_registry):
        registry_digest = phase_action_digest(action_registry)
        row = conn.execute(
            "SELECT plan_digest,program_digest,phase,action_registry_digest FROM sova_control.migration_phase_bindings WHERE tenant_id=%s AND application_id=%s AND plan_id=%s",
            (self.tenant_id, application_id, plan_id),
        ).fetchone()
        if row is None:
            raise RecordNotFound("Migration phase binding not found")
        if row[3] != registry_digest:
            raise ContractError("Current phase action registry differs from approval")
        plan = self.lifecycle._get_plan(conn, application_id, plan_id)
        program = self._get_program(conn, application_id, row[1])
        if plan.fingerprint != row[0]:
            raise ContractError("Stored phase plan digest mismatch")
        database_now = conn.execute("SELECT clock_timestamp()").fetchone()[0]
        binding = self._compile(program, MigrationPhase(row[2]), plan, action_registry)
        binding.execution_gate(plan, database_now)
        return binding
