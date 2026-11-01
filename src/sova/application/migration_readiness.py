"""Trusted boundary for six-area assessments, separate from execution approval."""

from sova.domain.contracts import ContractError, utc
from sova.domain.migration_program import MigrationProgram
from sova.domain.evidence import EvidenceRecord


class MigrationReadinessService:
    def __init__(
        self,
        *,
        program_provider,
        evidence_provider,
        authorize,
        authenticate_program,
        authenticate_evidence,
        clock,
    ):
        self.program_provider = program_provider
        self.evidence_provider = evidence_provider
        self.authorize = authorize
        self.authenticate_program = authenticate_program
        self.authenticate_evidence = authenticate_evidence
        self.clock = clock

    def assess(self, actor, scope, gate):
        self.authorize(actor, scope, "migration:assess")
        program = self.program_provider(scope)
        self.authenticate_program(program)
        if not isinstance(program, MigrationProgram):
            raise ContractError("Typed migration program required")
        if not program.issued_at <= utc(self.clock()) < program.valid_until:
            raise ContractError("Program expired or from future")
        if scope not in (program.source_scope, program.target_scope):
            raise ContractError("Assessment scope differs from registered program")
        for endpoint in (program.source_scope, program.target_scope):
            self.authorize(actor, endpoint, "migration:assess")
        evidence = self.evidence_provider(program)
        if (
            type(evidence) is not tuple
            or len(evidence) > 4096
            or any(not isinstance(e, EvidenceRecord) for e in evidence)
        ):
            raise ContractError("Immutable evidence snapshot required")
        for record in evidence:
            self.authenticate_evidence(record)
        return program.assess(evidence, gate, now=self.clock())
