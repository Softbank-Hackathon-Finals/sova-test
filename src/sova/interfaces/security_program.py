"""Offline diagnostics for the package contract; no production authority."""

from dataclasses import asdict
from datetime import timedelta
import json

from sova_security.adapters.graph_codec import read_document
from sova_security.adapters.modernization_codec import decode, encode
from sova_security.contracts.commands import ContractError, ResourceScope
from sova_security.contracts.evidence import Gate, RevisionSet, VerificationObligation
from sova_security.domain.security_program import (
    CHECKS,
    ProgramBinding,
    ProgramInput,
    ProgramKind,
    ProgramPhase,
    SecurityProgram,
    checks_for,
    obligation_id,
    review_program,
)


def example_program(kind, now):
    """Synthetic empty evidence: examples must never start as a green dashboard."""
    source = ResourceScope(
        "example-tenant", "example-app", "example-source", "example-workload"
    )
    target = ResourceScope(
        "example-tenant", "example-app", "example-target", "example-workload"
    )
    subject = "a" * 64
    revisions = RevisionSet("b" * 64, "c" * 64, "d" * 64, "e" * 64)
    bindings = tuple(
        ProgramBinding(
            check.check_id,
            VerificationObligation(
                obligation_id(subject, check.check_id),
                source if check.role == "source" else target,
                Gate.PREFLIGHT
                if check.phase == ProgramPhase.PREFLIGHT
                else Gate.POSTFLIGHT,
                "example-only:" + check.check_id,
            ),
            revisions,
        )
        for check in checks_for(kind)
    )
    return ProgramInput(
        SecurityProgram(
            kind, subject, source, target, bindings, now, now + timedelta(hours=1)
        ),
        (),
    )


def add_commands(commands):
    commands.add_parser(
        "security-program-catalog", help="Show architecture requirement/check mappings"
    )
    example = commands.add_parser(
        "security-program-example", help="Synthetic program with no passing evidence"
    )
    example.add_argument(
        "--kind", choices=[v.value for v in ProgramKind], default="migration"
    )
    check = commands.add_parser(
        "security-program-check",
        help="Offline diagnostic only; no signature authentication or execution",
    )
    check.add_argument("input")
    check.add_argument(
        "--phase", choices=[v.value for v in ProgramPhase], default="preflight"
    )


def run(args, now):
    if args.command == "security-program-catalog":
        print(
            json.dumps(
                {
                    "catalog_version": "security-modernization.v1",
                    "checks": [asdict(c) for c in CHECKS],
                },
                indent=2,
            )
        )
        return 0
    if args.command == "security-program-example":
        print(encode(example_program(ProgramKind(args.kind), now)))
        return 0
    body = read_document(args.input, limit=1048576)
    value = decode(json.dumps(body).encode())
    if not isinstance(value, ProgramInput):
        raise ContractError("Security program input envelope required")
    review = review_program(
        value.program, ProgramPhase(args.phase), value.evidence, now=now
    )
    print(
        json.dumps(
            {
                "mode": "offline-diagnostic",
                "authenticated": False,
                "execution_authorized": False,
                "checks_passed": review.passed,
                "review": review.document,
            },
            indent=2,
        )
    )
    return 0 if review.passed else 1
