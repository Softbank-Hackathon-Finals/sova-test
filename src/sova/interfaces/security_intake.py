"""Mac offline intake; existing private-file reader, no cloud subprocesses."""

import json
import os

from sova_security.application.acceptance_intake import intake_plan
from sova_security.contracts.commands import ContractError


def add_commands(commands):
    command = commands.add_parser("security-intake-plan",
        help="Offline T14/T33 full-profile intake list; never authenticates evidence or authorizes execution")
    command.add_argument("--control-run", action="append", default=[],
        help="Private T14 ControlRun JSON; at most one source and one target")
    command.add_argument("--source-status", action="append", default=[],
        help="Private current T33 SourceStatus JSON; no raw provider finding")


def run(args, now):
    from sova.adapters.kubernetes.https import private_text
    if len(args.control_run) > 2 or len(args.source_status) > 32:
        raise ContractError("Bounded offline intake required")
    if args.control_run or args.source_status:
        if not all(hasattr(os, name) for name in ("O_NOFOLLOW", "geteuid")):
            raise ContractError("Private intake files require the Mac/Linux owner-checked reader")
    def read(path):
        return private_text(path, limit=2 * 1024 * 1024).encode("utf-8")
    try:
        result = intake_plan(now=now, control_runs=tuple(read(p) for p in args.control_run),
            source_statuses=tuple(read(p) for p in args.source_status))
    except ModuleNotFoundError:
        raise ContractError("Install the security team extra for schema-based intake") from None
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
