"""T28 subprocess port backed by the existing effect executor and journal.

Server composition supplies registered commands, live authority and readback
adapters. No shell execution, permit issuer, approval or recovery shortcut is
provided here. JSONL is descriptive; it is never the execution authority.
"""

from dataclasses import dataclass
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

from sova.application.effects import EffectExecutor
from sova.domain.contracts import ContractError, EffectCommand, EffectStatus, ExecutionPermit
from sova.ports.effects import EffectAdapter

PLATFORM_COMMIT = "0795f65e24f58e43545b16b97757efcc0923fd4a"
DRIVER_HASHES = {
    "42811da4cf19ce941491d4794ab49790881dc409": "edac61dcc4ec0f0bf26e5e7583f33fb3137c544836d9d1c6441453724210d14c",
    PLATFORM_COMMIT: "e4bc607112512361d4bde4c6022bc59eb21191fdc139ade77b52f50bb013a355",
}


def load_driver(root):
    """Import only the reviewed source from a clean, pinned platform checkout."""
    root = Path(root).resolve(strict=True)
    git = ["git", "-c", f"safe.directory={root.as_posix()}", "-C", str(root)]
    commit = subprocess.check_output(git + ["rev-parse", "HEAD"], timeout=10).decode().strip()
    if commit not in DRIVER_HASHES:
        raise ContractError("Unqualified T28 platform commit")
    if subprocess.check_output(git + ["status", "--porcelain", "--untracked-files=normal"], timeout=10):
        raise ContractError("T28 source must be clean")
    path = root / "scripts/happy_path.py"
    if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != DRIVER_HASHES[commit]:
        raise ContractError("T28 source differs from the reviewed driver")
    spec = importlib.util.spec_from_file_location("sova_pinned_t28", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.__sova_platform_commit__ = commit
    return module


@dataclass(frozen=True)
class OperatorBinding:
    command: EffectCommand
    permit: ExecutionPermit
    adapter: EffectAdapter


class DurableT28Port:
    """Pass this object as cmd_run(run=...). Unregistered argv fail closed.

    The command's canonical parameters bind the exact argv, plan, application,
    diff and image. Its fingerprint already covers revision and fencing epoch.
    Effects use the original journal CAS and resource conflict barrier. A new
    JSONL path, lost stdout or restart cannot reset the durable effect record.
    """

    def __init__(self, root, plan_id, application_id, bindings, executor: EffectExecutor):
        self.root = Path(root).resolve(strict=True)
        self.plan_id, self.application_id = plan_id, application_id
        if type(bindings) is not tuple or not bindings:
            raise ContractError("Immutable server-registered operator bindings required")
        self.bindings, self.executor = bindings, executor
        self.platform_commit = bindings[0].command.parameters.get("platform_commit")
        if self.platform_commit not in DRIVER_HASHES:
            raise ContractError("Unqualified T28 operator source")
        seen = set()
        for binding in bindings:
            command = binding.command
            value = command.parameters
            if command.action != "t28_operator" or set(value) != {
                "argv", "platform_commit", "plan_id", "application_id", "diff_digest", "image_digest", "profile"
            }:
                raise ContractError("Exact T28 operator contract required")
            argv = value["argv"]
            if (type(argv) is not list or not argv or len(argv) > 64
                    or any(type(v) is not str or not v or len(v) > 4096 or "\x00" in v for v in argv)
                    or value["platform_commit"] != self.platform_commit
                    or value["plan_id"] != plan_id or value["application_id"] != application_id
                    or value["profile"] not in {"real", "local", "mock"}
                    or not re.fullmatch(r"[0-9a-f]{64}", value["diff_digest"])
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", value["image_digest"])):
                raise ContractError("T28 invocation differs from its registered plan artifacts")
            key = tuple(argv)
            if key in seen:
                raise ContractError("Ambiguous T28 operator registration")
            seen.add(key)

    def __call__(self, argv, *, cwd, capture_output, text, timeout, check):
        if (Path(cwd).resolve() != self.root or capture_output is not True or text is not True
                or check is not False or type(timeout) is not int or not 1 <= timeout <= 900):
            raise ContractError("Unexpected T28 invocation options")
        matches = [b for b in self.bindings if b.command.parameters["argv"] == argv]
        if len(matches) != 1:
            raise ContractError("T28 operator is not registered")
        binding = matches[0]
        record = self.executor.execute(binding.command, binding.permit, binding.adapter)
        if record.status != EffectStatus.APPLIED:
            raise ContractError("T28 operator has no confirmed effect receipt")
        # Historical receipt is deliberately labelled, never fresh health.
        output = json.dumps({"effect_receipt": binding.command.fingerprint,
                             "status": str(record.status), "fresh_health": False})
        return subprocess.CompletedProcess(argv, 0, output, "")

    def run(self, driver, args, *, read_state=None):
        if (Path(driver.ROOT).resolve() != self.root or args.plan_id != self.plan_id
                or getattr(driver, "__sova_platform_commit__", None) != self.platform_commit
                or (args.application_id or "") != self.application_id
                or any(b.command.parameters["profile"] != args.profile for b in self.bindings)):
            raise ContractError("T28 run identity differs from the registered operation")
        # Original T28 accepts a subprocess pretending to be a read-only reader.
        # It would bypass the operator port. Only a host-owned reader callback is
        # accepted here; a CLI command is never a read-only capability.
        if args.plan_state_command is not None or getattr(args, "platform_context", None) is not None:
            raise ContractError("Use the host-owned T10 reader, not a subprocess command")
        # A forged/old JSONL completion cannot bypass the durable receipt.
        head, outcomes = driver.read_record(Path(args.record))
        if head is not None and (head.get("plan_id") != self.plan_id or head.get("profile") != args.profile
                                 or head.get("develop_sha") != self.platform_commit):
            raise ContractError("T28 record belongs to a different plan/profile/platform")
        values = {"kubeconfig": args.kubeconfig or "", "fault_record": args.fault_record,
                  "application_id": args.application_id or "", "receipts": args.receipts or ""}
        steps = {step.id: step for step in driver.STEPS}
        for binding in self.bindings:
            step = steps.get(binding.command.step_id)
            if step is None or step.kind != "operator" or step.command is None:
                raise ContractError("Registered T28 step differs from the driver invocation")
            expected = [part.format(**values) for part in step.command]
            initial = getattr(driver, "INITIAL", ())
            if initial and step.command[:len(initial)] == initial:
                extra = getattr(args, "initial_args", None)
                if type(extra) is not list or not extra:
                    raise ContractError("Registered initial-proposal arguments required")
                expected += extra
            if expected != binding.command.parameters["argv"]:
                raise ContractError("Registered T28 step differs from the driver invocation")
        for step in driver.STEPS:
            if step.kind == "operator" and outcomes.get(step.id, {}).get("status") in {"done", "human_confirmed"}:
                matches = [b for b in self.bindings if b.command.step_id == step.id]
                if len(matches) != 1 or self.executor.journal.get(matches[0].command).status != EffectStatus.APPLIED:
                    raise ContractError("JSONL completion is not backed by the execution journal")
        return driver.cmd_run(args, run=self, read_state=read_state)
