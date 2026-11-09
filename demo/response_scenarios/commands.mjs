// Fixed browser commands, not a shell or an execution adapter.
import {
  definition,
  recoveryAvailable,
  currentPhase,
  advance,
  requestRecovery,
  createSession,
} from "./model.mjs";

const SIGNALS = {
  isolate: "access-violation",
  segment: "lateral-movement",
  egress: "suspicious-egress",
  credentials: "credential-exposure",
  patch: "vulnerable-image",
  restart: "worker-timeout",
  scale: "queue-pressure",
  migrate: "placement-change",
  rollback: "release-regression",
};
export function injectionCommand(id) {
  const spec = definition(id);
  return `inject ${SIGNALS[id]} --target ${spec.targets.join(",")}`;
}
// Each suggestion must be explicitly submitted; there is no playback scheduler.
export function nextCommand(session) {
  const phase = currentPhase(session);
  if (phase === "normal") return injectionCommand(session.scenario);
  if (recoveryAvailable(session)) return "recovery start";
  return (
    {
      detected: "response plan",
      planned: "response submit",
      awaiting_approval: "response approve",
      executing: "response verify",
      verifying: "response finalize",
      recovery_checking: "recovery verify",
      recovery_restoring: "recovery finalize",
      held: "incident inspect",
      recovery_held: "incident inspect",
    }[phase] || "workload status"
  );
}
const ACTIONS = {
  "response plan": ["plan", "detected"],
  "response submit": ["submit", "planned"],
  "response verify": ["verify", "executing"],
  "response finalize": ["finalize", "verifying"],
  "recovery verify": ["recovery_verify", "recovery_checking"],
  "recovery finalize": ["recovery_finalize", "recovery_restoring"],
};
export function executeCommand(session, raw, options = {}) {
  const command = parseCommand(raw, session);
  if (command.kind === "error") return { command, session };
  if (command.kind === "recover")
    return {
      command,
      session: requestRecovery(session, {
        outcome: options.recoveryOutcome ?? "pass",
      }),
    };
  if (command.kind === "reset")
    return {
      command,
      session: createSession(session.scenario, {
        outcome: options.outcome ?? session.outcome,
        preapproved: session.preapproved,
      }),
    };
  if (
    [
      "inject",
      "plan",
      "submit",
      "approve",
      "verify",
      "finalize",
      "recovery_verify",
      "recovery_finalize",
    ].includes(command.kind)
  )
    return {
      command,
      session: advance(session, { approve: command.kind === "approve" }),
    };
  return { command, session };
}
export function parseCommand(raw, session) {
  if (typeof raw !== "string" || raw.length > 256 || /[\r\n\u0000]/.test(raw))
    return { kind: "error", message: "명령은 256자 이내로 입력해 주세요." };
  const tokens = raw.trim().split(/\s+/);
  if (tokens.length === 1 && ["help", "status", "clear"].includes(tokens[0]))
    return { kind: tokens[0] };
  const name = tokens.join(" ");
  const readOnly = {
    "workload status": "workload_status",
    "incident inspect": "incident_inspect",
    "response watch": "watch",
  };
  if (Object.hasOwn(readOnly, name)) return { kind: readOnly[name] };
  if (name === "response approve") {
    return session.phase === "awaiting_approval" &&
      !session.approved &&
      !session.recovery
      ? { kind: "approve" }
      : {
          kind: "error",
          message: "현재 선택한 대응이 승인 대기일 때만 승인할 수 있습니다.",
        };
  }
  if (Object.hasOwn(ACTIONS, name)) {
    const [kind, phase] = ACTIONS[name];
    return currentPhase(session) === phase
      ? { kind }
      : {
          kind: "error",
          message: `현재 단계에서는 실행할 수 없습니다. 다음 명령: ${nextCommand(session)}`,
        };
  }
  if (name === "response reset") return { kind: "reset" };
  if (name === "recovery start")
    return recoveryAvailable(session)
      ? { kind: "recover" }
      : {
          kind: "error",
          message:
            "격리 대응이 끝난 뒤 원본 재검증·복귀를 요청할 수 있습니다. DB·이미지·자격증명 복구는 별도 절차가 필요하며, 중복 복귀는 허용하지 않습니다.",
        };
  const spec = definition(session.scenario);
  if (
    tokens.length !== 4 ||
    tokens[0] !== "inject" ||
    tokens[2] !== "--target" ||
    !/^[a-z-]+$/.test(tokens[1]) ||
    !/^[a-z,-]+$/.test(tokens[3])
  ) {
    return {
      kind: "error",
      message:
        "지원하지 않는 명령 또는 인자입니다. help로 조회·주입·대응·복귀 명령을 확인해 주세요.",
    };
  }
  const targets = tokens[3].split(",");
  if (
    tokens[1] !== SIGNALS[spec.id] ||
    targets.length !== spec.targets.length ||
    new Set(targets).size !== targets.length ||
    targets.some((id) => !spec.targets.includes(id))
  ) {
    return {
      kind: "error",
      message: "선택한 대응 유형의 이벤트·대상 범위와 일치하지 않습니다.",
    };
  }
  if (session.phase !== "normal")
    return {
      kind: "error",
      message: "이미 시작한 대응입니다. 새로 주입하려면 먼저 초기화해 주세요.",
    };
  return { kind: "inject", scenario: spec.id, event: tokens[1], targets };
}
