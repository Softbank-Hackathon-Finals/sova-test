// Fixed browser commands, not a shell or an execution adapter.
import {
  definition,
  isTerminal,
  recoveryAvailable,
  currentPhase,
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
// Suggestions only: the caller must still submit and pass parseCommand.
export function nextCommand(session, { playing = true } = {}) {
  const phase = currentPhase(session);
  if (phase === "normal") return injectionCommand(session.scenario);
  if (phase === "awaiting_approval" && !session.preapproved)
    return "response approve";
  if (recoveryAvailable(session)) return "recovery start";
  if (["held", "recovery_held"].includes(phase)) return "incident inspect";
  if (isTerminal(session)) return "workload status";
  if (!playing) return "response resume";
  if (["detected", "planned"].includes(phase)) return "incident inspect";
  return "response watch";
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
  if (["response pause", "response resume"].includes(name)) {
    if (isTerminal(session) || session.phase === "normal")
      return {
        kind: "error",
        message:
          "진행 중인 대응이 없습니다. 상태를 조회하거나 이상을 먼저 주입해 주세요.",
      };
    if (
      name === "response resume" &&
      session.phase === "awaiting_approval" &&
      !session.preapproved
    )
      return {
        kind: "error",
        message:
          "승인이 필요합니다. response approve로 선택한 범위를 확인해 주세요.",
      };
    return { kind: name.endsWith("pause") ? "pause" : "resume" };
  }
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
