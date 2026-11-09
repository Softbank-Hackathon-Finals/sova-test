// Fixed browser commands, not a shell or an execution adapter.
import { definition } from "./model.mjs";

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
export function parseCommand(raw, session) {
  if (typeof raw !== "string" || raw.length > 256)
    return { kind: "error", message: "명령은 256자 이내로 입력해 주세요." };
  const tokens = raw.trim().split(/\s+/);
  if (tokens.length === 1 && ["help", "status", "clear"].includes(tokens[0]))
    return { kind: tokens[0] };
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
        "지원하는 명령은 inject, help, status, clear입니다. 현재 유형의 주입 명령을 확인해 주세요.",
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
