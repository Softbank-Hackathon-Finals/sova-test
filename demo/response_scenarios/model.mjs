// Browser-only scenarios. No provider, credentials, requests or execution port.
export const PHASES = [
  "normal",
  "detected",
  "planned",
  "awaiting_approval",
  "executing",
  "verifying",
  "complete",
];
export const PHASE_LABELS = {
  normal: "정상 흐름",
  detected: "이상 주입",
  planned: "영향·계획 확인",
  awaiting_approval: "승인 대기",
  executing: "대응 진행",
  verifying: "결과 확인",
  complete: "대응 완료",
  held: "보류 · 전환 중지",
  recovery_checking: "원본 재검증 · 격리 유지",
  recovery_restoring: "원본 복귀 진행",
  recovered: "원본 복귀 확인",
  recovery_held: "복구 보류 · 격리 유지",
};
export const HEALTH_LABELS = {
  healthy: "정상",
  warning: "영향 가능",
  compromised: "문제 발생",
  isolated: "격리",
  draining: "연결 정리",
  preparing: "준비 중",
  standby: "대기",
  replaced: "교체됨",
  unknown: "결과 미확인",
  patched: "수정본",
};
const SCENARIO_ENGLISH = {
  isolate: "Component Isolation",
  segment: "Segment Isolation",
  egress: "Outbound Traffic Blocking",
  credentials: "Credential Rotation",
  patch: "Verified Patch Rollout",
  restart: "Workload Restart",
  scale: "Horizontal Scaling",
  migrate: "AWS to On-Premises Migration",
  rollback: "Deployment Rollback",
};
const scenario = (
  id,
  title,
  group,
  summary,
  signal,
  targets,
  action,
  verify,
  result,
  policy = false,
) => ({
  id,
  title,
  englishTitle: SCENARIO_ENGLISH[id],
  group,
  summary,
  signal,
  targets,
  action,
  verify,
  result,
  policy,
});
export const SCENARIOS = [
  scenario(
    "isolate",
    "구성 요소 격리",
    "보안 대응",
    "문제 작업자 하나의 통신만 끊고 나머지 기능은 유지합니다.",
    "작업자의 허용되지 않은 내부 접근을 감지한 상황",
    ["worker"],
    "선택 작업자의 수신·발신 차단 → 진행 중 연결 종료",
    "작업자 통신 차단 / API·첨부 경로 유지",
    "작업자는 격리하고 작업 큐는 대기합니다. 사고 보류는 유지합니다.",
    true,
  ),
  scenario(
    "segment",
    "연관 구간 부분 격리",
    "보안 대응",
    "API와 작업자를 함께 격리하고 인증·저장소는 보존합니다.",
    "API와 작업자에 연관된 침해 징후가 있는 상황",
    ["api", "worker"],
    "API·작업자 구간 차단 → 신규 유입 중단 → 연결 종료",
    "선택 구간 차단 / 주변 자원 상태 확인",
    "선택 구간의 서비스는 중단됩니다. 정상 표시된 주변 자원을 안전하다고 확정하는 뜻은 아닙니다.",
    true,
  ),
  scenario(
    "egress",
    "외부 통신 차단",
    "보안 대응",
    "의심스러운 외부 목적지만 차단하고 내부 업무 연결은 유지합니다.",
    "작업자가 허용되지 않은 외부 주소로 데이터를 보내려는 상황",
    ["worker"],
    "의심 외부 목적지 차단 → 기존 외부 연결 종료",
    "외부 전송 거부 / 내부 DB·큐 연결 유지",
    "외부 목적지 통신만 차단합니다. 작업자는 조사 대상으로 남습니다.",
    true,
  ),
  scenario(
    "credentials",
    "자격증명 회전",
    "보안 대응",
    "노출 의심 자격을 폐기하고 새 자격으로 앱을 다시 연결합니다.",
    "앱이 사용하던 Secret의 노출이 의심되는 상황",
    ["vault", "api"],
    "새 자격 준비 → 앱 재연결 → 이전 자격 폐기",
    "새 자격 허용 / 이전 자격 거부 / 업무 응답",
    "새 자격 연결을 확인합니다. 자격 교체만으로 침해 종료를 선언하지 않습니다.",
  ),
  scenario(
    "patch",
    "패치·검증 후 교체",
    "지속 보안 개선",
    "수정안을 샌드박스에서 시험한 뒤 새 이미지로 교체합니다.",
    "API 이미지에서 수정 가능한 취약점이 발견된 상황",
    ["api"],
    "수정안 → 샌드박스 시험 → 이미지 검사 → 대체본 준비",
    "취약점 재시험 / 기능 회귀 / 실행 이미지 일치",
    "검증을 통과한 대체 API로 전환합니다. 기존 API와 사고 이력은 보존합니다.",
  ),
  scenario(
    "restart",
    "장애 프로세스 재기동",
    "가용성 대응",
    "응답이 없는 작업자만 종료하고 같은 환경에서 새 실행본을 띄웁니다.",
    "작업자가 응답하지 않아 큐 적체가 생기는 상황",
    ["worker"],
    "신규 작업 중단 → 기존 연결 정리 → 작업자 재생성",
    "새 실행본 응답 / 중복 처리 방지 / 큐 재개",
    "같은 AWS 환경에서 작업자 실행본만 바뀝니다. DB나 앱 전체를 이전하지 않습니다.",
  ),
  scenario(
    "scale",
    "부하 분산·수평 확장",
    "가용성 대응",
    "작업자 복제본을 추가하고 대기 중인 작업을 분산합니다.",
    "큐 대기와 작업자 부하가 기준을 넘는 상황",
    ["worker", "queue"],
    "허용 복제본·예산 확인 → 작업자 추가 → 작업 분산",
    "새 실행본 준비 / 큐 대기 감소 / 오류율",
    "추가 작업자로 부하를 분산합니다.",
    true,
  ),
  scenario(
    "migrate",
    "AWS → 온프렘 이전",
    "환경 전환",
    "앱 준비와 DB 동기화를 나누고 단일 writer를 유지하며 전환합니다.",
    "AWS 환경을 떠나야 하는 정책 변경이 발생한 상황",
    ["api", "worker", "db"],
    "목적지 준비·DB 동기화 → 출발지 writer 차단 → 최종 비교",
    "최종 데이터 비교 / 목적지 writer 활성화 / 경로 확인",
    "검증 통과 뒤 온프렘 writer와 트래픽을 활성화합니다. 출발지 자원은 복구를 위해 보존합니다.",
  ),
  scenario(
    "rollback",
    "배포 롤백",
    "복구 대응",
    "새 배포에서 오류가 발생하면 검증한 이전 이미지로 복구합니다.",
    "새 API 배포 후 기능 오류율이 증가한 상황",
    ["api"],
    "신규 배포 보류 → 이전 이미지 재기동 → 호환성 검사",
    "이전 이미지·설정·현재 DB 스키마 호환 확인",
    "호환성 확인 뒤 이전 이미지로 복귀합니다. DB를 과거 시점으로 되돌리지 않습니다.",
  ),
];
const NODE_ENGLISH = {
  edge: "Fixed Entry Point",
  external: "External Endpoint",
  auth: "Authentication Service",
  api: "Application API",
  standby: "Standby API",
  vault: "Secrets Store",
  queue: "Task Queue",
  worker: "Background Worker",
  extra: "Additional Worker",
  objects: "Object Storage",
  db: "Source Database",
  "target-api": "Target API",
  "target-worker": "Target Worker",
  "target-db": "Target Database",
};
export const NODES = [
  {
    id: "edge",
    label: "고정 진입점",
    subtitle: "사용자 요청",
    kind: "entry",
    x: 30,
    y: 300,
  },
  {
    id: "external",
    label: "외부 목적지",
    subtitle: "허용 여부 점검",
    kind: "external",
    x: 30,
    y: 610,
  },
  {
    id: "auth",
    label: "인증 서비스",
    subtitle: "사용자 신원",
    kind: "service",
    x: 280,
    y: 120,
  },
  {
    id: "api",
    label: "업무 API",
    subtitle: "AWS · image v1",
    kind: "app",
    x: 520,
    y: 300,
  },
  {
    id: "standby",
    label: "대체 API",
    subtitle: "AWS · 대기 이미지",
    kind: "app",
    x: 790,
    y: 300,
  },
  {
    id: "vault",
    label: "Secret 저장소",
    subtitle: "앱 자격 v1",
    kind: "secret",
    x: 790,
    y: 120,
  },
  {
    id: "queue",
    label: "작업 큐",
    subtitle: "비동기 요청",
    kind: "queue",
    x: 280,
    y: 475,
  },
  {
    id: "worker",
    label: "비동기 작업자",
    subtitle: "AWS · 실행본 1",
    kind: "worker",
    x: 520,
    y: 475,
  },
  {
    id: "extra",
    label: "추가 작업자",
    subtitle: "AWS · 미기동",
    kind: "worker",
    x: 790,
    y: 475,
  },
  {
    id: "objects",
    label: "첨부 저장소",
    subtitle: "객체 데이터",
    kind: "storage",
    x: 280,
    y: 655,
  },
  {
    id: "db",
    label: "출발지 DB",
    subtitle: "업무 데이터 · writer",
    kind: "database",
    x: 790,
    y: 655,
  },
  {
    id: "target-api",
    label: "목적지 API",
    subtitle: "온프렘 · 미기동",
    kind: "app",
    x: 1150,
    y: 300,
  },
  {
    id: "target-worker",
    label: "목적지 작업자",
    subtitle: "온프렘 · 미기동",
    kind: "worker",
    x: 1150,
    y: 475,
  },
  {
    id: "target-db",
    label: "목적지 DB",
    subtitle: "온프렘 · writer 없음",
    kind: "database",
    x: 1150,
    y: 655,
  },
].map((node) => ({ ...node, englishLabel: NODE_ENGLISH[node.id] }));
export const EDGES = [
  ["ingress", "edge", "api", "HTTP"],
  ["auth-api", "auth", "api", "인증"],
  ["secret-api", "vault", "api", "자격"],
  ["api-queue", "api", "queue", "작업"],
  ["queue-worker", "queue", "worker", "소비"],
  ["api-db", "api", "db", "SQL"],
  ["api-objects", "api", "objects", "첨부"],
  ["worker-db", "worker", "db", "SQL"],
  ["egress", "worker", "external", "외부 전송"],
  ["standby-route", "edge", "standby", "대체 경로"],
  ["standby-db", "standby", "db", "SQL"],
  ["extra-work", "queue", "extra", "작업 분산"],
  ["extra-db", "extra", "db", "SQL"],
  ["target-route", "edge", "target-api", "목적지 경로"],
  ["target-work", "target-api", "target-worker", "작업"],
  ["target-sql", "target-api", "target-db", "SQL"],
  ["target-worker-db", "target-worker", "target-db", "SQL"],
  ["replication", "db", "target-db", "DB 동기화"],
].map(([id, source, target, label]) => ({ id, source, target, label }));

export function definition(id) {
  const found = SCENARIOS.find((value) => value.id === id);
  if (!found) throw new Error("Unknown mock scenario");
  return found;
}
const event = (phase, message) => ({ phase, message, provenance: "mock" });
export function createSession(
  id = "segment",
  { preapproved = false, outcome = "pass" } = {},
) {
  const spec = definition(id);
  if (!["pass", "fail", "unknown"].includes(outcome))
    throw new Error("Unknown simulated outcome");
  return {
    scenario: id,
    phase: "normal",
    preapproved: Boolean(preapproved && spec.policy),
    outcome,
    approved: false,
    history: [event("normal", "앱 정상 상태로 초기화")],
    source: "mock",
    recovery: null,
  };
}
export function recoveryAvailable(session) {
  return (
    ["isolate", "segment"].includes(session.scenario) &&
    ["complete", "held"].includes(session.phase) &&
    !session.recovery
  );
}
export function requestRecovery(session) {
  if (!recoveryAvailable(session)) return session;
  return {
    ...session,
    recovery: { phase: "recovery_checking" },
    history: [
      ...session.history,
      event(
        "recovery_checking",
        "원본 복귀 요청 접수 · 선택 대상의 응답·접근 정책 재검증. 통과 전에는 격리를 유지합니다.",
      ),
    ],
  };
}
export function currentPhase(session) {
  return session.recovery?.phase || session.phase;
}
export function isTerminal(session) {
  return session.recovery
    ? ["recovered", "recovery_held"].includes(session.recovery.phase)
    : ["complete", "held"].includes(session.phase);
}
export function advance(session, { approve = false } = {}) {
  if (session.recovery) {
    const phase = session.recovery.phase;
    if (isTerminal(session)) return session;
    const next =
      phase === "recovery_checking"
        ? session.outcome === "pass"
          ? "recovery_restoring"
          : "recovery_held"
        : "recovered";
    const message =
      next === "recovery_restoring"
        ? "원본 재검증 통과 · 선택 구성 요소만 원래 위치로 복귀. 연결 확인 전에는 기존 차단을 유지합니다."
        : next === "recovered"
          ? "원본 응답·업무 연결 복귀 확인 · 사고 보류와 대응 이력은 유지합니다."
          : "원본 재검증 실패 또는 결과 불명확 · 격리·기존 경로 유지. 자동 재시도하지 않습니다.";
    return {
      ...session,
      recovery: { phase: next },
      history: [...session.history, event(next, message)],
    };
  }
  const spec = definition(session.scenario);
  if (session.phase === "held" || session.phase === "complete") return session;
  if (
    session.phase === "awaiting_approval" &&
    !session.approved &&
    !session.preapproved &&
    !approve
  )
    return session;
  const index = PHASES.indexOf(session.phase);
  const next = PHASES[index + 1];
  const approved =
    session.approved ||
    (session.phase === "awaiting_approval" && (approve || session.preapproved));
  if (["executing", "verifying", "complete"].includes(next) && !approved)
    return session;
  const held = session.phase === "verifying" && session.outcome !== "pass";
  const phase = held ? "held" : next;
  const message =
    phase === "detected"
      ? spec.signal
      : phase === "planned"
        ? spec.action
        : phase === "awaiting_approval"
          ? session.preapproved
            ? "정확한 시나리오 범위의 사전 승인 정책 적용"
            : "승인을 기다립니다. 시간 경과로 승인되지 않습니다."
          : phase === "executing"
            ? `승인 확인 · ${spec.action}`
            : phase === "verifying"
              ? spec.verify
              : phase === "held"
                ? session.outcome === "unknown"
                  ? "결과 미확인 → 보류. 경로·writer 전환을 확정하지 않음"
                  : "검증 실패 → 보류. 대체 경로 활성화 금지"
                : spec.result;
  return {
    ...session,
    phase,
    approved,
    history: [...session.history, event(phase, message)],
  };
}

export function snapshot(session) {
  if (session.recovery?.phase === "recovered") {
    const restored = snapshot({ ...session, phase: "normal", recovery: null });
    return {
      ...restored,
      detected: true,
      hold: true,
      availability: "원본 업무 복귀 확인 · 사고 보류 유지",
    };
  }
  const spec = definition(session.scenario);
  const detected = session.phase !== "normal";
  const operating = ["executing", "verifying", "complete", "held"].includes(
    session.phase,
  );
  const done = session.phase === "complete";
  const held = session.phase === "held";
  const nodes = NODES.map((node) => ({
    ...node,
    status:
      ["standby", "extra"].includes(node.id) || node.id.startsWith("target-")
        ? "standby"
        : "healthy",
    affected: false,
  }));
  const edges = EDGES.map((edge) => ({
    ...edge,
    state: [
      "ingress",
      "auth-api",
      "secret-api",
      "api-queue",
      "queue-worker",
      "api-db",
      "api-objects",
      "worker-db",
    ].includes(edge.id)
      ? "flow"
      : "idle",
  }));
  const node = (id, values) =>
    Object.assign(
      nodes.find((item) => item.id === id),
      values,
    );
  const edge = (id, state) => {
    edges.find((item) => item.id === id).state = state;
  };
  let writer = "출발지 DB",
    route = "AWS 업무 API",
    availability = "정상",
    hold = false;
  if (detected) {
    hold = true;
    for (const id of spec.targets)
      node(id, { status: "compromised", affected: true });
    for (const link of edges)
      if (
        spec.targets.includes(link.source) ||
        spec.targets.includes(link.target)
      ) {
        if (link.state === "flow") link.state = "warning";
        const other = spec.targets.includes(link.source)
          ? link.target
          : link.source;
        const neighbor = nodes.find((item) => item.id === other);
        if (neighbor.status === "healthy") neighbor.affected = true;
      }
    availability = "영향 확인 중";
    if (spec.id === "egress") {
      edge("egress", "warning");
      node("external", { affected: true });
    }
  }
  if (operating) {
    if (["isolate", "segment"].includes(spec.id)) {
      for (const id of spec.targets) node(id, { status: "isolated" });
      for (const link of edges)
        if (
          spec.targets.includes(link.source) ||
          spec.targets.includes(link.target)
        )
          link.state = "cut";
      availability =
        spec.id === "segment"
          ? "API·작업 처리 중단"
          : "API 유지 / 작업 큐 대기";
    } else if (spec.id === "egress") {
      edge("egress", "cut");
      node("worker", { status: "warning" });
      for (const id of ["queue-worker", "worker-db"]) edge(id, "flow");
      availability = "내부 업무 유지";
    } else if (spec.id === "credentials") {
      node("vault", {
        status: done ? "healthy" : "preparing",
        subtitle: done ? "새 자격 v2 · 이전 자격 폐기" : "새 자격 발급",
      });
      node("api", { status: done ? "healthy" : "draining" });
      edge("secret-api", done ? "flow" : "draining");
    } else if (["patch", "rollback"].includes(spec.id)) {
      node("api", { status: "draining", subtitle: "기존 실행본 보존" });
      node("standby", {
        status: done ? "patched" : held ? "unknown" : "preparing",
        subtitle:
          spec.id === "patch" ? "수정 이미지 v2" : "이전 검증 이미지 v0",
      });
      if (done) {
        edge("ingress", "cut");
        edge("standby-route", "flow");
        edge("standby-db", "flow");
        route = "AWS 대체 API";
      }
    } else if (spec.id === "restart") {
      node("worker", {
        status: done ? "healthy" : "draining",
        subtitle: done ? "AWS · 새 실행본 2" : "기존 실행본 종료",
      });
      edge("queue-worker", done ? "flow" : "draining");
      edge("worker-db", done ? "flow" : "cut");
    } else if (spec.id === "scale") {
      node("worker", { status: done ? "healthy" : "warning" });
      node("extra", {
        status: done ? "healthy" : held ? "unknown" : "preparing",
        subtitle: "AWS · 추가 실행본 2",
      });
      node("queue", { status: done ? "healthy" : "warning" });
      if (done) {
        edge("extra-work", "flow");
        edge("extra-db", "flow");
      }
    } else if (spec.id === "migrate") {
      for (const id of ["target-api", "target-worker", "target-db"])
        node(id, { status: done ? "healthy" : held ? "unknown" : "preparing" });
      node("db", {
        status: done ? "replaced" : "draining",
        subtitle: "출발지 writer 차단",
      });
      edge("replication", done ? "idle" : "sync");
      writer = done ? "목적지 DB" : "없음 · 출발지 차단, 목적지 대기";
      if (done) {
        for (const id of ["api", "worker"])
          node(id, { status: "replaced", subtitle: "출발지 보존" });
        for (const id of ["ingress", "api-db", "worker-db", "queue-worker"])
          edge(id, "cut");
        for (const id of [
          "target-route",
          "target-work",
          "target-sql",
          "target-worker-db",
        ])
          edge(id, "flow");
        node("target-db", { subtitle: "온프렘 · 단일 writer" });
        route = "온프렘 목적지 API";
      }
      availability = done ? "목적지 업무 재개" : "읽기 유지 / 쓰기 대기";
    }
  }
  if (held) {
    availability =
      session.outcome === "unknown" ? "상태 미확인 · 보류" : "검증 실패 · 보류";
    for (const id of spec.targets) node(id, { status: "unknown" });
    for (const link of edges) if (link.state === "cut") link.state = "unknown";
    if (spec.id === "migrate") writer = "미확인 · 양쪽 쓰기 보류";
  }
  if (done && !["isolate", "segment", "egress", "migrate"].includes(spec.id))
    availability = "대응 후 업무 확인";
  const returning = session.recovery?.phase === "recovery_restoring";
  if (returning) {
    for (const id of spec.targets)
      node(id, { status: "preparing", subtitle: "원본 복귀 · 연결 확인 대기" });
    availability = "원본 재검증 통과 · 재연결 중";
  }
  if (session.recovery?.phase === "recovery_held")
    availability = "복구 결과 미확인 · 격리 유지";
  return {
    source: "mock",
    nodes,
    edges,
    writer,
    route,
    availability,
    hold,
    detected,
    operating: returning ? false : operating,
    counters: {
      active: nodes.filter(
        (item) => !["standby", "isolated", "replaced"].includes(item.status),
      ).length,
      isolated: nodes.filter((item) => item.status === "isolated").length,
      cut: edges.filter((item) => item.state === "cut").length,
    },
    // An ordinary patch/restart never clears an incident or establishes real evidence.
    incidentReleased: false,
    executionAuthority: false,
  };
}
