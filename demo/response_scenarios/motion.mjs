// Presentation only: logical placement and transitions never issue an operation.
export function motionPlan(session, view) {
  const positions = Object.fromEntries(
    view.nodes.map((n) => [n.id, { x: n.x, y: n.y }]),
  );
  const quarantine = ["segment", "isolate"].includes(session.scenario);
  const moving = view.operating && quarantine;
  const isolated =
    session.scenario === "segment" ? ["api", "worker"] : ["worker"];
  if (moving) {
    for (const [i, id] of isolated.entries()) {
      positions[id] = {
        x: isolated.length === 1 ? 650 : 550 + i * 240,
        y: 860,
      };
    }
  }
  const transfers = [],
    entering = [];
  let caption = "구성 요소를 선택해 연결과 대응 범위를 확인하세요.";
  const transfer = (id, from, to, label, tone = "blue") =>
    transfers.push({
      id,
      from,
      to,
      label,
      tone,
      englishLabel: {
        image: "Deploy Image",
        credential: "Refresh Credentials",
        replica: "Add Worker Replica",
        api: "Deploy API",
        worker: "Deploy Worker",
        data: "Synchronize Data",
      }[id],
    });
  if (session.phase === "executing") {
    if (moving) caption = "선택한 구성 요소를 논리적 격리 영역으로 분리합니다.";
    if (session.scenario === "egress")
      caption = "외부 연결을 끊고 내부 업무 연결은 유지합니다.";
    if (["patch", "rollback"].includes(session.scenario)) {
      transfer(
        "image",
        "api",
        "standby",
        session.scenario === "patch" ? "수정 이미지 배치" : "이전 이미지 배치",
      );
      entering.push("standby");
      caption = "기존 실행본을 보존하고 대체 실행본을 준비합니다.";
    }
    if (session.scenario === "credentials") {
      transfer("credential", "vault", "api", "새 자격 연결", "purple");
      caption = "새 자격으로 연결한 뒤 이전 자격의 폐기를 확인합니다.";
    }
    if (session.scenario === "restart") {
      entering.push("worker");
      caption = "같은 환경에서 작업자 실행본을 교체합니다.";
    }
    if (session.scenario === "scale") {
      transfer("replica", "worker", "extra", "작업자 복제본 추가");
      entering.push("extra");
      caption = "작업자 복제본을 추가하고 작업을 분산할 준비를 합니다.";
    }
    if (session.scenario === "migrate") {
      transfer("api", "api", "target-api", "앱 실행본 배치");
      transfer("worker", "worker", "target-worker", "작업자 배치");
      transfer("data", "db", "target-db", "데이터 동기화", "green");
      entering.push("target-api", "target-worker", "target-db");
      caption = "앱 배치와 데이터 동기화를 나누어 목적지를 준비합니다.";
    }
  }
  if (session.phase === "verifying")
    caption = "대응 결과를 확인합니다. 경로 전환은 검증 통과 뒤에 진행합니다.";
  if (session.phase === "complete") {
    caption = quarantine
      ? "선택 구간은 격리 상태를 유지하며 주변 자원은 원래 위치에 남습니다."
      : session.scenario === "migrate"
        ? "목적지로 업무 경로를 전환하고 출발지 실행본은 보존합니다."
        : "대응 후 연결 경로와 실행본 상태를 확인합니다.";
  }
  if (session.phase === "held")
    caption =
      "결과 확인이 필요합니다. 이동·배치 표시는 성공 판정을 대신하지 않습니다.";
  if (session.recovery) {
    caption = {
      recovery_checking:
        "원본을 재검증합니다. 아직 격리나 연결 차단을 해제하지 않습니다.",
      recovery_restoring:
        "재검증한 구성 요소만 원래 위치로 돌려보내고 연결을 확인합니다.",
      recovered:
        "원본 업무 연결을 복구했습니다. 사고 보류와 대응 이력은 유지합니다.",
      recovery_held:
        "복귀 조건을 확인하지 못했습니다. 격리와 기존 경로를 유지합니다.",
    }[session.recovery.phase];
  }
  return {
    positions,
    transfers,
    entering,
    caption,
    quarantine,
    moving,
    isolated,
    height: quarantine ? 1040 : 800,
    executionAuthority: false,
  };
}

export function createMotionClock(
  onFrame,
  {
    now = () => performance.now(),
    request = (fn) => requestAnimationFrame(fn),
    cancel = (id) => cancelAnimationFrame(id),
  } = {},
) {
  let handle = null,
    active = null,
    positions = {},
    key = null,
    progress = 1,
    paused = false;
  const copy = (value) =>
    Object.fromEntries(Object.entries(value).map(([id, p]) => [id, { ...p }]));
  const frame = () => ({
    positions: copy(positions),
    progress,
    state: active ? (paused ? "paused" : "moving") : "settled",
  });
  const publish = () => onFrame(frame());
  function unschedule() {
    if (handle !== null) cancel(handle);
    handle = null;
  }
  function update() {
    if (!active || paused) return;
    const elapsed = Math.max(0, active.elapsed + now() - active.started);
    progress = Math.min(1, elapsed / active.duration);
    const eased =
      progress < 0.5 ? 4 * progress ** 3 : 1 - (-2 * progress + 2) ** 3 / 2;
    positions = Object.fromEntries(
      Object.entries(active.to).map(([id, end]) => {
        const start = active.from[id] || end;
        return [
          id,
          {
            x: start.x + (end.x - start.x) * eased,
            y: start.y + (end.y - start.y) * eased,
          },
        ];
      }),
    );
    if (progress >= 1) active = null;
  }
  function tick() {
    handle = null;
    update();
    publish();
    if (active && !paused) handle = request(tick);
  }
  return {
    transition(to, { identity, duration = 1400, immediate = false } = {}) {
      if (identity === key) {
        publish();
        return;
      }
      update();
      unschedule();
      const empty = Object.keys(positions).length === 0;
      const wasPaused = paused;
      key = identity;
      progress = 0;
      active = {
        from: copy(positions),
        to: copy(to),
        started: now(),
        elapsed: 0,
        duration: Math.max(1, duration),
      };
      if (immediate || empty) {
        positions = copy(to);
        progress = 1;
        active = null;
      }
      paused = wasPaused;
      publish();
      if (active && !paused) handle = request(tick);
    },
    pause() {
      update();
      if (active && !paused)
        active.elapsed += Math.max(0, now() - active.started);
      paused = true;
      unschedule();
      publish();
    },
    resume() {
      if (!paused) return;
      paused = false;
      if (active) {
        active.started = now();
        handle = request(tick);
      }
      publish();
    },
    finish() {
      if (active) positions = copy(active.to);
      unschedule();
      active = null;
      progress = 1;
      publish();
    },
    clear() {
      unschedule();
      active = null;
      positions = {};
      key = null;
      progress = 1;
      paused = false;
    },
    read: frame,
  };
}
