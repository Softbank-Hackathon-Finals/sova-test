// Render only validated GET observations. This view never infers a DB writer,
// traffic weight, gate result or completed migration from Kubernetes readiness.
const node = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
};

export function migrationSnapshot(observation, now = Date.now()) {
  const graph = observation?.view;
  return ["source", "target"].map((lane) => {
    const env = observation?.environments?.find((e) => e.lane === lane);
    const age = now - Date.parse(env?.observed_at);
    const current = env?.status === "CURRENT" && age >= 0 && age < 90000;
    const nodes = (graph?.nodes ?? []).filter((n) => n.lane === lane);
    // column 0 is the existing collector's registered Service, 1 its Pod.
    // Never count containers or an unrelated Pod as another chat replica.
    const services = nodes.filter((n) => n.column === 0);
    return {
      lane,
      current,
      observedAt: env?.observed_at ?? null,
      services: services.map((service) => {
        const children = new Set(
          (graph?.edges ?? [])
            .filter(
              (e) => e.source === service.id && e.label === "Service selector",
            )
            .map((e) => e.target),
        );
        const pods = nodes.filter((n) => n.column === 1 && children.has(n.id));
        return {
          id: service.id,
          uid: service.resource_uid,
          label: service.label,
          kind: service.kind,
          pods: current ? pods.length : null,
          ready: current
            ? pods.filter((p) => observation.facets?.[p.id]?.ready === true)
                .length
            : null,
          http: current && service.health === "ready",
          podUIDs: current ? pods.map((p) => p.resource_uid) : [],
        };
      }),
    };
  });
}

// A successful read receipt is not a plan binding or execution approval.
export function planConnectionState(connection, now = Date.now()) {
  const age = now - Date.parse(connection?.checked_at);
  const fresh = connection?.current === true && age >= 0 && age < 180000;
  if (!connection)
    return {
      fresh: false,
      tone: "unknown",
      label: "계획 연결 필요",
      detail: "운영 계획과 본인 조회 권한을 연결해 주세요.",
    };
  if (!fresh)
    return {
      fresh: false,
      tone: "unknown",
      label: "접속 상태 재확인 필요",
      detail: "이전 조회 기록만 있습니다. 현재 계획 접근 권한은 미확인입니다.",
    };
  if (connection.last_http_status === 403)
    return {
      fresh,
      tone: "attention",
      label: "계획 조회 권한 필요",
      detail:
        "최근 본인 조회가 거부됐습니다(403). 운영 담당자의 계획별 권한 연결이 필요합니다.",
    };
  if (connection.last_http_status === 200)
    return {
      fresh,
      tone: "unknown",
      label: "계획 결속 확인 필요",
      detail:
        "조회 응답은 받았지만 현재 계획·승인·실행 연결은 확인되지 않았습니다.",
    };
  return {
    fresh,
    tone: "attention",
    label: "계획 조회 미완료",
    detail: "운영 콘솔에서 본인 인증과 계획 조회 상태를 확인해 주세요.",
  };
}

export function renderJourney(
  parent,
  { observation, connection, trial, trialView, onNavigate },
) {
  const box = node("section", undefined, "card sova-live-card sova-journey");
  box.append(
    node("p", "SERVICE MIGRATION", "eyebrow"),
    node("h2", "관측부터 이전·대응까지"),
    node("p", "현재 확인된 근거와 다음 작업을 이어서 확인합니다.", "muted"),
  );
  const grid = node("div", undefined, "sova-journey-grid");
  for (const lane of migrationSnapshot(observation)) {
    const item = node("article", undefined, "sova-journey-item");
    item.dataset.tone = lane.current ? "observed" : "unknown";
    item.append(
      node(
        "small",
        lane.lane === "source" ? "01 · AWS 출발지" : "02 · 온프렘 목적지",
      ),
      node("h3", lane.current ? "자원 관측 수신" : "현재 상태 미확인"),
      node(
        "p",
        lane.current
          ? `등록 Service ${lane.services.length}개 · 준비 상태와 HTTP 응답은 개별 확인`
          : "유효한 수집 결과가 필요합니다.",
      ),
    );
    grid.append(item);
  }
  const access = planConnectionState(connection);
  const plan = node("article", undefined, "sova-journey-item");
  plan.dataset.tone = access.tone;
  plan.append(
    node("small", "03 · 운영 이전"),
    node("h3", access.label),
    node("p", access.detail),
  );
  grid.append(plan);
  box.append(grid);
  const actions = node("div", undefined, "sova-journey-actions");
  for (const [label, target] of [
    ["이전 단계·필요 근거 보기", "migration"],
    ["실제 워크로드 지도", "topology"],
  ]) {
    const b = node("button", label, "sova-live-link");
    b.type = "button";
    b.onclick = () => onNavigate(target);
    actions.append(b);
  }
  box.append(actions);
  const response = node("div", undefined, "sova-journey-response");
  const state =
    !trial || trial.phase === "idle"
      ? "시험 준비 전"
      : trial.phase === "ended"
        ? "종료된 시험 기록"
        : trialView?.fresh
          ? "전용 시험 상태 수신"
          : "시험 상태 재확인 필요";
  response.append(
    node("strong", `격리·대체·복귀 · ${state}`),
    node(
      "p",
      "전용 무상태 시험 자원의 실제 대응입니다. 공유 채팅 앱의 운영 대응·AWS 이전 완료와 별도로 표시합니다.",
    ),
  );
  box.append(response);
  parent.append(box);
}

export function renderMigration(parent, observation, connection = null) {
  const box = node("section", undefined, "card sova-live-card sova-migration");
  box.append(
    node("p", "REAL CHAT · AWS → ON-PREMISES", "eyebrow"),
    node("h2", "실제 채팅 앱 · AWS → 온프렘"),
    node(
      "p",
      "등록된 실제 채팅 앱과 DB·첨부 저장소의 배포 관측입니다. 아래 전용 격리 시험의 자원과는 다릅니다.",
    ),
  );
  const lanes = node("div", undefined, "sova-migration-lanes");
  for (const lane of migrationSnapshot(observation)) {
    const col = node("section", undefined, "sova-migration-lane");
    col.dataset.lane = lane.lane;
    col.dataset.current = String(lane.current);
    col.append(
      node("h3", lane.lane === "source" ? "AWS · 출발지" : "온프렘 · 목적지"),
      node("p", lane.current ? "실제 자원 조회됨" : "현재 자원 상태 미확인"),
      node(
        "small",
        lane.observedAt
          ? `관측 ${new Date(lane.observedAt).toLocaleString("ko-KR")}`
          : "관측 기록 없음",
      ),
    );
    for (const service of lane.services) {
      const resource = node("article", undefined, "sova-migration-resource");
      resource.dataset.kind = service.kind;
      resource.append(
        node("strong", service.label),
        node(
          "p",
          service.pods === null
            ? "Pod 준비 상태 미확인"
            : `Service 선택 Pod ${service.pods}개 · Ready ${service.ready}개`,
        ),
        node(
          "p",
          service.http ? "관리 경로 /healthz 응답 확인" : "HTTP 응답 미확인",
        ),
      );
      const identity = node("details");
      identity.append(
        node("summary", "실제 자원 식별 근거"),
        node("p", `Service UID: ${service.uid}`),
      );
      for (const uid of service.podUIDs)
        identity.append(node("p", `Pod UID: ${uid}`));
      resource.append(identity);
      col.append(resource);
    }
    if (!lane.services.length)
      col.append(node("p", "확인된 등록 Service가 없습니다."));
    lanes.append(col);
  }
  box.append(
    lanes,
    node(
      "p",
      "이전 방향: AWS → 온프렘 · 현재 트래픽 비율과 DB 쓰기 대상은 이 배포 관측만으로 판정하지 않습니다.",
      "sova-migration-boundary",
    ),
  );
  const steps = node("ol", undefined, "sova-migration-steps");
  const access = planConnectionState(connection);
  for (const [title, detail] of [
    ["계획 연결", access.detail],
    ["보안·데이터 준비 판정", "같은 계획의 T14 원문·T19 결과 연결 필요"],
    ["단계적 앱 트래픽 전환", "T10 승인·T17 실제 가중치 관측 필요"],
    ["DB 쓰기 대상 전환", "T12 쓰기 차단·최종 동기화·무결성 영수증 필요"],
    ["채팅·첨부·재접속 확인", "실제 업무 요청과 전환 후 데이터 보존 시험 필요"],
    ["안정화·복귀 준비", "관측 창과 역방향 데이터·Edge 복귀 근거 필요"],
  ]) {
    const step = node("li");
    step.dataset.state = steps.children.length === 0 ? access.tone : "unknown";
    step.append(
      node(
        "span",
        String(steps.children.length + 1).padStart(2, "0"),
        "sova-step-number",
      ),
      node("strong", title),
      node(
        "span",
        steps.children.length === 0 ? access.label : "근거 연결 필요",
        "sova-step-state",
      ),
      node("p", detail),
    );
    steps.append(step);
  }
  const next = node("div", undefined, "sova-migration-next");
  next.append(
    node("strong", `다음 작업 · ${access.label}`),
    node("p", access.detail),
  );
  const link = node("a", "운영 계획·이벤트 콘솔 열기 ↗", "sova-live-link");
  link.href = "/__native/console/";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  next.append(link);
  // Show the operational journey before individual resource inventories.
  box.insertBefore(next, lanes);
  box.insertBefore(node("h3", "운영 이전 단계"), lanes);
  box.insertBefore(steps, lanes);
  if (connection?.checked_at)
    box.append(
      node(
        "p",
        `운영 접점 확인 시각: ${new Date(connection.checked_at).toLocaleString("ko-KR")} · ${access.fresh ? "최근 조회 기록" : "과거 기록 · 현재 권한 재확인 필요"}`,
      ),
    );
  box.append(
    node(
      "p",
      "공유 채팅 앱 격리·이전 실행은 연결되지 않았습니다. 전용 시험 승인은 이 앱의 변경을 허용하지 않습니다.",
    ),
  );
  parent.append(box);
}
