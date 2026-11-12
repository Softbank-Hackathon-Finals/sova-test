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
  const denied = connection?.last_http_status === 403;
  const access = denied
    ? "마지막 본인 운영자 조회: 권한 거부(403)"
    : connection?.last_http_status === 200
      ? "조회 응답 수신 · 현재 정본 계획 결속 확인 필요"
      : "현재 정본 계획·운영자 조회 인수 필요";
  for (const [title, detail] of [
    ["계획 연결", access],
    ["보안·데이터 준비 판정", "같은 계획의 T14 원문·T19 결과 연결 필요"],
    ["단계적 앱 트래픽 전환", "T10 승인·T17 실제 가중치 관측 필요"],
    ["DB 쓰기 대상 전환", "T12 쓰기 차단·최종 동기화·무결성 영수증 필요"],
    ["채팅·첨부·재접속 확인", "실제 업무 요청과 전환 후 데이터 보존 시험 필요"],
    ["안정화·복귀 준비", "관측 창과 역방향 데이터·Edge 복귀 근거 필요"],
  ]) {
    const step = node("li");
    step.append(node("strong", title), node("p", detail));
    steps.append(step);
  }
  box.append(node("h3", "운영 이전 연결 상태"), steps);
  if (connection?.checked_at)
    box.append(
      node(
        "p",
        `운영 접점 확인 시각: ${new Date(connection.checked_at).toLocaleString("ko-KR")} · ${connection.current ? "최근 조회 기록" : "과거 기록 · 현재 권한 재확인 필요"}`,
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
