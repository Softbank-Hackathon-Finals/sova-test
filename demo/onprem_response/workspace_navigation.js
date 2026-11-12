import { observedTopology } from "/console/observation-model.js";
import { stageLabels, responseLabels } from "/console/workload-model.js";
import {
  renderMigration,
  renderJourney,
  planConnectionState,
  migrationSnapshot,
} from "/__trial/migration_view.js";

const views = {
  overview: ["워크스페이스", "실제 관측과 전용 시험의 연결 상태를 확인합니다."],
  migration: [
    "환경 이전",
    "실제 채팅 앱의 AWS·온프렘 배포와 운영 이전 연결 상태를 확인합니다.",
  ],
  topology: [
    "워크로드 지도",
    "실제 등록 자원과 전용 시험의 격리·전환을 확인합니다.",
  ],
  network: [
    "네트워크 아틀라스",
    "실제로 관측한 자원의 연결·설정 참조 관계입니다.",
  ],
  security: [
    "보안·거버넌스",
    "현재 보안 설정, 보존 통제 시험, 전용 시험의 승인·격리 근거입니다.",
  ],
  delivery: [
    "IaC·고객 환경",
    "계획 승인·변경 반영·고객 동기화는 각 제품 API의 연결이 필요합니다.",
  ],
  monitoring: [
    "모니터링",
    "수집 시각·관측 만료·Kubernetes 준비 상태와 HTTP 확인을 구분합니다.",
  ],
  timeline: [
    "실행 타임라인",
    "서버가 전달한 전용 시험의 실행·실패·복귀 기록입니다.",
  ],
  analysis: [
    "의존성·후보 비교",
    "현재 관측한 의존 관계를 표시하며 미연결 후보 평가는 생성하지 않습니다.",
  ],
  ai: ["AI·리허설", "실제 에이전트·리허설 실행 경로의 연결 상태를 확인합니다."],
  costs: ["비용·예산", "비용 수집 API에서 받은 자료만 표시합니다."],
};

const node = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = String(text);
  if (cls) n.className = cls;
  return n;
};

const time = (value) =>
  value ? new Date(value).toLocaleString("ko-KR", { hour12: false }) : "미확인";

export function mountWorkspace({ trialPanel }) {
  const main = document.querySelector("#workspace-main");
  const root = node("section", undefined, "sova-live-pages");
  root.id = "sova-live-pages";
  const content = node("div");
  const retained = node("div");
  root.append(content, retained);
  main.append(root);
  const securityPanels = ["observed-security", "observed-controls"]
    .map((id) => document.getElementById(id))
    .filter(Boolean);
  for (const panel of securityPanels) retained.append(panel);
  let active = "overview",
    observation = null,
    trial = null,
    trialView = null;
  let observationRaw = null,
    migrationConnection = null,
    reading = false,
    authorized = false,
    stopped = false,
    generation = 0;
  let lastRender = "";

  const button = (text, target) => {
    const b = node("button", text, "sova-live-link");
    b.type = "button";
    b.onclick = () => select(target);
    return b;
  };
  const card = (title, detail) => {
    const section = node("section", undefined, "card sova-live-card");
    section.append(node("h2", title));
    if (detail) section.append(node("p", detail, "muted"));
    content.append(section);
    return section;
  };
  const table = (parent, headers, rows) => {
    const wrap = node("div", undefined, "sova-live-table");
    const t = node("table");
    const head = node("thead"),
      hrow = node("tr");
    for (const h of headers) hrow.append(node("th", h));
    head.append(hrow);
    const body = node("tbody");
    for (const values of rows) {
      const row = node("tr");
      for (const value of values) row.append(node("td", value));
      body.append(row);
    }
    if (!rows.length) {
      const row = node("tr"),
        cell = node("td", "확인된 자료가 없습니다.");
      cell.colSpan = headers.length;
      row.append(cell);
      body.append(row);
    }
    t.append(head, body);
    wrap.append(t);
    parent.append(wrap);
  };
  const unavailable = (title, required) => {
    const c = card(
      title,
      "이 관측 호스트에는 해당 제품 API가 연결되지 않았습니다.",
    );
    c.dataset.connection = "unconnected";
    c.append(
      node("p", "연결 전에는 실행·성공·금액을 표시하지 않습니다."),
      node("p", required),
      button("현재 연결 상태 보기", "overview"),
    );
    return c;
  };
  const environmentRows = () =>
    (observation?.environments ?? []).map((e) => [
      e.lane === "source" ? "AWS 출발지" : "온프렘 목적지",
      e.status === "CURRENT"
        ? "현재 관측"
        : e.status === "STALE"
          ? "만료·수집 실패"
          : "미연결",
      `${e.observed_service_count ?? "—"} / ${e.registered_service_count}`,
      time(e.observed_at),
    ]);
  const records = () => trialView?.events ?? [];
  const resultLabel = (r) =>
    r.current
      ? (responseLabels[r.status] ?? r.status)
      : r.status === "verified"
        ? "과거 확인 · 현재 미확인"
        : `기록: ${responseLabels[r.status] ?? r.status}`;

  function render() {
    const key = JSON.stringify([
      active,
      observation?.revision,
      observation?.environments.map((e) => e.status),
      trial?.session_id,
      trial?.phase,
      trial?.observation_revision,
      trialView?.fresh,
      authorized,
      migrationConnection,
      planConnectionState(migrationConnection).fresh,
      migrationSnapshot(observation).map((lane) => lane.current),
    ]);
    if (key === lastRender) return;
    lastRender = key;
    retained.hidden = active !== "security" || !authorized;
    if (active === "topology") return;
    content.replaceChildren();
    if (!authorized) {
      card(
        "개인 접속 확인 필요",
        "현재 인증된 조회 결과가 없어 이전 자료를 철회했습니다.",
      );
      return;
    }
    const graph = observation?.view;
    const nodes = graph?.nodes ?? [],
      edges = graph?.edges ?? [];
    if (active === "overview") {
      renderJourney(content, {
        observation,
        connection: migrationConnection,
        trial,
        trialView,
        onNavigate: select,
      });
      const c = card(
        "실제 연결 상태",
        "클러스터 관측, 전용 시험, 제품 운영 연결은 각각 확인합니다.",
      );
      table(
        c,
        ["연결", "상태", "확인 범위"],
        [
          [
            "AWS·온프렘 자원 관측",
            observation ? "자료 수신" : "현재 미확인",
            `관측 자원 ${nodes.length}개 · 관계 ${edges.length}개`,
          ],
          [
            "격리·재검증·복귀 시험",
            trial?.phase === "idle"
              ? "준비 전"
              : trial?.phase === "ended"
                ? "종료·정리된 기록"
                : "전용 시험",
            "소유한 새 무상태 시험 자원",
          ],
          [
            "운영 계획·승인·이전",
            planConnectionState(migrationConnection).label,
            "운영 콘솔 연결 준비 · 실제 계획·승인·실행 인수 필요",
          ],
          [
            "IaC·고객 동기화 / AI / 비용",
            "이 호스트에 미연결",
            "해당 제품의 인증된 API 필요",
          ],
        ],
      );
      const actions = card("기능 바로가기");
      for (const id of [
        "topology",
        "security",
        "monitoring",
        "timeline",
        "migration",
      ])
        actions.append(button(views[id][0], id));
      const envs = card("환경별 관측");
      table(
        envs,
        ["환경", "수집 상태", "Service", "관측 시각"],
        environmentRows(),
      );
    } else if (active === "security") {
      const c = card(
        "격리·재검증·복귀",
        "개인 전용 시험의 변경은 정확한 계획에 대한 별도 승인을 사용합니다.",
      );
      c.append(button("워크로드 지도에서 승인·실행", "topology"));
      table(
        c,
        ["단계", "상태", "근거"],
        (trialView?.responses ?? []).map((r) => [
          stageLabels[r.stage] ?? r.stage,
          resultLabel(r),
          r.detail,
        ]),
      );
    } else if (active === "migration") {
      const native = card(
        "실제 계획·SSE·운영 승인",
        "팀 플랫폼의 기존 계획·이벤트·승인 화면을 같은 Sova 디자인으로 연결합니다. 운영자 권한과 실행 구간은 서버에서 확인합니다.",
      );
      const nativeLink = node(
        "a",
        "실제 운영 계획 콘솔 열기",
        "sova-live-link",
      );
      nativeLink.href = "/__native/console/";
      nativeLink.target = "_blank";
      nativeLink.rel = "noopener noreferrer";
      native.append(nativeLink);
      content.append(native);
      renderMigration(content, observation, migrationConnection);
      const c = card(
        "전용 시험의 전환·복귀",
        "같은 온프렘의 무상태 시험 경로입니다. AWS→온프렘 업무·데이터 이전과 구분합니다.",
      );
      c.append(button("현재 시험 경로와 승인 보기", "topology"));
      table(
        c,
        ["단계", "상태", "범위"],
        (trialView?.responses ?? [])
          .filter((r) =>
            ["approve", "verify", "route", "recover"].includes(r.stage),
          )
          .map((r) => [stageLabels[r.stage], resultLabel(r), r.detail]),
      );
    } else if (["network", "analysis"].includes(active)) {
      const c = card(
        active === "network" ? "관측된 연결 관계" : "현재 자원 의존 관계",
        "selector·소속·설정 참조와 확인된 HTTP 경로를 표시합니다. 실제 트래픽이나 코드 분석 결과를 추정하지 않습니다.",
      );
      const byId = new Map(nodes.map((n) => [n.id, n.label]));
      table(
        c,
        ["출발 자원", "대상 자원", "종류", "관측 관계"],
        edges.map((e) => [
          byId.get(e.source) ?? "미확인",
          byId.get(e.target) ?? "미확인",
          e.kind,
          e.label,
        ]),
      );
      c.append(button("지도에서 자원 선택", "topology"));
      if (active === "analysis")
        unavailable(
          "코드 의존성·배치 후보 평가",
          "등록한 앱의 분석 산출물과 요구사항·호환성·비용 근거가 필요합니다.",
        );
    } else if (active === "monitoring") {
      const c = card(
        "환경별 수집 상태",
        "Kubernetes Ready와 실제 HTTP 응답은 서로 다른 근거입니다.",
      );
      table(
        c,
        ["환경", "수집 상태", "Service", "관측 시각"],
        environmentRows(),
      );
      const readiness = card("자원별 관측");
      table(
        readiness,
        ["자원", "Kubernetes 준비", "HTTP 확인", "근거"],
        nodes.map((n) => [
          n.label,
          observation?.facets?.[n.id]?.ready === true
            ? "준비 확인"
            : observation?.facets?.[n.id]?.ready === false
              ? "준비 미완료"
              : "미확인",
          n.health === "ready" ? "응답 확인" : "현재 미확인",
          observation?.facets?.[n.id]?.summary ?? "미확인",
        ]),
      );
      unavailable(
        "CPU·메모리·OTel·서비스 SLO",
        "인증된 시계열·관측 창·목표 기준 연결이 필요합니다. 준비 상태로 지연·가용성을 대신하지 않습니다.",
      );
    } else if (active === "timeline") {
      const c = card(
        "전용 시험의 실행 기록",
        "서버가 전달한 시각과 결과만 표시합니다. 운영 T10 이벤트는 별도 연결입니다.",
      );
      table(
        c,
        ["시각", "단계", "결과", "내용"],
        records().map((e) => [
          time(e.occurred_at),
          stageLabels[e.stage] ?? e.stage,
          responseLabels[e.status] ?? e.status,
          e.summary,
        ]),
      );
      if (trial?.phase === "ended")
        c.append(
          node(
            "p",
            "종료된 전용 시험입니다. 현재 운영 자원 상태를 나타내지 않습니다.",
            "muted",
          ),
        );
    } else if (active === "delivery") {
      unavailable(
        "IaC 승인·변경 반영",
        "연결할 경로: 기존 변경 제안·diff/digest·서버 승인·PR 생성·반영 결과 조회.",
      );
      unavailable(
        "고객 환경 동기화",
        "연결할 경로: 등록된 고객 환경, Argo CD 등 기존 GitOps 상태 수집, 적용 revision·실행 imageID 대조.",
      );
    } else if (active === "ai") {
      unavailable(
        "AI·리허설 실행",
        "연결할 경로: 기존 에이전트 요청, T15/Harbor 실행, 독립 검증 산출물, T10 승인·감사 이벤트.",
      );
      card(
        "전용 시험과 구분",
        "터미널의 고정 HTTP 접근 시도와 검증 실패 주입은 실제 AI 에이전트 실행 결과가 아닙니다.",
      );
    } else if (active === "costs") {
      unavailable(
        "비용 조회·예산",
        "연결할 경로: 기존 T1 비용 조회·예산 API와 환경·통화·기간·자료 갱신 시각.",
      );
      card(
        "현재 금액 미확인",
        "청구 자료가 연결되지 않아 금액·절감률을 계산하지 않습니다. 실행 시간은 청구액을 대신하지 않습니다.",
      );
    }
  }

  function select(id) {
    if (!Object.hasOwn(views, id)) return;
    active = id;
    document.body.dataset.liveView = id;
    for (const b of document.querySelectorAll("nav button[data-view]"))
      b.setAttribute("aria-current", b.dataset.view === id ? "page" : "false");
    document.getElementById("breadcrumb-view").textContent = views[id][0];
    document.getElementById("view-title").textContent = views[id][0];
    document.getElementById("view-description").textContent = views[id][1];
    document.querySelector(".scope-pill").textContent =
      "실제 관측 · 전용 시험 · 연결 범위 표시";
    render();
    if (id === "topology") trialPanel.scrollIntoView({ block: "start" });
    document.getElementById("view-title").focus({ preventScroll: true });
  }

  async function refresh() {
    if (reading || stopped || !authorized) return;
    reading = true;
    const requestGeneration = generation;
    try {
      const response = await fetch("/v1/observed-workload", {
        credentials: "same-origin",
        cache: "no-store",
        signal: AbortSignal.timeout(6000),
      });
      if (!response.ok) throw Error("observation_unavailable");
      const raw = await response.json();
      const next = observedTopology(raw);
      if (generation !== requestGeneration || !authorized || stopped) return;
      if (
        observation &&
        observation.stream_id === next.stream_id &&
        next.revision < observation.revision
      )
        throw Error("old_observation");
      observationRaw = raw;
      observation = next;
      try {
        const response = await fetch("/__migration/status", {
          credentials: "same-origin",
          cache: "no-store",
          signal: AbortSignal.timeout(4000),
        });
        if (!response.ok) throw Error("migration_read_unavailable");
        const connection = await response.json();
        if (
          connection.kind !== "native-plan-read-status.v1" ||
          connection.plan_connected !== false ||
          connection.authorizes_execution !== false ||
          ![200, 401, 403, 404, 503].includes(connection.last_http_status) ||
          !Number.isFinite(Date.parse(connection.checked_at)) ||
          Date.parse(connection.checked_at) > Date.now() ||
          typeof connection.current !== "boolean"
        )
          throw Error("migration_read_invalid");
        if (generation === requestGeneration && authorized && !stopped)
          migrationConnection = connection;
      } catch {
        if (generation === requestGeneration) migrationConnection = null;
      }
    } catch {
      if (generation === requestGeneration) {
        observation = null;
        observationRaw = null;
        migrationConnection = null;
      }
    } finally {
      reading = false;
      render();
    }
  }

  for (const b of document.querySelectorAll("nav button[data-view]")) {
    b.disabled = false;
    b.onclick = () => select(b.dataset.view);
  }
  select("overview");
  const timer = setInterval(refresh, 5000);
  window.addEventListener("pagehide", () => {
    stopped = true;
    authorized = false;
    generation++;
    clearInterval(timer);
    observation = null;
    observationRaw = null;
    migrationConnection = null;
    trial = null;
    trialView = null;
    render();
  });
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) location.reload();
  });
  return {
    updateTrial(status, view) {
      if (stopped) return;
      const wasAuthorized = authorized;
      authorized = status !== null;
      trial = status;
      trialView = view;
      if (!authorized) {
        generation++;
        observation = null;
        observationRaw = null;
        migrationConnection = null;
      }
      if (authorized && observationRaw) {
        try {
          observation = observedTopology(observationRaw);
        } catch {
          observation = null;
          observationRaw = null;
        }
      }
      render();
      if (!wasAuthorized && authorized) refresh();
    },
    select,
  };
}
