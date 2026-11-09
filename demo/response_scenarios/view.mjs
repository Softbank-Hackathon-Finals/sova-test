import {
  SCENARIOS,
  PHASES,
  PHASE_LABELS,
  HEALTH_LABELS,
  definition,
  createSession,
  advance,
  snapshot,
} from "./model.mjs";

const $ = (id) => document.getElementById(id);
const element = (tag, text, className) => {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (className) item.className = className;
  return item;
};
const svgElement = (tag, attrs = {}, text) => {
  const item = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs))
    item.setAttribute(key, String(value));
  if (text !== undefined) item.textContent = text;
  return item;
};
let session = createSession(),
  selected = "api",
  zoom = 1,
  timer = null,
  playing = false;
const glyphs = {
  entry: "↗",
  external: "↗",
  service: "◎",
  app: "▣",
  secret: "◇",
  queue: "≡",
  worker: "⚙",
  storage: "▤",
  database: "▥",
};

function stop() {
  playing = false;
  clearTimeout(timer);
  timer = null;
}
function reset(id = session.scenario) {
  stop();
  const changingScenario = id !== session.scenario;
  session = createSession(id, {
    outcome: $("outcome").value,
    preapproved: !changingScenario && $("preapproved").checked,
  });
  selected = definition(id).targets[0];
  render();
}
function forward(approve = false) {
  const next = advance(session, { approve });
  session = next;
  if (
    ["complete", "held"].includes(session.phase) ||
    (session.phase === "awaiting_approval" && !session.preapproved)
  )
    stop();
  render();
}
function schedule() {
  clearTimeout(timer);
  if (!playing) return;
  timer = setTimeout(
    () => {
      forward();
      schedule();
    },
    Number($("speed").value),
  );
}
function renderScenarios() {
  const root = $("scenario-list");
  if (!root.childElementCount) {
    let group = "";
    for (const [index, item] of SCENARIOS.entries()) {
      if (group !== item.group) {
        group = item.group;
        root.append(element("h3", group, "scenario-category"));
      }
      const button = element("button", undefined, "scenario-choice");
      button.type = "button";
      button.dataset.scenario = item.id;
      button.append(
        element("span", String(index + 1).padStart(2, "0"), "scenario-number"),
        element("span", item.title),
        element("span", "↗", "scenario-arrow"),
      );
      button.onclick = () => reset(item.id);
      root.append(button);
    }
  }
  for (const button of root.querySelectorAll("button")) {
    const active = button.dataset.scenario === session.scenario;
    button.classList.toggle("selected", active);
    button.setAttribute("aria-pressed", String(active));
  }
}

function edgePath(source, target, id) {
  // Long bypass routes run through a separate upper lane to avoid passing through nodes.
  const sx = source.x + 180,
    sy = source.y + 43,
    tx = target.x,
    ty = target.y + 43;
  if (["standby-route", "target-route"].includes(id)) {
    const lane = id === "target-route" ? 56 : 240;
    return `M ${sx} ${sy} C ${sx + 75} ${sy}, ${sx + 50} ${lane}, ${sx + 100} ${lane} L ${tx - 60} ${lane} Q ${tx - 20} ${lane} ${tx - 20} ${lane + 40} L ${tx - 20} ${ty - 25} Q ${tx - 20} ${ty} ${tx} ${ty}`;
  }
  if (tx < source.x)
    return `M ${source.x} ${sy} C ${source.x - 65} ${sy}, ${target.x + 245} ${ty}, ${target.x + 180} ${ty}`;
  return `M ${sx} ${sy} C ${sx + Math.max(35, (tx - sx) * 0.5)} ${sy}, ${tx - 50} ${ty}, ${tx} ${ty}`;
}
function renderGraph(view) {
  const svg = $("workload-map");
  svg.style.width = `${zoom * 100}%`;
  svg.replaceChildren();
  const defs = svgElement("defs");
  for (const state of [
    "flow",
    "warning",
    "cut",
    "sync",
    "idle",
    "draining",
    "unknown",
  ]) {
    const marker = svgElement("marker", {
      id: `arrow-${state}`,
      markerWidth: 8,
      markerHeight: 8,
      refX: 7,
      refY: 3,
      orient: "auto",
      markerUnits: "strokeWidth",
    });
    marker.append(
      svgElement("path", { d: "M0,0 L0,6 L7,3 z", class: `arrow-${state}` }),
    );
    defs.append(marker);
  }
  svg.append(defs);
  const aws = svgElement("g");
  aws.append(
    svgElement("rect", {
      x: 245,
      y: 84,
      width: 760,
      height: 680,
      rx: 22,
      class: "environment-zone",
    }),
    svgElement(
      "text",
      { x: 270, y: 107, class: "environment-title" },
      "AWS · 가상 출발 환경",
    ),
  );
  const onprem = svgElement("g");
  onprem.append(
    svgElement("rect", {
      x: 1075,
      y: 84,
      width: 300,
      height: 680,
      rx: 22,
      class: "environment-zone destination",
    }),
    svgElement(
      "text",
      { x: 1100, y: 107, class: "environment-title" },
      "온프렘 · 가상 목적지",
    ),
  );
  svg.append(aws, onprem);
  if (view.operating && ["segment", "isolate"].includes(session.scenario)) {
    const segment = session.scenario === "segment";
    svg.append(
      svgElement("rect", {
        x: 502,
        y: segment ? 282 : 457,
        width: 216,
        height: segment ? 300 : 125,
        rx: 18,
        class: `isolation-zone ${session.phase === "held" ? "uncertain" : ""}`,
      }),
      svgElement(
        "text",
        { x: 513, y: segment ? 274 : 449, class: "isolation-label" },
        session.phase === "held"
          ? "격리 확인 보류 · 목업"
          : "선택 구간 격리 · 목업",
      ),
    );
  }
  const byId = new Map(view.nodes.map((node) => [node.id, node]));
  for (const item of view.edges) {
    const path = edgePath(
      byId.get(item.source),
      byId.get(item.target),
      item.id,
    );
    const group = svgElement("g", {
      class: `link ${item.state}`,
      "data-edge": item.id,
      "data-state": item.state,
    });
    group.append(
      svgElement(
        "title",
        {},
        `${byId.get(item.source).label} → ${byId.get(item.target).label}: ${item.label} / ${item.state} / 목업`,
      ),
    );
    group.append(
      svgElement("path", {
        d: path,
        "marker-end": `url(#arrow-${item.state})`,
        class: "edge-line",
      }),
    );
    if (["flow", "warning", "sync"].includes(item.state)) {
      const particle = svgElement("circle", { r: 3, class: "flow-particle" });
      particle.append(
        svgElement("animateMotion", {
          dur: item.state === "sync" ? "2.8s" : "2.1s",
          repeatCount: "indefinite",
          path,
        }),
      );
      group.append(particle);
    }
    if (item.state === "cut") {
      const from = byId.get(item.source),
        to = byId.get(item.target);
      const x = (from.x + to.x + 180) / 2,
        y = (from.y + to.y) / 2 + 43;
      group.append(
        svgElement("circle", { cx: x, cy: y, r: 10, class: "cut-badge" }),
        svgElement(
          "text",
          { x, y: y + 4, "text-anchor": "middle", class: "cut-mark" },
          "×",
        ),
      );
    }
    if (item.id === "replication" && item.state === "sync")
      group.append(
        svgElement(
          "text",
          { x: 1024, y: 677, class: "sync-label" },
          "최종 동기화 · 모의",
        ),
      );
    svg.append(group);
  }
  for (const item of view.nodes) {
    const group = svgElement("g", {
      transform: `translate(${item.x} ${item.y})`,
      class: `map-node ${item.status} ${item.affected ? "affected" : ""} ${selected === item.id ? "selected" : ""}`,
      role: "button",
      tabindex: 0,
      "aria-label": `${item.label}, ${HEALTH_LABELS[item.status]}`,
      "aria-pressed": String(selected === item.id),
      "data-node": item.id,
    });
    group.append(
      svgElement("rect", {
        x: -7,
        y: -7,
        width: 194,
        height: 102,
        rx: 17,
        class: "node-halo",
      }),
      svgElement("rect", {
        width: 180,
        height: 88,
        rx: 12,
        class: "node-surface",
      }),
      svgElement(
        "text",
        { x: 13, y: 26, class: "node-glyph" },
        glyphs[item.kind],
      ),
      svgElement("text", { x: 39, y: 25, class: "node-label" }, item.label),
      svgElement(
        "text",
        { x: 13, y: 46, class: "node-subtitle" },
        item.subtitle,
      ),
      svgElement("circle", { cx: 17, cy: 68, r: 3, class: "node-dot" }),
      svgElement(
        "text",
        { x: 27, y: 72, class: "node-state" },
        HEALTH_LABELS[item.status],
      ),
    );
    const choose = () => {
      selected = item.id;
      renderGraph(snapshot(session));
      renderInspector(snapshot(session));
    };
    group.onclick = choose;
    group.onkeydown = (event) => {
      if (["Enter", " "].includes(event.key)) {
        event.preventDefault();
        choose();
      }
    };
    svg.append(group);
  }
}
function renderInspector(view) {
  const root = $("node-inspector"),
    item = view.nodes.find((node) => node.id === selected);
  root.replaceChildren(
    element("p", "COMPONENT INSPECTOR", "eyebrow"),
    element("h3", item.label),
    element(
      "span",
      HEALTH_LABELS[item.status],
      `node-state-pill ${item.status}`,
    ),
    element("p", item.subtitle),
  );
  const target = definition(session.scenario).targets.includes(item.id);
  root.append(
    element("h4", "이번 대응 범위"),
    element(
      "p",
      target
        ? "선택 시나리오의 직접 대응 대상입니다."
        : "이번 시나리오의 직접 변경 대상이 아닙니다.",
    ),
  );
  if (item.affected && !target)
    root.append(
      element(
        "p",
        "연결 관계에 따른 영향 가능 표시입니다. 침해 확정이나 격리 대상 확대를 뜻하지 않습니다.",
        "inspector-warning",
      ),
    );
  root.append(element("h4", "연결 상태 · 목업"));
  const labels = {
    flow: "흐름 유지",
    warning: "영향 가능",
    cut: "차단",
    sync: "동기화 중",
    idle: "대기",
    draining: "전환 준비",
    unknown: "미확인",
  };
  for (const link of view.edges.filter(
    (edge) => edge.source === selected || edge.target === selected,
  )) {
    const neighbor = view.nodes.find(
      (node) =>
        node.id === (link.source === selected ? link.target : link.source),
    );
    const row = element("div", undefined, "inspector-link");
    row.append(
      element(
        "span",
        `${link.source === selected ? "→" : "←"} ${neighbor.label}`,
      ),
      element("b", labels[link.state], link.state),
    );
    root.append(row);
  }
  root.append(
    element(
      "p",
      "가상 자원이며 실제 Pod UID·로그·패킷 증거가 없습니다.",
      "inspector-footnote",
    ),
  );
}
function renderApproval() {
  const root = $("approval-panel");
  root.replaceChildren();
  root.hidden = session.phase !== "awaiting_approval";
  if (root.hidden) return;
  const spec = definition(session.scenario);
  root.append(
    element(
      "strong",
      session.preapproved
        ? "사전 승인 범위 확인 · 목업"
        : "이 대응 범위를 승인할까요? · 목업",
    ),
    element("p", spec.action),
    element(
      "small",
      "실제 운영 승인이 아닙니다. 재생 시간을 기다려도 사람이 승인한 것으로 처리하지 않습니다.",
    ),
  );
  const button = element("button", "목업 승인 후 계속", "button primary");
  button.type = "button";
  button.id = "approve";
  button.onclick = () => forward(true);
  root.append(button);
}
function render() {
  const spec = definition(session.scenario),
    view = snapshot(session);
  renderScenarios();
  $("scenario-title").textContent = spec.title;
  $("scenario-group").textContent = spec.group;
  $("scenario-description").textContent = spec.summary;
  $("stat-phase").textContent = PHASE_LABELS[session.phase];
  $("stat-scenario").textContent = spec.title;
  $("stat-availability").textContent = view.availability;
  $("stat-isolation").textContent =
    `${view.counters.isolated}개 / ${view.counters.cut}개`;
  $("stat-route").textContent = view.route;
  $("stat-writer").textContent = `writer: ${view.writer} · 모의`;
  $("phase-track").replaceChildren(
    ...PHASES.map((phase, i) => {
      const reached = session.history.some((event) => event.phase === phase);
      const item = element(
        "span",
        undefined,
        `phase-item ${reached ? "reached" : ""} ${phase === session.phase ? "current" : ""}`,
      );
      item.append(
        element("b", String(i + 1)),
        element("span", PHASE_LABELS[phase]),
      );
      if (phase === session.phase) item.setAttribute("aria-current", "step");
      return item;
    }),
  );
  const terminal = ["held", "complete"].includes(session.phase),
    approval = session.phase === "awaiting_approval" && !session.preapproved;
  $("next").textContent =
    session.phase === "normal"
      ? "이상 상황 주입 · 목업"
      : terminal
        ? "실행 종료"
        : approval
          ? "목업 승인 필요"
          : "다음 단계";
  $("next").disabled = terminal || approval;
  $("autoplay").textContent = playing ? "재생 일시정지" : "자동 재생";
  $("autoplay").disabled = terminal || approval;
  $("outcome").disabled = session.phase !== "normal";
  $("preapproved").disabled = !spec.policy || session.phase !== "normal";
  $("preapproved").checked = session.preapproved;
  $("policy-description").textContent = spec.policy
    ? "이 유형의 범위만 미리 허용합니다. 시작 전 선택할 수 있습니다."
    : "이 유형은 단계별 목업 승인을 유지합니다.";
  $("scope-description").textContent = spec.result;
  const facts = [
    [
      "대상",
      spec.targets
        .map((id) => view.nodes.find((node) => node.id === id).label)
        .join(" · "),
    ],
    ["결과 확인", spec.verify],
    ["사고 보류", view.hold ? "유지 · 일반 승인으로 해제하지 않음" : "미발생"],
    ["실행 권한", "없음 · 브라우저 상태만 변경"],
  ];
  $("scope-facts").replaceChildren(
    ...facts.flatMap(([label, value]) => [
      element("dt", label),
      element("dd", value),
    ]),
  );
  $("playback-status").textContent = session.history.at(-1).message;
  $("playback-status").className =
    session.phase === "held" ? "held-message" : "";
  $("event-list").replaceChildren(
    ...session.history.map((event, i) => {
      const row = element("li");
      row.append(
        element("span", String(i + 1).padStart(2, "0"), "event-sequence"),
      );
      const text = element("div");
      text.append(
        element("b", PHASE_LABELS[event.phase]),
        element("p", event.message),
      );
      row.append(text, element("small", "MOCK", "event-provenance"));
      return row;
    }),
  );
  renderApproval();
  renderGraph(view);
  renderInspector(view);
}
$("next").onclick = () => forward();
$("reset").onclick = () => reset();
$("outcome").onchange = () => reset();
$("preapproved").onchange = () => reset();
$("autoplay").onclick = () => {
  if (playing) stop();
  else playing = true;
  render();
  schedule();
};
$("speed").onchange = schedule;
$("zoom-in").onclick = () => {
  zoom = Math.min(2, zoom + 0.2);
  renderGraph(snapshot(session));
};
$("zoom-out").onclick = () => {
  zoom = Math.max(1, zoom - 0.2);
  renderGraph(snapshot(session));
};
$("zoom-fit").onclick = () => {
  zoom = 1;
  renderGraph(snapshot(session));
};
$("export").onclick = () => {
  const payload = {
    kind: "sova.workload-response.mock.v1",
    provenance: "mock",
    actual_execution: false,
    scenario: session.scenario,
    session,
    result: snapshot(session),
    note: "가상 시나리오 기록입니다. 운영 증거로 사용할 수 없습니다.",
  };
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
  );
  const link = element("a");
  link.href = url;
  link.download = `sova-mock-${session.scenario}.json`;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};
for (const button of document.querySelectorAll("[data-section]"))
  button.onclick = () => {
    for (const sibling of document.querySelectorAll("[data-section]")) {
      sibling.classList.toggle("active", sibling === button);
      if (sibling === button) sibling.setAttribute("aria-current", "page");
      else sibling.removeAttribute("aria-current");
    }
    $(button.dataset.section).scrollIntoView({
      behavior: matchMedia("(prefers-reduced-motion: reduce)").matches
        ? "instant"
        : "smooth",
      block: "start",
    });
  };
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    stop();
    render();
  }
});
window.addEventListener("pagehide", stop);
render();
