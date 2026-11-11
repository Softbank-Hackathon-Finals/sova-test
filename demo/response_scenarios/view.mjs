import {
  SCENARIOS,
  PHASES,
  PHASE_LABELS,
  HEALTH_LABELS,
  definition,
  createSession,
  snapshot,
  currentPhase,
  recoveryAvailable,
} from "./model.mjs";
import { createMotionClock, motionPlan } from "./motion.mjs";
import { mountSidebar, mountStudioView } from "./layout.mjs";
import { mountInjectionConsole } from "./injection_console.mjs";
import { executeCommand } from "./commands.mjs";
import { liveMode, connectRuntime, runtimeCommand, chooseRuntime, runtimeStatus, localGraph } from "./runtime_client.mjs";

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
  runVersion = 0,
  motionPaused = false,
  currentGraph = null,
  currentMotionPlan = null;
const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)");
if (liveMode) session = {...session, source: "local-rke2", history: [], outcome: "unknown"};
const motion = createMotionClock(applyMotionFrame);
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

function readSnapshot() {
  return liveMode ? localGraph(session, snapshot(session)) : snapshot(session);
}
function showError(error) {
  $("injection-feedback").textContent = error.message;
  $("stat-availability").textContent = "연결·실행 상태 확인 필요";
}
function reset(id = session.scenario) {
  if (liveMode) {
    chooseRuntime(id).catch(showError);
    return;
  }
  motion.clear();
  runVersion++;
  motionPaused = false;
  $("recovery-outcome").value = "pass";
  if (!reducedMotion.matches) $("workload-map").unpauseAnimations();
  const changingScenario = id !== session.scenario;
  session = createSession(id, {
    outcome: $("outcome").value,
    preapproved: !changingScenario && $("preapproved").checked,
  });
  selected = definition(id).targets[0];
  render();
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
function applyMotionFrame(frame) {
  if (!currentGraph || !currentMotionPlan) return;
  const svg = $("workload-map");
  svg.dataset.motionState = frame.state;
  svg.dataset.motionProgress = frame.progress.toFixed(3);
  const nodes = currentGraph.nodes.map((node) => ({
    ...node,
    ...(frame.positions[node.id] || currentMotionPlan.positions[node.id]),
  }));
  const indexed = new Map(nodes.map((node) => [node.id, node]));
  for (const node of nodes) {
    const group = svg.querySelector(`[data-node="${node.id}"]`);
    if (!group) continue;
    const entering = currentMotionPlan.entering.includes(node.id);
    const lift = entering ? -18 * (1 - frame.progress) : 0;
    group.setAttribute("transform", `translate(${node.x} ${node.y + lift})`);
    group.style.opacity =
      entering && frame.progress < 1 ? String(0.3 + 0.7 * frame.progress) : "";
  }
  for (const edge of currentGraph.edges) {
    const group = svg.querySelector(`[data-edge="${edge.id}"]`);
    if (!group) continue;
    const from = indexed.get(edge.source),
      to = indexed.get(edge.target);
    const path = edgePath(from, to, edge.id);
    group.querySelector(".edge-line").setAttribute("d", path);
    const stream = group.querySelector("animateMotion");
    if (stream && stream.getAttribute("path") !== path)
      stream.setAttribute("path", path);
    const badge = group.querySelector(".cut-badge"),
      mark = group.querySelector(".cut-mark");
    if (badge && mark) {
      const x = (from.x + to.x + 180) / 2,
        y = (from.y + to.y) / 2 + 43;
      badge.setAttribute("cx", x);
      badge.setAttribute("cy", y);
      mark.setAttribute("x", x);
      mark.setAttribute("y", y + 4);
    }
  }
  for (const path of svg.querySelectorAll(".transfer-path")) {
    const chip = svg.querySelector(
      `[data-transfer="${path.dataset.transferPath}"]`,
    );
    if (!chip) continue;
    const p = path.getPointAtLength(path.getTotalLength() * frame.progress);
    chip.setAttribute("transform", `translate(${p.x - 78} ${p.y - 23})`);
    chip.style.opacity =
      frame.progress >= 1 || reducedMotion.matches
        ? "0"
        : String(Math.min(1, frame.progress * 7, (1 - frame.progress) * 7));
  }
}
function setMotionPaused(paused) {
  motionPaused = paused;
  const svg = $("workload-map");
  svg.classList.toggle("motion-paused", paused);
  if (paused || reducedMotion.matches) svg.pauseAnimations();
  else svg.unpauseAnimations();
  if (paused) motion.pause();
  else motion.resume();
  $("motion-toggle").textContent = paused ? "움직임 재생" : "움직임 정지";
  $("motion-toggle").setAttribute("aria-pressed", String(paused));
}
function renderGraph(view) {
  const svg = $("workload-map");
  currentGraph = view;
  currentMotionPlan = motionPlan(session, view);
  const previous = motion.read().positions;
  const displayed = view.nodes.map((node) => ({
    ...node,
    ...(previous[node.id] || currentMotionPlan.positions[node.id]),
  }));
  svg.setAttribute("viewBox", `0 0 1400 ${currentMotionPlan.height}`);
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
      height: currentMotionPlan.quarantine ? 940 : 680,
      rx: 22,
      class: "environment-zone",
    }),
    svgElement(
      "text",
      { x: 270, y: 107, class: "environment-title" },
      liveMode ? "로컬 출발지 · 이 Mac RKE2" : "AWS · 출발 환경",
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
      liveMode ? "로컬 목적지 · 같은 RKE2" : "온프렘 · 목적지",
    ),
  );
  svg.append(aws, onprem);
  if (currentMotionPlan.quarantine) {
    svg.append(
      svgElement("rect", {
        x: 480,
        y: 810,
        width: 510,
        height: 190,
        rx: 18,
        class: `isolation-zone quarantine-bay ${view.operating ? "active" : ""} ${session.phase === "held" ? "uncertain" : ""}`,
      }),
      svgElement(
        "text",
        { x: 500, y: 837, class: "isolation-label" },
        session.phase === "held"
          ? "논리적 격리 영역 · 상태 확인 필요"
          : view.operating
            ? liveMode ? "논리적 격리 영역 · 이 Mac RKE2" : "논리적 격리 영역 · AWS 내부"
            : "논리적 격리 영역 · 대기",
      ),
    );
    if (currentMotionPlan.moving)
      for (const id of currentMotionPlan.isolated) {
        const original = view.nodes.find((node) => node.id === id);
        svg.append(
          svgElement("rect", {
            x: original.x,
            y: original.y,
            width: 180,
            height: 88,
            rx: 12,
            class: "origin-outline",
          }),
          svgElement(
            "text",
            {
              x: original.x + 90,
              y: original.y + 48,
              "text-anchor": "middle",
              class: "origin-caption",
            },
            "격리 이전 위치",
          ),
        );
      }
  }
  const byId = new Map(displayed.map((node) => [node.id, node]));
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
        `${byId.get(item.source).label} → ${byId.get(item.target).label}: ${item.label} / ${item.state}`,
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
          "최종 동기화",
        ),
      );
    svg.append(group);
  }
  for (const item of displayed) {
    const group = svgElement("g", {
      transform: `translate(${item.x} ${item.y})`,
      class: `map-node ${item.status} ${item.affected ? "affected" : ""} ${selected === item.id ? "selected" : ""}`,
      role: "button",
      tabindex: 0,
      "aria-label": `${item.label}, ${item.englishLabel}, ${HEALTH_LABELS[item.status]}`,
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
        { x: 13, y: 41, class: "node-english", lang: "en" },
        item.englishLabel,
      ),
      svgElement(
        "text",
        { x: 13, y: 58, class: "node-subtitle" },
        item.subtitle,
      ),
      svgElement("circle", { cx: 17, cy: 74, r: 3, class: "node-dot" }),
      svgElement(
        "text",
        { x: 27, y: 78, class: "node-state" },
        HEALTH_LABELS[item.status],
      ),
    );
    const choose = () => {
      selected = item.id;
      renderGraph(readSnapshot());
      renderInspector(readSnapshot());
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
  for (const transfer of currentMotionPlan.transfers) {
    const from = byId.get(transfer.from),
      to = byId.get(transfer.to);
    const sx = from.x + 90,
      sy = from.y + 44,
      tx = to.x + 90,
      ty = to.y + 44;
    const path = `M ${sx} ${sy} C ${sx + (tx - sx) * 0.35} ${sy - 100}, ${tx - (tx - sx) * 0.35} ${ty - 100}, ${tx} ${ty}`;
    svg.append(
      svgElement("path", {
        d: path,
        class: `transfer-path ${transfer.tone}`,
        "data-transfer-path": transfer.id,
      }),
    );
    const chip = svgElement("g", {
      class: `transfer-chip ${transfer.tone}`,
      "data-transfer": transfer.id,
      "pointer-events": "none",
    });
    chip.append(
      svgElement("rect", { width: 156, height: 46, rx: 10 }),
      svgElement(
        "text",
        { x: 78, y: 20, "text-anchor": "middle" },
        transfer.label,
      ),
      svgElement(
        "text",
        {
          x: 78,
          y: 36,
          "text-anchor": "middle",
          class: "transfer-english",
          lang: "en",
        },
        transfer.englishLabel,
      ),
    );
    svg.append(chip);
  }
  $("motion-caption").textContent = liveMode ? "실제 로컬 자원 관측 · 움직임은 논리적 배치 표시이며 물리적 이동을 뜻하지 않습니다." : currentMotionPlan.caption;
  motion.transition(currentMotionPlan.positions, {
    identity: `${runVersion}:${session.scenario}:${currentPhase(session)}`,
    duration: 1400,
    immediate: reducedMotion.matches,
  });
  setMotionPaused(motionPaused);
}
function renderInspector(view) {
  const root = $("node-inspector"),
    item = view.nodes.find((node) => node.id === selected);
  root.replaceChildren(
    element("p", "COMPONENT INSPECTOR", "eyebrow"),
    element("h3", item.label),
    element("p", item.englishLabel, "inspector-english"),
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
  if (liveMode) {
    root.append(element("h4", "실제 Kubernetes 관측"));
    for (const resource of item.resources || []) {
      root.append(element("p", `${resource.name} · ${resource.ready ? "Ready" : resource.phase}`));
      root.append(element("small", `Pod UID: ${resource.uid}`));
      for (const image of resource.images || []) root.append(element("p", image.image_id || "imageID 미확인", "inspector-footnote"));
    }
    const observed = runtimeStatus()?.observation;
    root.append(element("p", observed?.observed_at ? `관측 시각: ${new Date(observed.observed_at).toLocaleTimeString("ko-KR")}` : "실제 관측을 기다립니다.", "inspector-footnote"));
    const relevant = session.checks || [];
    for (const check of relevant) root.append(element("p", `${check.passed ? "PASS" : "BLOCK"} · ${check.name}`, check.passed ? "inspector-footnote" : "inspector-warning"));
  }
  root.append(element("h4", "연결 상태"));
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
      "선택한 구성 요소의 연결과 이번 대응 범위를 표시합니다.",
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
        ? "사전 승인 범위 확인"
        : "이 대응 범위를 승인할까요?",
    ),
    element("p", spec.action),
    element(
      "small",
      "대상과 동작을 확인한 뒤 승인하세요. 시간이 지나도 자동으로 승인되지 않습니다.",
    ),
  );
  const button = element("button", "승인 명령 채우기", "button primary");
  button.type = "button";
  button.id = "approve";
  button.onclick = () => {
    const input = $("injection-command");
    input.value = "response approve";
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.focus();
  };
  root.append(button);
}
function render() {
  const spec = definition(session.scenario),
    view = readSnapshot();
  renderScenarios();
  $("scenario-title").textContent = liveMode && spec.id === "migrate" ? "로컬 출발지 → 이 Mac 온프렘 이전" : spec.title;
  $("scenario-english").textContent = liveMode && spec.id === "migrate" ? "Local Source to On-Premises Migration" : spec.englishTitle;
  $("scenario-group").textContent = spec.group;
  $("scenario-description").textContent = liveMode ? "이 Mac의 전용 앱·PostgreSQL에 실제 명령을 적용합니다. 결과는 서버의 실행 기록과 관측으로 확인합니다." : spec.summary;
  $("stat-phase").textContent = liveMode && !runtimeStatus() ? "실제 연결 확인 중" : PHASE_LABELS[currentPhase(session)];
  $("stat-scenario").textContent = spec.title;
  $("stat-availability").textContent = view.availability;
  $("stat-isolation").textContent =
    `${view.counters.isolated}개 / ${view.counters.cut}개`;
  $("stat-route").textContent = view.route;
  $("stat-writer").textContent = `writer: ${view.writer}`;
  $("phase-track").dataset.mode = session.recovery ? "recovery" : "response";
  const phases = session.recovery
    ? ["recovery_checking", "recovery_restoring", "recovered"]
    : PHASES;
  $("phase-track").replaceChildren(
    ...phases.map((phase, i) => {
      const reached = session.history.some((event) => event.phase === phase);
      const item = element(
        "span",
        undefined,
        `phase-item ${reached ? "reached" : ""} ${phase === currentPhase(session) ? "current" : ""}`,
      );
      item.append(
        element("b", String(i + 1)),
        element("span", PHASE_LABELS[phase]),
      );
      if (phase === currentPhase(session))
        item.setAttribute("aria-current", "step");
      return item;
    }),
  );
  $("outcome").disabled = session.phase !== "normal";
  $("recovery-outcome").disabled = !recoveryAvailable(session);
  $("preapproved").disabled = liveMode || !spec.policy || session.phase !== "normal";
  $("preapproved").checked = session.preapproved;
  $("policy-description").textContent = spec.policy
    ? "이 유형의 범위만 미리 허용합니다. 시작 전 선택할 수 있습니다."
    : "이 유형은 단계별 승인을 유지합니다.";
  $("scope-description").textContent = liveMode ? "전용 로컬 RKE2 시험 앱입니다. 팀 운영 승인·실제 AWS 이전·자동 사이버공격 탐지와 구분합니다." : spec.result;
  const facts = [
    [
      "대상",
      spec.targets
        .map((id) => view.nodes.find((node) => node.id === id).label)
        .join(" · "),
    ],
    [
      "결과 확인",
      session.recovery ? "원본 응답·접근 정책·업무 연결 재검증" : spec.verify,
    ],
    ["사고 보류", view.hold ? "유지 · 일반 승인으로 해제하지 않음" : "미발생"],
    ["기록 범위", "현재 선택한 대응 흐름"],
  ];
  $("scope-facts").replaceChildren(
    ...facts.flatMap(([label, value]) => [
      element("dt", label),
      element("dd", value),
    ]),
  );
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
      row.append(text, element("small", "", "event-provenance"));
      return row;
    }),
  );
  renderApproval();
  injectionConsole.update(session, runVersion);
  renderGraph(view);
  renderInspector(view);
}
$("outcome").onchange = () => reset();
$("preapproved").onchange = () => reset();
$("motion-toggle").onclick = () => setMotionPaused(!motionPaused);
$("zoom-in").onclick = () => {
  zoom = Math.min(2, zoom + 0.2);
  renderGraph(readSnapshot());
};
$("zoom-out").onclick = () => {
  zoom = Math.max(1, zoom - 0.2);
  renderGraph(readSnapshot());
};
$("zoom-fit").onclick = () => {
  zoom = 1;
  renderGraph(readSnapshot());
};
$("export").onclick = () => {
  const payload = liveMode ? runtimeStatus() : {
    kind: "sova.workload-response.mock.v1",
    provenance: "mock",
    actual_execution: false,
    scenario: session.scenario,
    session,
    result: readSnapshot(),
    note: "화면 재생 기록이며 운영 판정이나 실행 권한을 부여하지 않습니다.",
  };
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
  );
  const link = element("a");
  link.href = url;
  link.download = `sova-response-${session.scenario}.json`;
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
    setMotionPaused(true);
    render();
  }
});
reducedMotion.addEventListener("change", () => {
  if (reducedMotion.matches) motion.finish();
  setMotionPaused(motionPaused);
});
const injectionConsole = mountInjectionConsole({
  getSession: () => session,
  getSnapshot: () => readSnapshot(),
  onCommand: async (raw) => {
    if (liveMode) {
      await runtimeCommand(raw);
      return;
    }
    const result = executeCommand(session, raw, {
      recoveryOutcome: $("recovery-outcome").value,
      outcome: $("outcome").value,
    });
    if (result.command.kind === "error") return;
    if (result.command.kind === "reset") {
      reset();
      return;
    }
    if (result.session === session) return;
    session = result.session;
    setMotionPaused(false);
    render();
  },
});
if (liveMode) {
  document.querySelector(".injection-submit").disabled = true;
  document.getElementById("injection-command").disabled = true;
  const appLink = element("a", "실제 앱 보기", "button secondary");
  appLink.href = "/app/";
  appLink.target = "_blank";
  appLink.rel = "noopener";
  document.querySelector(".topbar-right").prepend(appLink);
  document.querySelector(".header-note").textContent = "이 Mac · 실제 RKE2 연결";
  document.querySelector(".panel-intro").textContent = "완료 후 response reset으로 복귀한 뒤 유형을 바꿉니다.";
  connectRuntime(value => {
    const changed = session.run_id !== value.session.run_id;
    session = value.session;
    if (changed) { runVersion++; motion.clear(); }
    if (session.recovery?.phase === "recovered") session.recovery.outcome = "pass";
    render();
    const disabled = value.busy || !value.observation?.current;
    document.querySelector(".injection-submit").disabled = disabled;
    document.getElementById("injection-command").disabled = disabled;
    document.querySelector(".header-note").textContent = value.busy ? "실제 명령 처리 중" : "이 Mac · 실제 RKE2 관측";
  }, showError);
}
mountSidebar();
mountStudioView();
window.addEventListener("pagehide", () => {
  motion.clear();
});
render();
