import { createWorkloadRenderer } from "/console/workload-motion.js";
import { mountWorkspace } from "/__trial/workspace_navigation.js";
import {
  workloadGraph,
  projectedWorkload,
  stageLabels,
  responseLabels,
} from "/console/workload-model.js";
const el = (tag, text, cls) => {
  const n = document.createElement(tag);
  if (text !== undefined) n.textContent = text;
  if (cls) n.className = cls;
  return n;
};
const css = el("link");
css.rel = "stylesheet";
css.href = "/__trial/style.css";
document.head.append(css);
const workspaceCss = el("link");
workspaceCss.rel = "stylesheet";
workspaceCss.href = "/__trial/workspace_navigation.css";
document.head.append(workspaceCss);
const panel = el("section", undefined, "terminal-trial");
panel.id = "terminal-response-workspace";
panel.append(
  el("p", "LIVE WORKLOAD RESPONSE", "eyebrow"),
  el("h3", "실제 부분 격리 · 기존 연결 종료 · 재검증 · 원본 복귀"),
  el(
    "p",
    "같은 온프렘의 새 시험 namespace에서만 실행합니다. 아래 AWS·온프렘 운영 설정 지도와 시험 대상을 구분합니다.",
    "muted",
  ),
);
const phase = el("p", "접속 확인 중", "terminal-phase");
phase.setAttribute("role", "status");
const consentLabel = el("label", undefined, "terminal-consent"),
  consent = el("input");
consent.type = "checkbox";
consentLabel.append(
  consent,
  document.createTextNode(
    "전용 시험 자원 생성 또는 표시된 대응 계획의 격리·대체 전환을 승인합니다. 제품 T10 승인이 아닌 개인 시험 승인입니다.",
  ),
);
const buttons = el("div", undefined, "terminal-actions"),
  prepare = el("button", "1. 시험 준비"),
  respond = el("button", "3. 관측한 대응 계획 승인·실행"),
  stop = el("button", "시험 종료·자원 정리");
for (const b of [prepare, respond, stop]) b.type = "button";
buttons.append(prepare, respond, stop);
const command = el(
    "code",
    "시험 준비 후 터미널 명령이 표시됩니다.",
    "terminal-command",
  ),
  copy = el("button", "명령 복사");
copy.type = "button";
const receipt = el(
  "pre",
  "터미널 요청과 실제 403 감사 기록을 기다립니다.",
  "terminal-receipt",
);
const feedback = el("p", "", "muted");
feedback.setAttribute("role", "status");
const approvalScope = el("details"),
  approvalDetails = el("pre");
approvalScope.append(
  el("summary", "승인할 변경 범위·이미지·기한"),
  approvalDetails,
);
const grid = el("div", undefined, "response-grid"),
  canvas = el("div", undefined, "response-canvas"),
  inspect = el("aside", undefined, "response-inspector");
const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
svg.setAttribute("role", "img");
svg.setAttribute("aria-label", "실제 전용 워크로드 격리·대체 지도");
canvas.append(svg);
grid.append(canvas, inspect);
const stages = el("ol", undefined, "terminal-stages");
panel.append(
  phase,
  consentLabel,
  approvalScope,
  buttons,
  el("h4", "2. 터미널에서 직접 접근 시도"),
  command,
  copy,
  receipt,
  feedback,
  grid,
  stages,
);
document.querySelector("#response-workspace").prepend(panel);
const workspace = mountWorkspace({ trialPanel: panel });
let status = null,
  raw = null,
  selected = new Set(),
  busy = false,
  stream = null;
const renderer = createWorkloadRenderer(svg, {
  onSelect: (id) => {
    selected = new Set([id]);
    draw();
  },
});
const labels = {
  awaiting_respond: "선택한 구성 요소 격리·fencing·대체 기동 승인 대기",
  awaiting_recheck: "대체 검증 실패 · 경로 유지 · 별도 재검증 승인 대기",
  awaiting_return: "대체 경로 확인 · 새 원본 검증·복귀 승인 대기",
  idle: "시험 준비 전",
  preparing: "실제 자원 준비 중",
  ready: "정상 연결 확인 · 터미널 시도 대기",
  awaiting_approval: "실제 403·행동 주체·감사 대조 완료 · 사람 승인 대기",
  responding: "승인된 격리·대체 검증 진행 중",
  complete: "실제 재검증·새 원본 복귀 확인 · 사건 보류 유지",
  ended: "시험 종료 · 자원 정리 확인",
  stopping: "정리 중",
  attention: "실행 또는 정리 결과 확인 필요",
  connection_failed: "개인 온프렘 접속 확인 필요",
};
function draw() {
  panel.dataset.phase = status?.phase ?? "unavailable";
  phase.textContent =
    (labels[status?.phase] ?? "현재 시험 상태 미확인") +
    (status?.remaining_seconds > 0
      ? ` · 남은 ${status.remaining_seconds}초`
      : "");
  respond.textContent =
    status?.pending_kind === "recheck"
      ? "4. 실패 원인 해소·재검증·대체 전환 승인"
      : status?.pending_kind === "return"
        ? "5. 새 원본 검증·경로 복귀 별도 승인"
        : "3. 선택 범위 격리·기존 연결 종료 승인";
  approvalDetails.textContent = status?.approval_scope
    ? JSON.stringify(status.approval_scope, null, 2)
    : "시험 준비 후 정확한 선택 범위·계획이 표시됩니다.";
  prepare.disabled = busy || !consent.checked || !status?.can_prepare;
  respond.disabled = busy || !consent.checked || !status?.can_respond;
  stop.disabled = busy || !status?.can_stop;
  command.textContent =
    status?.terminal_command ?? "개인 세션을 확인해 주세요.";
  if (status?.attack) {
    const a = status.attack;
    receipt.textContent = `실제 요청 ID: ${a.nonce}\n내부 보호 API: HTTP ${a.upstream_status}\n행동 주체 Pod UID: ${a.actor_pod_uid}\nPod UID/IP 대조: ${a.actor_identity_verified ? "확인" : "미확인"}\n독립 감사 대조: ${a.independent_audit_verified ? "확인" : "미확인"}`;
  } else receipt.textContent = "터미널 요청과 실제 403 감사 기록을 기다립니다.";
  let view = null;
  try {
    if (raw) view = projectedWorkload(workloadGraph(raw), Date.now());
  } catch {
    raw = null;
  }
  renderer.draw(view, { selected });
  workspace.updateTrial(status, view);
  for (const label of svg.querySelectorAll(".response-lane-label")) {
    if (label.textContent === "출발 환경")
      label.textContent = "격리 대상 · 전용 시험";
    if (label.textContent === "대체 실행 환경")
      label.textContent = "대체 실행 · 같은 온프렘";
  }
  inspect.replaceChildren(el("h4", "실행·검증 근거"));
  const node = view?.nodes.find((n) => selected.has(n.id));
  if (node) {
    inspect.append(
      el("strong", node.label),
      el("p", node.detail),
      el("p", "실제 자원 UID: " + node.resource_uid),
    );
    for (const proof of view.evidence.filter((e) => e.resource_id === node.id))
      inspect.append(el("p", proof.summary));
  } else
    inspect.append(
      el("p", "대상 자원을 선택하면 실제 격리·HTTP 응답 근거를 확인합니다."),
    );
  stages.replaceChildren();
  for (const r of view?.responses ?? [])
    stages.append(
      el(
        "li",
        `${stageLabels[r.stage] ?? r.stage} · ${responseLabels[r.status] ?? r.status}`,
      ),
    );
}
async function act(action) {
  if (busy || !status) return;
  busy = true;
  draw();
  try {
    const response = await fetch("/__trial/control", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        "X-Sova-Trial": status.csrf,
      },
      body: JSON.stringify({
        action,
        request_id: crypto.randomUUID().replaceAll("-", ""),
        session_id: status.session_id,
        plan_digest: status.plan_digest,
        approved: action === "stop" || consent.checked,
      }),
      signal: AbortSignal.timeout(15000),
    });
    if (response.status !== 202)
      throw Error("요청을 확정하지 못했습니다. 자동 재시도하지 않습니다.");
    feedback.textContent = "요청 접수 · 실제 실행 결과를 기다립니다.";
    consent.checked = false;
  } catch (e) {
    feedback.textContent = e.message;
  } finally {
    busy = false;
    await poll();
  }
}
prepare.onclick = () => act("prepare");
respond.onclick = () => act("respond");
stop.onclick = () => act("stop");
consent.onchange = draw;
copy.onclick = async () => {
  try {
    await navigator.clipboard.writeText(command.textContent);
    feedback.textContent = "터미널에 붙여 넣을 명령을 복사했습니다.";
  } catch {
    feedback.textContent = "표시된 명령을 직접 복사해 주세요.";
  }
};
async function poll() {
  try {
    const r = await fetch("/__trial/status", {
      credentials: "same-origin",
      cache: "no-store",
      signal: AbortSignal.timeout(6000),
    });
    if (!r.ok) throw Error("status");
    const next = await r.json();
    if (next.qualification_only !== true || next.authorizes_execution !== false)
      throw Error("scope");
    if (
      status?.plan_digest !== next.plan_digest ||
      status?.session_id !== next.session_id
    )
      consent.checked = false;
    status = next;
    if (status.session_id && status.plan_id) {
      const f = await fetch("/__trial/feed", {
        credentials: "same-origin",
        cache: "no-store",
        signal: AbortSignal.timeout(6000),
      });
      if (!f.ok) raw = null;
      else {
        const value = await f.json();
        if (
          value.qualification_only !== true ||
          value.plan_connected !== false ||
          value.authorizes_execution !== false ||
          value.session_id !== status.session_id
        )
          throw Error("feed");
        const doc = value.document;
        workloadGraph(doc);
        if (stream !== doc.stream_id) {
          renderer.reset();
          selected.clear();
          stream = doc.stream_id;
        }
        if (
          raw &&
          raw.stream_id === doc.stream_id &&
          doc.revision < raw.revision
        )
          throw Error("old revision");
        raw = doc;
      }
    } else raw = null;
  } catch {
    status = null;
    raw = null;
    renderer.reset();
    selected.clear();
  }
  draw();
}
poll();
setInterval(poll, 3000);
setInterval(draw, 1000);
window.addEventListener("pagehide", () => renderer.reset());
