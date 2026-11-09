import {
  definition,
  PHASE_LABELS,
  HEALTH_LABELS,
  snapshot,
  currentPhase,
  recoveryAvailable,
} from "./model.mjs";
import { injectionCommand, parseCommand, nextCommand } from "./commands.mjs";

export function mountInjectionConsole({
  getSession,
  onInject,
  onApprove,
  onPause,
  onResume,
  onRecover,
}) {
  const input = document.getElementById("injection-command");
  const output = document.getElementById("injection-output");
  const feedback = document.getElementById("injection-feedback");
  const example = document.getElementById("injection-example");
  let run = null,
    seen = 0,
    context = null,
    draft = false,
    playing = false;
  input.addEventListener("input", () => {
    draft = true;
  });
  function line(kind, message) {
    const row = document.createElement("div");
    row.className = `console-line ${kind}`;
    const prefix = document.createElement("span");
    prefix.className = "console-prefix";
    prefix.textContent =
      kind === "command" ? "sova >" : kind === "error" ? "!" : "›";
    const text = document.createElement("span");
    text.textContent = String(message).slice(0, 500);
    row.append(prefix, text);
    output.append(row);
    while (output.childElementCount > 80) output.firstElementChild.remove();
    output.scrollTop = output.scrollHeight;
  }
  function execute(raw) {
    const session = getSession();
    const command = parseCommand(raw, session);
    line("command", raw.trim().slice(0, 256));
    feedback.textContent = "";
    input.removeAttribute("aria-invalid");
    if (command.kind === "error") {
      line("error", command.message);
      feedback.textContent = command.message;
      input.setAttribute("aria-invalid", "true");
      return;
    }
    draft = false;
    if (command.kind === "clear") {
      output.replaceChildren();
      return;
    }
    if (command.kind === "help") {
      line("info", `주입: ${injectionCommand(session.scenario)}`);
      line(
        "info",
        "workload status: 현재 대응 상태와 구성 요소 / incident inspect: 근거·대상·계획",
      );
      line(
        "info",
        "response approve: 승인 후 자동 진행 / response watch: 현재 흐름 관찰",
      );
      line(
        "info",
        "response pause / response resume: 진행 일시정지·재개 (승인 생략 불가)",
      );
      line(
        "info",
        "recovery start: 격리 완료 후 원본 재검증·복귀 요청 / clear: 콘솔 기록 지우기",
      );
      return;
    }
    if (["status", "workload_status", "watch"].includes(command.kind)) {
      const view = snapshot(session);
      line(
        "info",
        `현재 대응 상태: ${definition(session.scenario).title} · ${PHASE_LABELS[currentPhase(session)]} · 승인 ${session.approved ? "확인" : "대기"}`,
      );
      line(
        "info",
        `경로 ${view.route} · writer ${view.writer} · 격리 ${view.counters.isolated} · 차단 연결 ${view.counters.cut} · 사고 보류 ${view.hold ? "유지" : "없음"}`,
      );
      if (command.kind === "workload_status")
        for (const node of view.nodes)
          line(
            "info",
            `${node.id} · ${node.label} · ${HEALTH_LABELS[node.status]}`,
          );
      if (command.kind === "watch") {
        line(
          "info",
          "이후 단계 결과는 이 콘솔에 계속 표시합니다. 관찰 요청은 승인이나 실행을 시작하지 않습니다.",
        );
        for (const event of session.history.slice(-3))
          line("event", `[${PHASE_LABELS[event.phase]}] ${event.message}`);
      }
      return;
    }
    if (command.kind === "incident_inspect") {
      const spec = definition(session.scenario);
      if (session.phase === "normal") {
        line("info", "현재 주입된 이상이 없습니다.");
        return;
      }
      line("info", `근거: ${spec.signal}`);
      line("info", `대상: ${spec.targets.join(", ")} · 계획: ${spec.action}`);
      line("info", `검증 기준: ${spec.verify}`);
      line(
        "info",
        `승인 방식: ${session.preapproved ? "선택 범위 사전 승인" : "대응별 명시 승인"} · 사고 보류 ${snapshot(session).hold ? "유지" : "없음"}`,
      );
      return;
    }
    if (command.kind === "approve") {
      line(
        "accepted",
        "선택 대상·대응 범위 승인 접수 · 실행과 검증을 자동 진행합니다.",
      );
      onApprove();
      return;
    }
    if (command.kind === "pause") {
      onPause();
      line(
        "info",
        "진행을 일시정지했습니다. 승인·격리·연결 상태는 유지합니다.",
      );
      return;
    }
    if (command.kind === "resume") {
      onResume();
      line("info", "현재 단계에서 진행을 재개합니다.");
      return;
    }
    if (command.kind === "recover") {
      line(
        "accepted",
        "선택 대상의 원본 재검증·복귀 요청 접수 · 검증 전에는 격리를 유지합니다.",
      );
      onRecover();
      return;
    }
    if (command.kind !== "inject") {
      line("error", "처리할 수 없는 명령입니다.");
      return;
    }
    line(
      "accepted",
      `이벤트 접수: ${command.event} · 대상 ${command.targets.join(", ")}`,
    );
    onInject(command);
  }
  document.getElementById("injection-form").onsubmit = (event) => {
    event.preventDefault();
    execute(input.value);
  };
  example.onclick = () => {
    input.value = nextCommand(getSession(), { playing });
    draft = false;
    input.focus();
    input.removeAttribute("aria-invalid");
    feedback.textContent = "";
  };
  document.getElementById("injection-clear").onclick = () =>
    output.replaceChildren();
  for (const button of document.querySelectorAll("[data-console-command]"))
    button.onclick = () => {
      input.value = button.dataset.consoleCommand;
      execute(input.value);
    };
  return {
    update(session, version, runtime = {}) {
      playing = runtime.playing ?? false;
      if (run !== version) {
        run = version;
        seen = 0;
        output.replaceChildren();
        feedback.textContent = "";
        context = null;
        draft = false;
        input.removeAttribute("aria-invalid");
      }
      const next = nextCommand(session, { playing });
      const nextContext = `${version}:${currentPhase(session)}:${playing}`;
      if (context !== nextContext) {
        context = nextContext;
        if (!draft || !input.value.trim()) {
          input.value = next;
          input.removeAttribute("aria-invalid");
          feedback.textContent = "";
          draft = false;
        }
      }
      input.placeholder = next;
      example.textContent = "다음 명령 채우기";
      example.title = next;
      for (const event of session.history.slice(seen)) {
        line(
          ["held", "recovery_held"].includes(event.phase)
            ? "error"
            : ["complete", "recovered"].includes(event.phase)
              ? "accepted"
              : "event",
          `[${PHASE_LABELS[event.phase]}] ${event.message}`,
        );
      }
      seen = session.history.length;
      const label = document.getElementById("injection-state");
      label.textContent = PHASE_LABELS[currentPhase(session)];
      label.dataset.phase = currentPhase(session);
      document.querySelector(
        '[data-console-command="response approve"]',
      ).disabled =
        session.phase !== "awaiting_approval" ||
        session.approved ||
        Boolean(session.recovery);
      document.querySelector(
        '[data-console-command="recovery start"]',
      ).disabled = !recoveryAvailable(session);
      example.disabled = false;
      document.getElementById("injection-targets").textContent = definition(
        session.scenario,
      ).targets.join(" · ");
    },
  };
}
