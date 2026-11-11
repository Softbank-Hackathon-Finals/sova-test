import {
  definition,
  PHASE_LABELS,
  HEALTH_LABELS,
  snapshot,
  currentPhase,
  recoveryAvailable,
} from "./model.mjs";
import { injectionCommand, parseCommand, nextCommand } from "./commands.mjs";

export function mountInjectionConsole({ getSession, onCommand, getSnapshot = snapshot }) {
  const input = document.getElementById("injection-command");
  const output = document.getElementById("injection-output");
  const feedback = document.getElementById("injection-feedback");
  const example = document.getElementById("injection-example");
  let run = null,
    seen = 0,
    context = null,
    draft = false;
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
        "response plan → response submit → response approve: 계획·승인 요청·승인 (각 한 단계)",
      );
      line(
        "info",
        "response verify → response finalize: 검증·판정 확정 / response watch: 조회만 수행",
      );
      line(
        "info",
        "recovery start → recovery verify → recovery finalize: 복귀 요청·재검증·복귀 확정",
      );
      line(
        "info",
        "response reset: 현재 유형 새 실행 / clear: 콘솔 표시만 지우기. 다음 단계는 명령 실행으로만 진행합니다.",
      );
      return;
    }
    if (["status", "workload_status", "watch"].includes(command.kind)) {
      const view = getSnapshot(session);
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
    if (
      [
        "inject",
        "plan",
        "submit",
        "approve",
        "verify",
        "finalize",
        "recover",
        "recovery_verify",
        "recovery_finalize",
        "reset",
        "security_hold",
        "security_release",
        "exit_drill",
      ].includes(command.kind)
    ) {
      if (command.kind === "security_hold")
        line("accepted", "보안 보류 요청 · 해제 전까지 초기화를 포함한 모든 변경을 거부합니다.");
      else if (command.kind === "security_release")
        line("accepted", "보류 해제 요청 · 서버가 별도 승인자의 서명과 현재 상태 결속을 확인합니다.");
      else if (command.kind === "exit_drill")
        line("accepted", "출발지 독립 시험 요청 · 출발지 경로를 끊고 목적지만으로 운영되는지 확인합니다.");
      else if (command.kind === "inject")
        line(
          "accepted",
          `이벤트 접수: ${command.event} · 대상 ${command.targets.join(", ")}`,
        );
      else
        line(
          "accepted",
          "명령 접수 · 현재 단계만 처리합니다. 다음 명령 실행 전까지 대기합니다.",
        );
      Promise.resolve(onCommand(raw)).catch(error => {
        line("error", error.message);
        feedback.textContent = error.message;
      });
      return;
    }
    line("error", "처리할 수 없는 명령입니다.");
  }
  document.getElementById("injection-form").onsubmit = (event) => {
    event.preventDefault();
    execute(input.value);
  };
  example.onclick = () => {
    input.value = nextCommand(getSession());
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
      draft = false;
      input.focus();
      input.removeAttribute("aria-invalid");
      feedback.textContent = "";
    };
  return {
    update(session, version) {
      if (run !== version) {
        run = version;
        seen = 0;
        output.replaceChildren();
        feedback.textContent = "";
        context = null;
        draft = false;
        input.removeAttribute("aria-invalid");
      }
      const next = nextCommand(session);
      const nextContext = `${version}:${currentPhase(session)}`;
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
