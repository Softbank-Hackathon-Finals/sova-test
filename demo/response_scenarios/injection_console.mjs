import { definition, PHASE_LABELS } from "./model.mjs";
import { injectionCommand, parseCommand } from "./commands.mjs";

export function mountInjectionConsole({ getSession, onInject }) {
  const input = document.getElementById("injection-command");
  const output = document.getElementById("injection-output");
  const feedback = document.getElementById("injection-feedback");
  const example = document.getElementById("injection-example");
  let run = null,
    seen = 0;
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
    if (command.kind === "clear") {
      output.replaceChildren();
      return;
    }
    if (command.kind === "help") {
      line("info", `주입: ${injectionCommand(session.scenario)}`);
      line("info", "status: 현재 대응 상태 / clear: 콘솔 기록 지우기");
      return;
    }
    if (command.kind === "status") {
      line(
        "info",
        `${definition(session.scenario).title} · ${PHASE_LABELS[session.phase]} · 승인 ${session.approved ? "확인" : "대기"}`,
      );
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
    input.value = injectionCommand(getSession().scenario);
    input.focus();
    input.removeAttribute("aria-invalid");
    feedback.textContent = "";
  };
  document.getElementById("injection-clear").onclick = () =>
    output.replaceChildren();
  return {
    update(session, version) {
      if (run !== version) {
        run = version;
        seen = 0;
        output.replaceChildren();
        feedback.textContent = "";
        input.value = injectionCommand(session.scenario);
        input.removeAttribute("aria-invalid");
      }
      for (const event of session.history.slice(seen)) {
        line(
          event.phase === "held"
            ? "error"
            : event.phase === "complete"
              ? "accepted"
              : "event",
          `[${PHASE_LABELS[event.phase]}] ${event.message}`,
        );
      }
      seen = session.history.length;
      const label = document.getElementById("injection-state");
      label.textContent = PHASE_LABELS[session.phase];
      label.dataset.phase = session.phase;
      example.disabled = session.phase !== "normal";
      document.getElementById("injection-targets").textContent = definition(
        session.scenario,
      ).targets.join(" · ");
    },
  };
}
