// Real-Chrome check that the live terminal drives the runner end to end.
// Usage: node live-terminal-check.mjs <devtools-port> <console-url-with-token> <scenario> <out-dir>
// Selects the scenario, runs the read-only commands, then submits only the
// console's own suggested next command (the example button) until the
// response completes, and records each command with the phase it reached.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [port, consoleUrl, scenario, output] = process.argv.slice(2);
await mkdir(output, { recursive: true, mode: 0o700 });
const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: "PUT" })).json();
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});
let serial = 0;
const pending = new Map(), exceptions = [];
socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(String(data));
  if (message.id && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    message.error ? reject(new Error(message.error.message)) : resolve(message.result);
  }
  if (message.method === "Runtime.exceptionThrown") exceptions.push(message.params.exceptionDetails.text);
});
const call = (method, params = {}) =>
  new Promise((resolve, reject) => {
    const id = ++serial;
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params }));
  });
const evaluate = async (expression) =>
  (await call("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true })).result.value;
const text = (id) => evaluate(`document.getElementById(${JSON.stringify(id)})?.textContent ?? ""`);
const lines = () => evaluate(`[...document.querySelectorAll("#injection-output > *")].map(e => e.textContent)`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(predicate, label, seconds = 300) {
  const end = Date.now() + seconds * 1000;
  while (Date.now() < end) {
    if (await predicate()) return;
    await sleep(500);
  }
  throw new Error("timed out: " + label + " · last lines: " + (await lines()).slice(-3).join(" | "));
}
async function submit(raw) {
  await evaluate(`(() => { const i = document.getElementById("injection-command"); i.value = ${JSON.stringify(raw)}; i.dispatchEvent(new Event("input")); document.getElementById("injection-form").requestSubmit(); })()`);
}

await call("Runtime.enable");
await call("Page.enable");
await call("Page.navigate", { url: consoleUrl });
await until(async () => (await text("stat-phase")) && (await text("stat-phase")) !== "실제 연결 확인 중", "live state", 60);

if ((await text("stat-phase")) !== "정상 흐름") {
  await submit("response reset");
  await until(async () => (await text("stat-phase")) === "정상 흐름", "reset to normal");
}
await evaluate(`document.querySelector('[data-scenario=${JSON.stringify(scenario)}]').click()`);
await until(async () => (await evaluate(`document.querySelector('[data-scenario=${JSON.stringify(scenario)}]').classList.contains("active") || document.querySelector('[data-scenario=${JSON.stringify(scenario)}]').getAttribute("aria-pressed") === "true"`)) || (await text("injection-command")) !== null, "scenario selected", 30);
await sleep(3000);

const readOnly = {};
for (const raw of ["help", "status", "workload status", "response watch", "incident inspect"]) {
  const before = (await lines()).length;
  await submit(raw);
  await sleep(700);
  const added = (await lines()).slice(before);
  readOnly[raw] = raw === "help" ? added.filter((l) => l.includes("security hold") || l.includes("exit drill")) : added.slice(0, 4);
  assert.ok(added.length >= 2, raw + " printed nothing");
  assert.ok(!added.some((l) => l.includes("처리할 수 없는 명령")), raw + " was not handled");
}

const transcript = [];
for (let step = 0; step < 14; step++) {
  const phase = await text("stat-phase");
  if (phase === "대응 완료") break;
  assert.ok(!phase.includes("보류"), "held at: " + phase);
  await evaluate(`document.getElementById("injection-example").click()`);
  const suggested = await evaluate(`document.getElementById("injection-command").value`);
  await evaluate(`document.getElementById("injection-form").requestSubmit()`);
  await until(async () => (await text("stat-phase")) !== phase || (await text("stat-phase")).includes("보류"), "phase after " + suggested);
  transcript.push({ command: suggested, phase: await text("stat-phase") });
}
assert.equal(await text("stat-phase"), "대응 완료", "response completed through the terminal");
const before = (await lines()).length;
await submit("incident inspect");
await sleep(700);
const inspect = (await lines()).slice(before);
assert.ok(inspect.some((l) => l.includes("계획(실제)")), "inspect shows the live plan");
assert.ok(inspect.some((l) => l.includes("서명 증거(verify): PASS")), "inspect shows signed evidence");
assert.ok(readOnly.help.length >= 1);
assert.deepEqual(exceptions, [], "no uncaught page exceptions");
const result = { scenario, readOnly, transcript, inspect, exceptions };
await writeFile(join(output, "terminal-result.json"), JSON.stringify(result, null, 2));
console.log(JSON.stringify(result));
socket.close();
