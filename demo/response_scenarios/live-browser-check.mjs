// Real-Chrome check of the live console against a running local runtime.
// Usage: node live-browser-check.mjs <devtools-port> <console-url-with-token> <approve-command> <out-dir>
// The approve command is run between hold and release; it prints an approval id.
// Uses only the DevTools protocol of an isolated headless Chrome; no npm packages.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const [port, consoleUrl, approveCommand, output] = process.argv.slice(2);
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
async function until(predicate, label, seconds = 60) {
  const end = Date.now() + seconds * 1000;
  while (Date.now() < end) {
    if (await predicate()) return;
    await new Promise((r) => setTimeout(r, 500));
  }
  const terminal = await evaluate(`[...document.querySelectorAll("#injection-output > *")].slice(-4).map(e => e.textContent).join(" | ")`);
  throw new Error("timed out: " + label + " · terminal: " + terminal + " · feedback: " + (await text("injection-feedback")));
}
async function command(raw) {
  await evaluate(`(() => { const i = document.getElementById("injection-command"); i.value = ${JSON.stringify(raw)}; i.dispatchEvent(new Event("input")); document.getElementById("injection-form").requestSubmit(); })()`);
}
async function shot(name) {
  const { data } = await call("Page.captureScreenshot", { format: "png" });
  await writeFile(join(output, name + ".png"), Buffer.from(data, "base64"));
}

await call("Runtime.enable");
await call("Page.enable");
await call("Emulation.setDeviceMetricsOverride", { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false });
await call("Page.navigate", { url: consoleUrl });
await until(async () => (await text("stat-phase")) && (await text("stat-phase")) !== "실제 연결 확인 중", "live state");
const steps = {
  live_phase: await text("stat-phase"),
  scope: (await text("scope-description")).slice(0, 240),
  description: (await text("scenario-description")).slice(0, 160),
  zones: await evaluate(`[...document.querySelectorAll(".environment-title")].map(e => e.textContent)`),
};
assert.equal(await evaluate(`document.body.dataset.runtime`), "local-rke2");
assert.equal(await evaluate("location.hash"), "", "one-time token must leave the address bar");
await shot("01-live");

const terminalHas = (needle) =>
  evaluate(`[...document.querySelectorAll("#injection-output > *")].some(e => e.textContent.includes(${JSON.stringify(needle)}))`);
steps.already_held = (await text("stat-phase")).includes("보안 보류");
if (!steps.already_held) await command("security hold browser-drill");
await until(async () => (await text("stat-phase")).includes("보안 보류"), "security hold shown");
steps.hold_phase = await text("stat-phase");
await command("response reset");
await until(() => terminalHas("보안 보류 중입니다"), "reset refused in the console", 10);
steps.reset_refused = true;
await shot("02-hold");

const approval = execFileSync("/bin/zsh", ["-c", approveCommand], { encoding: "utf8" }).trim().split("\n").pop();
assert.match(approval, /^rel-[0-9a-f]{12}$/);
await command("security release " + approval);
await until(async () => !(await text("stat-phase")).includes("보안 보류"), "released");
steps.released_phase = await text("stat-phase");
await shot("03-released");

assert.deepEqual(exceptions, [], "no uncaught page exceptions");
await writeFile(join(output, "result.json"), JSON.stringify({ steps, exceptions }, null, 2));
console.log(JSON.stringify({ passed: true, steps }));
socket.close();
