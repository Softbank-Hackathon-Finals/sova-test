// Optional real-Chrome checks. Uses an isolated local DevTools instance, no npm packages.
import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

const output = process.argv[2] || "/private/tmp/sova-response-browser-20261109";
await mkdir(output, { recursive: true, mode: 0o700 });
const target = await (
  await fetch("http://127.0.0.1:19232/json/new?about:blank", { method: "PUT" })
).json();
const socket = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => {
  socket.addEventListener("open", resolve, { once: true });
  socket.addEventListener("error", reject, { once: true });
});
let serial = 0;
const pending = new Map(),
  exceptions = [],
  requests = [],
  failures = [];
socket.addEventListener("message", ({ data }) => {
  const message = JSON.parse(String(data));
  if (message.id) {
    const entry = pending.get(message.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    pending.delete(message.id);
    if (message.error) entry.reject(new Error(message.error.message));
    else entry.resolve(message.result);
  }
  if (message.method === "Runtime.exceptionThrown")
    exceptions.push(message.params.exceptionDetails.text);
  if (message.method === "Network.requestWillBeSent")
    requests.push({
      url: message.params.request.url,
      method: message.params.request.method,
      type: message.params.type,
    });
  if (message.method === "Network.loadingFailed") failures.push(message.params);
});
function call(method, params = {}) {
  const id = ++serial;
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`CDP timeout: ${method}`));
    }, 12000);
    pending.set(id, { resolve, reject, timer });
    socket.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const result = await call("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  if (result.exceptionDetails)
    throw new Error(
      result.exceptionDetails.exception?.description ||
        "Browser evaluation failed",
    );
  return result.result.value;
}
const results = [];
async function check(name, run) {
  await run();
  results.push({ name, passed: true });
  console.log("PASS", name);
}
async function choose(id, outcome = "pass") {
  await evaluate(
    `document.querySelector('[data-scenario="${id}"]').click();document.getElementById('outcome').value=${JSON.stringify(outcome)};document.getElementById('outcome').dispatchEvent(new Event('change'));`,
  );
}
async function goTo(phase) {
  const path = {
    normal: null,
    detected: 0,
    planned: 1,
    awaiting_approval: 2,
    executing: 3,
    verifying: 4,
    complete: 5,
    held: 5,
  };
  const actions = [
    null,
    "response plan",
    "response submit",
    "response approve",
    "response verify",
    "response finalize",
  ];
  for (let i = 0; i < 7; i++) {
    const current = await evaluate(
      "document.getElementById('injection-state').dataset.phase",
    );
    if (current === phase) return;
    if (["complete", "held"].includes(current))
      throw new Error(`Stopped at ${current}, wanted ${phase}`);
    if (current === "normal")
      await evaluate(
        "document.getElementById('injection-form').requestSubmit()",
      );
    else await command(actions[path[current] + 1]);
  }
  throw new Error(`Failed to reach ${phase}`);
}
async function finish() {
  await goTo("complete");
}
const sleep = (ms) =>
  evaluate(`new Promise(resolve=>setTimeout(resolve,${ms}))`);
const phase = () =>
  evaluate("document.getElementById('injection-state').dataset.phase");
const inputValue = () =>
  evaluate("document.getElementById('injection-command').value");
async function command(value) {
  await evaluate(
    `document.getElementById('injection-command').value=${JSON.stringify(value)};document.getElementById('injection-form').requestSubmit()`,
  );
}
async function phaseIs(value, timeout = 3600) {
  return evaluate(
    `new Promise((resolve,reject)=>{const end=Date.now()+${timeout};const tick=()=>{const phase=document.getElementById('stat-phase').textContent;if(phase===${JSON.stringify(value)})resolve(phase);else if(Date.now()>end)reject(new Error('Expected phase '+${JSON.stringify(value)}+', got '+phase));else setTimeout(tick,40)};tick()})`,
  );
}
try {
  await call("Page.enable");
  await call("Runtime.enable");
  await call("Network.enable");
  await call("Emulation.setDeviceMetricsOverride", {
    width: 1600,
    height: 1100,
    deviceScaleFactor: 1,
    mobile: false,
  });
  await call("Page.navigate", { url: "http://127.0.0.1:18132/console/" });
  await evaluate(
    "new Promise((resolve,reject)=>{let n=0;const tick=()=>{if(document.querySelectorAll('[data-scenario]').length===9)resolve();else if(n++>80)reject(new Error('UI failed to mount'));else setTimeout(tick,50)};tick()})",
  );
  await check(
    "nine playbooks, fourteen bilingual resources and no visible playback controls",
    async () => {
      assert.equal(
        await evaluate("document.querySelectorAll('[data-node]').length"),
        14,
      );
      assert.equal(
        await evaluate(
          "document.querySelectorAll('.map-node .node-english').length",
        ),
        14,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('#next,#autoplay,#reset,#speed,#response-controls')",
        ),
        null,
      );
      assert.equal(
        await evaluate(
          "/목업|가상|모의|시뮬레|MOCK|SIMULAT/.test(document.body.innerText)",
        ),
        false,
      );
    },
  );
  await check(
    "each submitted command advances exactly one stage and elapsed time never advances it",
    async () => {
      await choose("segment");
      const expected = [
        ["detected", "response plan"],
        ["planned", "response submit"],
        ["awaiting_approval", "response approve"],
        ["executing", "response verify"],
        ["verifying", "response finalize"],
        ["complete", "recovery start"],
      ];
      for (const [index, [state, next]] of expected.entries()) {
        await evaluate(
          "document.getElementById('injection-form').requestSubmit()",
        );
        assert.equal(await phase(), state);
        assert.equal(await inputValue(), next);
        await sleep(index === 0 || index === 3 ? 2200 : 150);
        assert.equal(await phase(), state);
        await command("response watch");
        await command("incident inspect");
        await command("workload status");
        assert.equal(await phase(), state);
        await evaluate("document.getElementById('injection-example').click()");
        assert.equal(await inputValue(), next);
      }
    },
  );
  await check(
    "approval and quick action buttons only fill the CLI and cannot execute a stage",
    async () => {
      await choose("segment");
      await goTo("awaiting_approval");
      await evaluate("document.getElementById('approve').click()");
      assert.equal(await phase(), "awaiting_approval");
      assert.equal(await inputValue(), "response approve");
      await evaluate(
        "document.querySelector('[data-console-command=\"response approve\"]').click()",
      );
      await sleep(1200);
      assert.equal(await phase(), "awaiting_approval");
      await evaluate(
        "document.getElementById('injection-form').requestSubmit()",
      );
      assert.equal(await phase(), "executing");
      await command("response approve");
      assert.equal(await phase(), "executing");
      assert.equal(
        await evaluate(
          "document.getElementById('injection-command').getAttribute('aria-invalid')",
        ),
        "true",
      );
    },
  );
  await check(
    "wrong stage, old playback, out-of-scope and markup requests do not mutate or execute markup",
    async () => {
      await choose("segment");
      for (const raw of [
        "response approve",
        "response verify",
        "response finalize",
        "recovery start",
        "response resume",
        "response pause",
        "response plan --force",
        "inject lateral-movement --target api,worker,db",
        '<img src=x onerror="throw 1">',
        "constructor",
      ]) {
        await command(raw);
        assert.equal(await phase(), "normal");
        assert.equal(
          await evaluate(
            "document.getElementById('injection-command').getAttribute('aria-invalid')",
          ),
          "true",
        );
      }
      assert.equal(
        await evaluate(
          "document.querySelector('#injection-output img,#injection-output script')",
        ),
        null,
      );
    },
  );
  await check(
    "all nine scenarios explicitly finalize and failed or unknown results never promote the target",
    async () => {
      const ids = await evaluate(
        "Array.from(document.querySelectorAll('[data-scenario]')).map(n=>n.dataset.scenario)",
      );
      for (const id of ids)
        for (const result of ["pass", "fail", "unknown"]) {
          await choose(id, result);
          await goTo(result === "pass" ? "complete" : "held");
          assert.equal(await phase(), result === "pass" ? "complete" : "held");
          if (result !== "pass") {
            assert.equal(
              await evaluate(
                "document.getElementById('stat-route').textContent",
              ),
              "AWS 업무 API",
            );
            assert.notEqual(
              await evaluate(
                "document.getElementById('stat-writer').textContent",
              ),
              "writer: 목적지 DB",
            );
            await command("response finalize");
            assert.equal(await phase(), "held");
          }
        }
    },
  );
  await check(
    "preapproved scope still waits for explicit terminal confirmation",
    async () => {
      await choose("isolate");
      await evaluate("document.getElementById('preapproved').click()");
      await goTo("awaiting_approval");
      assert.equal(await inputValue(), "response approve");
      await sleep(2200);
      assert.equal(await phase(), "awaiting_approval");
      await command("response approve");
      assert.equal(await phase(), "executing");
      await evaluate(
        "document.querySelector('[data-scenario=migrate]').click()",
      );
      assert.equal(
        await evaluate("document.getElementById('preapproved').checked"),
        false,
      );
    },
  );
  await check(
    "recovery needs separate start, verify and finalize commands; time and animations never reconnect",
    async () => {
      await choose("segment");
      await finish();
      await evaluate(
        "document.querySelector('[data-console-command=\"recovery start\"]').click()",
      );
      assert.equal(await phase(), "complete");
      await evaluate(
        "document.getElementById('injection-form').requestSubmit()",
      );
      assert.equal(await phase(), "recovery_checking");
      assert.equal(await inputValue(), "recovery verify");
      await sleep(2200);
      assert.equal(await phase(), "recovery_checking");
      await command("recovery finalize");
      assert.equal(await phase(), "recovery_checking");
      await command("recovery verify");
      assert.equal(await phase(), "recovery_restoring");
      assert.equal(await inputValue(), "recovery finalize");
      await sleep(1800);
      assert.equal(await phase(), "recovery_restoring");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=ingress]').dataset.state",
        ),
        "cut",
      );
      await command("recovery finalize");
      assert.equal(await phase(), "recovered");
      assert.equal(await inputValue(), "workload status");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=ingress]').dataset.state",
        ),
        "flow",
      );
      assert.match(
        await evaluate(
          "document.getElementById('stat-availability').textContent",
        ),
        /사고 보류 유지/,
      );
    },
  );
  await check(
    "failed or uncertain original revalidation keeps containment and cannot be forced to finalize",
    async () => {
      for (const outcome of ["fail", "unknown"]) {
        await choose("segment");
        await finish();
        await evaluate(
          `document.getElementById('recovery-outcome').value=${JSON.stringify(outcome)}`,
        );
        await command("recovery start");
        await command("recovery verify");
        assert.equal(await phase(), "recovery_held");
        assert.equal(
          await evaluate(
            "document.querySelector('[data-edge=ingress]').dataset.state",
          ),
          "cut",
        );
        await evaluate(
          "document.getElementById('recovery-outcome').value='pass'",
        );
        await command("recovery finalize");
        await command("response approve");
        await command("recovery start");
        await sleep(250);
        assert.equal(await phase(), "recovery_held");
      }
    },
  );
  await check(
    "typed drafts survive redraws; explicit commands update suggestions and reset clears the old run",
    async () => {
      await choose("segment");
      await goTo("detected");
      await evaluate(
        "document.getElementById('injection-command').value='workload sta';document.getElementById('injection-command').dispatchEvent(new Event('input',{bubbles:true}));document.querySelector('[data-node=db]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}))",
      );
      assert.equal(await inputValue(), "workload sta");
      await evaluate("document.getElementById('injection-example').click()");
      assert.equal(await inputValue(), "response plan");
      await command("response reset");
      assert.equal(await phase(), "normal");
      assert.equal(
        await inputValue(),
        "inject lateral-movement --target api,worker",
      );
      assert.equal(
        await evaluate("document.getElementById('phase-track').dataset.mode"),
        "response",
      );
    },
  );
  await check(
    "isolation animation pauses and resumes without changing the execution phase",
    async () => {
      await choose("segment");
      await goTo("awaiting_approval");
      await command("response approve");
      await sleep(450);
      const y = await evaluate(
        "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
      );
      assert(y > 300 && y < 860, String(y));
      await evaluate("document.getElementById('motion-toggle').click()");
      const paused = await evaluate(
        "document.querySelector('[data-node=api]').getAttribute('transform')",
      );
      await sleep(400);
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').getAttribute('transform')",
        ),
        paused,
      );
      assert.equal(await phase(), "executing");
      await evaluate("document.getElementById('motion-toggle').click()");
      await sleep(1600);
      assert.equal(await phase(), "executing");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
        ),
        860,
      );
      assert.deepEqual(
        await evaluate(
          "Array.from(document.querySelectorAll('.map-node.isolated')).map(n=>n.dataset.node)",
        ),
        ["api", "worker"],
      );
    },
  );
  await check(
    "migration transfers animate but preserve source writer fencing and inactive target route until commands finalize",
    async () => {
      await choose("migrate");
      await goTo("awaiting_approval");
      await command("response approve");
      await sleep(300);
      assert.equal(
        await evaluate("document.querySelectorAll('[data-transfer]').length"),
        3,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=target-route]').dataset.state",
        ),
        "idle",
      );
      assert.match(
        await evaluate("document.getElementById('stat-writer').textContent"),
        /出|출발지 차단/,
      );
      await sleep(1700);
      assert.equal(await phase(), "executing");
      await command("response verify");
      assert.equal(await phase(), "verifying");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=target-route]').dataset.state",
        ),
        "idle",
      );
      await command("response finalize");
      assert.equal(await phase(), "complete");
      assert.equal(
        await evaluate("document.getElementById('stat-writer').textContent"),
        "writer: 목적지 DB",
      );
      await choose("egress");
      assert.equal(
        await evaluate("document.querySelectorAll('[data-transfer]').length"),
        0,
      );
    },
  );
  await check(
    "desktop sidebar expands content without changing the current response",
    async () => {
      await choose("segment");
      await goTo("detected");
      await evaluate(
        "if(document.body.dataset.sidebar!=='open')document.getElementById('sidebar-toggle').click()",
      );
      await sleep(350);
      const before = await evaluate(
        "document.querySelector('.main-shell').getBoundingClientRect().width",
      );
      await evaluate("document.getElementById('sidebar-toggle').click()");
      await sleep(350);
      assert(
        (await evaluate(
          "document.querySelector('.main-shell').getBoundingClientRect().width",
        )) >
          before + 190,
      );
      assert.equal(await phase(), "detected");
    },
  );
  await check(
    "focused layout keeps map, CLI and approval visible for all nine playbooks at four screen sizes",
    async () => {
      for (const [width, height] of [
        [1440, 900],
        [1366, 768],
        [1280, 800],
        [1180, 700],
      ]) {
        await call("Emulation.setDeviceMetricsOverride", {
          width,
          height,
          deviceScaleFactor: 1,
          mobile: false,
        });
        await evaluate(
          "if(document.body.dataset.studioView!=='focused')document.getElementById('studio-view-toggle').click()",
        );
        await sleep(350);
        const ids = await evaluate(
          "Array.from(document.querySelectorAll('[data-scenario]')).map(n=>n.dataset.scenario)",
        );
        for (const id of ids) {
          await choose(id);
          await goTo("awaiting_approval");
          const positions = await evaluate(
            "['phase-track','injection-form','map-viewport','approve'].map(id=>{const r=document.getElementById(id).getBoundingClientRect();return {id,left:r.left,top:r.top,right:r.right,bottom:r.bottom,height:r.height}})",
          );
          assert(
            positions.every(
              (r) =>
                r.left >= 0 &&
                r.top >= 0 &&
                r.right <= width + 1 &&
                r.bottom <= height + 1 &&
                r.height > 0,
            ),
            JSON.stringify({ width, height, positions }),
          );
          assert.equal(await phase(), "awaiting_approval");
          assert.equal(
            await evaluate(
              "document.documentElement.scrollHeight<=innerHeight+1&&document.documentElement.scrollWidth<=innerWidth+1",
            ),
            true,
          );
        }
      }
      await writeFile(
        join(output, "terminal-only-focused.png"),
        Buffer.from(
          (await call("Page.captureScreenshot", { format: "png" })).data,
          "base64",
        ),
      );
      await evaluate("document.getElementById('inspector-toggle').click()");
      assert.equal(
        await evaluate("document.getElementById('node-inspector').inert"),
        false,
      );
      await call("Input.dispatchKeyEvent", {
        type: "keyDown",
        key: "Escape",
        code: "Escape",
      });
      assert.equal(
        await evaluate("document.getElementById('node-inspector').inert"),
        true,
      );
    },
  );
  await check(
    "mobile drawer and reduced motion preserve terminal-only progression",
    async () => {
      await call("Emulation.setDeviceMetricsOverride", {
        width: 390,
        height: 844,
        deviceScaleFactor: 1,
        mobile: true,
      });
      await sleep(200);
      assert.equal(
        await evaluate("document.body.dataset.studioView"),
        "overview",
      );
      await evaluate("document.getElementById('sidebar-toggle').click()");
      await sleep(350);
      assert.equal(
        await evaluate("document.querySelector('.main-shell').inert"),
        true,
      );
      await call("Input.dispatchKeyEvent", {
        type: "keyDown",
        key: "Escape",
        code: "Escape",
      });
      await sleep(350);
      assert.equal(
        await evaluate("document.querySelector('.main-shell').inert"),
        false,
      );
      assert.equal(
        await evaluate("document.documentElement.scrollWidth<=innerWidth+1"),
        true,
      );
      await call("Emulation.setEmulatedMedia", {
        features: [{ name: "prefers-reduced-motion", value: "reduce" }],
      });
      await choose("segment");
      await goTo("executing");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
        ),
        860,
      );
      assert.equal(await phase(), "executing");
    },
  );
  await check(
    "no product API, external request, mutation or browser error",
    async () => {
      assert.deepEqual(exceptions, []);
      assert.deepEqual(failures, []);
      assert(
        requests.every(
          (r) =>
            r.method === "GET" &&
            new URL(r.url).origin === "http://127.0.0.1:18132" &&
            (new URL(r.url).pathname === "/console/" ||
              new URL(r.url).pathname.startsWith("/__mock/response/")),
        ),
        JSON.stringify(requests),
      );
    },
  );
  await writeFile(
    join(output, "results.json"),
    JSON.stringify(
      {
        provenance: "mock-browser-validation",
        actual_cluster_requests: 0,
        results,
        requests,
        exceptions,
        failures,
      },
      null,
      2,
    ),
  );
  console.log("Evidence:", output);
} finally {
  socket.close();
}
