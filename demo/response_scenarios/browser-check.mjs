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
    `document.querySelector('[data-scenario="${id}"]').click(); document.getElementById('reset').click(); document.getElementById('outcome').value=${JSON.stringify(outcome)}; document.getElementById('outcome').dispatchEvent(new Event('change'));`,
  );
}
async function finish() {
  return evaluate(
    `(() => { for(let i=0;i<10;i++){const approve=document.getElementById('approve'); if(approve){approve.click();continue;}const b=document.getElementById('next');if(b.disabled)break;b.click();}return {phase:document.getElementById('stat-phase').textContent,route:document.getElementById('stat-route').textContent,writer:document.getElementById('stat-writer').textContent}; })()`,
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
    `new Promise((resolve,reject)=>{let count=0;const tick=()=>{if(document.querySelectorAll('[data-scenario]').length===9)resolve(true);else if(count++>80)reject(new Error('UI failed to mount'));else setTimeout(tick,50);};tick();})`,
  );
  await check(
    "nine playbooks and fourteen selectable mock resources",
    async () => {
      assert.equal(
        await evaluate("document.querySelectorAll('[data-node]').length"),
        14,
      );
      assert.equal(
        await evaluate("document.querySelector('.mock-banner')"),
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
  await check("all nine response types reach a mock completion", async () => {
    for (const id of [
      "isolate",
      "segment",
      "egress",
      "credentials",
      "patch",
      "restart",
      "scale",
      "migrate",
      "rollback",
    ]) {
      await choose(id);
      const result = await finish();
      assert.equal(result.phase, "대응 완료", id);
    }
  });
  await check(
    "failure and unknown preserve source route and stop writer promotion",
    async () => {
      for (const outcome of ["fail", "unknown"]) {
        await choose("migrate", outcome);
        const result = await finish();
        assert.match(result.phase, /보류/);
        assert.equal(result.route, "AWS 업무 API");
        assert.doesNotMatch(result.writer, /^writer: 목적지 DB/);
      }
    },
  );
  await check(
    "autoplay pauses at manual approval and does not approve on timeout",
    async () => {
      await choose("patch");
      await evaluate(
        "document.getElementById('next').click();document.getElementById('next').click();document.getElementById('speed').value='900';document.getElementById('autoplay').click()",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,1200))");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "승인 대기",
      );
      assert.equal(
        await evaluate("document.getElementById('autoplay').textContent"),
        "자동 재생",
      );
      assert.equal(
        await evaluate("document.getElementById('next').disabled"),
        true,
      );
    },
  );
  await check(
    "scenario switch revokes previous preapproval and cancels playback",
    async () => {
      await choose("isolate");
      await evaluate(
        "document.getElementById('preapproved').click();document.getElementById('autoplay').click();document.querySelector('[data-scenario=egress]').click()",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,1200))");
      assert.equal(
        await evaluate("document.getElementById('preapproved').checked"),
        false,
      );
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "정상 흐름",
      );
    },
  );
  await choose("segment");
  await evaluate(
    "for(let i=0;i<3;i++)document.getElementById('next').click();document.getElementById('approve').click()",
  );
  await check(
    "only API and worker are isolated in the displayed graph",
    async () => {
      assert.deepEqual(
        await evaluate(
          "Array.from(document.querySelectorAll('.map-node.isolated')).map(n=>n.dataset.node)",
        ),
        ["api", "worker"],
      );
      await evaluate(
        "document.querySelector('[data-node=db]').dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}))",
      );
      assert.equal(
        await evaluate(
          "document.querySelector('#node-inspector h3').textContent",
        ),
        "출발지 DB",
      );
    },
  );
  const desktop = await call("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: true,
  });
  await writeFile(
    join(output, "desktop.png"),
    Buffer.from(desktop.data, "base64"),
  );
  await check("mobile keeps the document within the viewport", async () => {
    await call("Emulation.setDeviceMetricsOverride", {
      width: 390,
      height: 844,
      deviceScaleFactor: 1,
      mobile: true,
    });
    await evaluate("new Promise(resolve=>setTimeout(resolve,100))");
    assert.equal(
      await evaluate("document.documentElement.scrollWidth <= innerWidth + 1"),
      true,
    );
  });
  const mobile = await call("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: true,
  });
  await writeFile(
    join(output, "mobile.png"),
    Buffer.from(mobile.data, "base64"),
  );
  await check("reduced-motion hides animated particles", async () => {
    await choose("egress");
    await call("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-reduced-motion", value: "reduce" }],
    });
    assert.equal(
      await evaluate(
        "getComputedStyle(document.querySelector('.flow-particle')).display",
      ),
      "none",
    );
  });
  await check(
    "no product API, external request, mutation or browser error",
    async () => {
      assert.equal(exceptions.length, 0, JSON.stringify(exceptions));
      assert.equal(failures.length, 0, JSON.stringify(failures));
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
