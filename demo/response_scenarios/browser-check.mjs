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
    `document.querySelector('[data-scenario="${id}"]').click(); document.getElementById('reset').click(); document.getElementById('outcome').value=${JSON.stringify(outcome)}; document.getElementById('outcome').dispatchEvent(new Event('change')); document.getElementById('speed').value='3000';`,
  );
}
async function finish() {
  return evaluate(
    `(() => { for(let i=0;i<10;i++){const approve=document.getElementById('approve'); if(approve){approve.click();continue;}const b=document.getElementById('next');if(b.disabled)break;b.click();}return {phase:document.getElementById('stat-phase').textContent,route:document.getElementById('stat-route').textContent,writer:document.getElementById('stat-writer').textContent}; })()`,
  );
}
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
    `new Promise((resolve,reject)=>{let count=0;const tick=()=>{if(document.querySelectorAll('[data-scenario]').length===9)resolve(true);else if(count++>80)reject(new Error('UI failed to mount'));else setTimeout(tick,50);};tick();})`,
  );
  await check(
    "nine playbooks and fourteen selectable mock resources",
    async () => {
      assert.equal(
        await evaluate("document.querySelectorAll('[data-node]').length"),
        14,
      );
      const labels = await evaluate(
        "Array.from(document.querySelectorAll('.map-node .node-english')).map(n=>({text:n.textContent,right:n.getBBox().x+n.getBBox().width}))",
      );
      assert.equal(labels.length, 14);
      assert(
        labels.every((n) => /[A-Za-z]/.test(n.text) && n.right <= 175),
        JSON.stringify(labels),
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
  await check(
    "desktop sidebar slides closed and the main area expands without resetting the session",
    async () => {
      await evaluate(
        "if(document.getElementById('sidebar-toggle').getAttribute('aria-expanded')==='false')document.getElementById('sidebar-toggle').click()",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
      const before = await evaluate(
        "({width:document.querySelector('.main-shell').getBoundingClientRect().width, margin:parseFloat(getComputedStyle(document.querySelector('.main-shell')).marginLeft),phase:document.getElementById('stat-phase').textContent})",
      );
      await evaluate("document.getElementById('sidebar-toggle').click()");
      await evaluate("new Promise(resolve=>setTimeout(resolve,70))");
      const middle = await evaluate(
        "parseFloat(getComputedStyle(document.querySelector('.main-shell')).marginLeft)",
      );
      assert(
        middle > 0 && middle < before.margin,
        `Expected sliding margin, got ${middle}`,
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
      const after = await evaluate(
        "({width:document.querySelector('.main-shell').getBoundingClientRect().width,inert:document.getElementById('workspace-sidebar').inert,phase:document.getElementById('stat-phase').textContent})",
      );
      assert(after.width > before.width + 190);
      assert.equal(after.inert, true);
      assert.equal(after.phase, before.phase);
    },
  );
  await check("desktop layout preference survives refresh", async () => {
    await call("Page.reload");
    await new Promise((resolve) => setTimeout(resolve, 400));
    assert.equal(
      await evaluate(
        "document.getElementById('sidebar-toggle').getAttribute('aria-expanded')",
      ),
      "false",
    );
    await evaluate("document.getElementById('sidebar-toggle').click()");
    await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
  });
  await check(
    "main layout responds to available space, not only window width",
    async () => {
      await call("Emulation.setDeviceMetricsOverride", {
        width: 1200,
        height: 1100,
        deviceScaleFactor: 1,
        mobile: false,
      });
      await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
      const narrow = await evaluate(
        "getComputedStyle(document.querySelector('.map-layout')).gridTemplateColumns.split(' ').length",
      );
      await evaluate("document.getElementById('sidebar-toggle').click()");
      await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
      const expanded = await evaluate(
        "getComputedStyle(document.querySelector('.map-layout')).gridTemplateColumns.split(' ').length",
      );
      assert.equal(narrow, 1);
      assert.equal(expanded, 2);
      assert.equal(
        await evaluate(
          "document.documentElement.scrollWidth <= innerWidth + 1",
        ),
        true,
      );
      await call("Emulation.setDeviceMetricsOverride", {
        width: 1600,
        height: 1100,
        deviceScaleFactor: 1,
        mobile: false,
      });
      await evaluate(
        "document.getElementById('sidebar-toggle').click();new Promise(resolve=>setTimeout(resolve,350))",
      );
    },
  );
  await check(
    "flow and injection console share the map card and inspection commands do not advance",
    async () => {
      await choose("segment");
      assert.equal(
        await evaluate(
          "document.getElementById('map').contains(document.getElementById('injection-form')) && document.getElementById('map').contains(document.getElementById('phase-track'))",
        ),
        true,
      );
      assert.equal(
        await evaluate(
          "['next','autoplay','reset','speed','outcome'].every(id=>Boolean(document.getElementById(id).closest('.flow-console-grid')))",
        ),
        true,
      );
      assert.equal(
        await evaluate("document.querySelectorAll('#next').length"),
        1,
      );
      assert.equal(
        await evaluate(
          "getComputedStyle(document.getElementById('response-controls')).display",
        ),
        "none",
      );
      await evaluate(
        "document.getElementById('injection-command').value='help';document.getElementById('injection-form').requestSubmit();document.getElementById('injection-command').value='status';document.getElementById('injection-form').requestSubmit()",
      );
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "정상 흐름",
      );
      assert.match(
        await evaluate(
          "document.getElementById('injection-output').textContent",
        ),
        /현재 대응 상태/,
      );
      await evaluate("document.getElementById('injection-clear').click()");
      assert.equal(
        await evaluate(
          "document.getElementById('injection-output').childElementCount",
        ),
        0,
      );
    },
  );
  await check(
    "unsupported commands and expanded targets are refused without executable markup",
    async () => {
      await choose("segment");
      for (const value of [
        '<img src=x onerror="throw 1">',
        "inject lateral-movement --target api,worker,db",
        "approve",
      ]) {
        await evaluate(
          `document.getElementById('injection-command').value=${JSON.stringify(value)};document.getElementById('injection-form').requestSubmit()`,
        );
        assert.equal(
          await evaluate(
            "document.getElementById('injection-command').getAttribute('aria-invalid')",
          ),
          "true",
        );
        assert.equal(
          await evaluate("document.getElementById('stat-phase').textContent"),
          "정상 흐름",
        );
      }
      assert.equal(
        await evaluate(
          "document.querySelector('#injection-output img, #injection-output script')",
        ),
        null,
      );
    },
  );
  await check(
    "a console injection advances the flow and stops at human approval; duplicate injection is refused",
    async () => {
      await choose("segment");
      await evaluate(
        "document.getElementById('speed').value='900';document.getElementById('injection-form').requestSubmit()",
      );
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "이상 주입",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,2200))");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "승인 대기",
      );
      assert.equal(
        await evaluate("document.getElementById('autoplay').textContent"),
        "자동 재생",
      );
      await command("inject lateral-movement --target api,worker");
      assert.match(
        await evaluate(
          "document.getElementById('injection-feedback').textContent",
        ),
        /이미 시작/,
      );
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "승인 대기",
      );
      const consoleImage = await call("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: true,
      });
      await writeFile(
        join(output, "injection-console.png"),
        Buffer.from(consoleImage.data, "base64"),
      );
    },
  );
  await check(
    "each console preset injects its own scenario and reset cancels the old flow",
    async () => {
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
        await evaluate(
          "document.getElementById('injection-form').requestSubmit()",
        );
        assert.equal(
          await evaluate("document.getElementById('stat-phase').textContent"),
          "이상 주입",
        );
        assert.match(
          await evaluate(
            "document.getElementById('injection-output').textContent",
          ),
          /이벤트 접수/,
        );
      }
      await choose("segment");
      await evaluate("new Promise(resolve=>setTimeout(resolve,1100))");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "정상 흐름",
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
      assert.match(
        await evaluate(
          "document.getElementById('scenario-english').textContent",
        ),
        /^[A-Za-z]/,
      );
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
  await check(
    "isolation visibly moves, pauses, resumes and settles inside the same environment",
    async () => {
      await choose("segment");
      await evaluate(
        "document.getElementById('speed').value='3000';for(let i=0;i<3;i++)document.getElementById('next').click();document.getElementById('approve').click()",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,600))");
      const midway = await evaluate(
        "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
      );
      assert(
        midway > 300 && midway < 860,
        `Expected an intermediate position, got ${midway}`,
      );
      await evaluate("document.getElementById('motion-toggle').click()");
      const paused = await evaluate(
        "document.querySelector('[data-node=api]').getAttribute('transform')",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,400))");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').getAttribute('transform')",
        ),
        paused,
      );
      assert.equal(
        await evaluate(
          "document.getElementById('workload-map').dataset.motionState",
        ),
        "paused",
      );
      await evaluate("document.getElementById('motion-toggle').click()");
      await evaluate("new Promise(resolve=>setTimeout(resolve,2600))");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
        ),
        860,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=db]').transform.baseVal.consolidate().matrix.f",
        ),
        655,
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
  await check(
    "mobile drawer has a backdrop, traps focus and closes with Escape or navigation",
    async () => {
      await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
      assert.equal(await evaluate("document.body.dataset.sidebar"), "closed");
      await evaluate("document.getElementById('sidebar-toggle').click()");
      assert.equal(
        await evaluate(
          "document.getElementById('workspace-sidebar').getAttribute('aria-modal')",
        ),
        "true",
      );
      assert.equal(
        await evaluate("document.querySelector('.main-shell').inert"),
        true,
      );
      assert.equal(
        await evaluate("document.getElementById('sidebar-backdrop').hidden"),
        false,
      );
      assert.equal(
        await evaluate("document.activeElement.id"),
        "sidebar-close",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
      const drawer = await call("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: false,
      });
      await writeFile(
        join(output, "mobile-menu.png"),
        Buffer.from(drawer.data, "base64"),
      );
      await evaluate(
        "document.querySelector('#workspace-sidebar .brand').focus();document.dispatchEvent(new KeyboardEvent('keydown',{key:'Tab',shiftKey:true,bubbles:true,cancelable:true}))",
      );
      assert.equal(
        await evaluate("document.activeElement.dataset.section"),
        "timeline",
      );
      await evaluate(
        "document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true,cancelable:true}))",
      );
      assert.equal(
        await evaluate("document.activeElement.id"),
        "sidebar-toggle",
      );
      assert.equal(
        await evaluate("document.querySelector('.main-shell').inert"),
        false,
      );
      await evaluate(
        "document.getElementById('sidebar-toggle').click();document.querySelector('#workspace-sidebar [data-section=map]').click()",
      );
      assert.equal(await evaluate("document.body.dataset.sidebar"), "closed");
      await evaluate(
        "document.getElementById('sidebar-toggle').click();document.getElementById('sidebar-backdrop').click()",
      );
      assert.equal(await evaluate("document.body.dataset.sidebar"), "closed");
      await evaluate("document.getElementById('sidebar-toggle').click()");
      await call("Emulation.setDeviceMetricsOverride", {
        width: 1200,
        height: 1100,
        deviceScaleFactor: 1,
        mobile: false,
      });
      await evaluate("new Promise(resolve=>setTimeout(resolve,100))");
      assert.equal(
        await evaluate("document.querySelector('.main-shell').inert"),
        false,
      );
      assert.equal(
        await evaluate(
          "document.getElementById('workspace-sidebar').hasAttribute('aria-modal')",
        ),
        false,
      );
      assert.equal(
        await evaluate("document.activeElement.id"),
        "sidebar-toggle",
      );
      await call("Emulation.setDeviceMetricsOverride", {
        width: 390,
        height: 844,
        deviceScaleFactor: 1,
        mobile: true,
      });
      await evaluate(
        "window.scrollTo(0,0);new Promise(resolve=>setTimeout(resolve,350))",
      );
    },
  );
  const mobile = await call("Page.captureScreenshot", {
    format: "png",
    captureBeyondViewport: true,
  });
  await writeFile(
    join(output, "mobile.png"),
    Buffer.from(mobile.data, "base64"),
  );
  await check(
    "migration animates three transfers while retaining the source and inactive destination route",
    async () => {
      await call("Emulation.setDeviceMetricsOverride", {
        width: 1600,
        height: 1100,
        deviceScaleFactor: 1,
        mobile: false,
      });
      await choose("migrate");
      await evaluate(
        "for(let i=0;i<3;i++)document.getElementById('next').click();document.getElementById('approve').click()",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,500))");
      assert.equal(
        await evaluate("document.querySelectorAll('[data-transfer]').length"),
        3,
      );
      const before = await evaluate(
        "document.querySelector('[data-transfer=api]').getAttribute('transform')",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,200))");
      assert.notEqual(
        await evaluate(
          "document.querySelector('[data-transfer=api]').getAttribute('transform')",
        ),
        before,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.e",
        ),
        520,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=target-route]').dataset.state",
        ),
        "idle",
      );
      const transfer = await call("Page.captureScreenshot", {
        format: "png",
        captureBeyondViewport: true,
      });
      await writeFile(
        join(output, "migration-motion.png"),
        Buffer.from(transfer.data, "base64"),
      );
    },
  );
  await check(
    "switching scenario cancels transfers and leaves no stale movement",
    async () => {
      await choose("egress");
      await evaluate("new Promise(resolve=>setTimeout(resolve,500))");
      assert.equal(
        await evaluate("document.querySelectorAll('[data-transfer]').length"),
        0,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=worker]').transform.baseVal.consolidate().matrix.f",
        ),
        475,
      );
      assert.equal(
        await evaluate(
          "document.getElementById('workload-map').dataset.motionState",
        ),
        "settled",
      );
    },
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
    "reduced-motion places nodes immediately without movement",
    async () => {
      await choose("segment");
      await evaluate(
        "for(let i=0;i<3;i++)document.getElementById('next').click();document.getElementById('approve').click()",
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
        ),
        860,
      );
      assert.equal(
        await evaluate(
          "document.getElementById('workload-map').dataset.motionState",
        ),
        "settled",
      );
    },
  );
  await check(
    "operator inspection and watch do not grant approval or start a response",
    async () => {
      await choose("segment");
      for (const raw of [
        "workload status",
        "incident inspect",
        "response watch",
        "response approve",
        "recovery start",
        "constructor",
        "response approve --force",
      ])
        await command(raw);
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "정상 흐름",
      );
      assert.match(
        await evaluate(
          "document.getElementById('injection-output').textContent",
        ),
        /worker.*작업자/,
      );
      await evaluate(
        "document.getElementById('reset').click();document.getElementById('speed').value='900'",
      );
      await command("inject lateral-movement --target api,worker");
      await command("response pause");
      await evaluate("new Promise(resolve=>setTimeout(resolve,1100))");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "이상 주입",
      );
      await command("response resume");
      await phaseIs("승인 대기");
      await command("incident inspect");
      await command("response watch");
      await command("response resume");
      assert.equal(
        await evaluate(
          "document.getElementById('injection-command').getAttribute('aria-invalid')",
        ),
        "true",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,1100))");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "승인 대기",
      );
    },
  );
  await check(
    "terminal approval runs containment and verification automatically with the same map state",
    async () => {
      await command("response approve");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "대응 진행",
      );
      await command("response approve");
      assert.equal(
        await evaluate(
          "document.getElementById('injection-command').getAttribute('aria-invalid')",
        ),
        "true",
      );
      await phaseIs("대응 완료");
      assert.deepEqual(
        await evaluate(
          "Array.from(document.querySelectorAll('.map-node.isolated')).map(n=>n.dataset.node)",
        ),
        ["api", "worker"],
      );
      await command("workload status");
      assert.match(
        await evaluate(
          "document.getElementById('injection-output').textContent",
        ),
        /격리 2/,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-console-command=\"recovery start\"]').disabled",
        ),
        false,
      );
    },
  );
  await check(
    "terminal recovery revalidates before reconnecting and preserves the incident history",
    async () => {
      await command("recovery start");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "원본 재검증 · 격리 유지",
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=ingress]').dataset.state",
        ),
        "cut",
      );
      await command("recovery start");
      assert.equal(
        await evaluate(
          "document.getElementById('injection-command').getAttribute('aria-invalid')",
        ),
        "true",
      );
      await phaseIs("원본 복귀 진행");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=ingress]').dataset.state",
        ),
        "cut",
      );
      await phaseIs("원본 복귀 확인");
      await evaluate("new Promise(resolve=>setTimeout(resolve,1400))");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=ingress]').dataset.state",
        ),
        "flow",
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
        ),
        300,
      );
      assert.match(
        await evaluate(
          "document.getElementById('stat-availability').textContent",
        ),
        /사고 보류 유지/,
      );
      const log = await evaluate(
        "document.getElementById('injection-output').textContent",
      );
      assert.match(log, /이벤트 접수/);
      assert.match(log, /원본 복귀 확인/);
      await writeFile(
        join(output, "operator-recovery.png"),
        Buffer.from(
          (
            await call("Page.captureScreenshot", {
              format: "png",
              captureBeyondViewport: true,
            })
          ).data,
          "base64",
        ),
      );
    },
  );
  await check(
    "recovery failure or uncertainty keeps isolation and cannot be retried by approval or result edits",
    async () => {
      for (const result of ["fail", "unknown"]) {
        await choose("segment");
        await finish();
        await evaluate(
          `document.getElementById('speed').value='900';document.getElementById('recovery-outcome').value=${JSON.stringify(result)}`,
        );
        await command("recovery start");
        await phaseIs("복구 보류 · 격리 유지");
        assert.equal(
          await evaluate(
            "document.querySelector('[data-edge=ingress]').dataset.state",
          ),
          "cut",
        );
        assert.equal(
          await evaluate(
            "document.querySelector('[data-node=api]').classList.contains('isolated')",
          ),
          true,
        );
        await evaluate(
          "document.getElementById('recovery-outcome').value='pass'",
        );
        await command("response approve");
        await command("recovery start");
        await evaluate("new Promise(resolve=>setTimeout(resolve,1100))");
        assert.equal(
          await evaluate("document.getElementById('stat-phase').textContent"),
          "복구 보류 · 격리 유지",
        );
      }
    },
  );
  await check(
    "approval button auto-progresses to a failed verification and reset cancels stale recovery",
    async () => {
      await choose("patch", "fail");
      await evaluate(
        "document.getElementById('speed').value='900';for(let i=0;i<3;i++)document.getElementById('next').click();document.getElementById('approve').click()",
      );
      await phaseIs("보류 · 전환 중지");
      assert.equal(
        await evaluate("document.getElementById('stat-route').textContent"),
        "AWS 업무 API",
      );
      await choose("segment");
      await finish();
      await evaluate("document.getElementById('speed').value='900'");
      await command("recovery start");
      await choose("migrate");
      await command("recovery start");
      await evaluate("new Promise(resolve=>setTimeout(resolve,1100))");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "정상 흐름",
      );
      assert.equal(
        await evaluate("document.getElementById('phase-track').dataset.mode"),
        "response",
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=target-db]').classList.contains('standby')",
        ),
        true,
      );
    },
  );
  await check(
    "return motion can be paused and resumed without reconnecting early",
    async () => {
      await choose("segment");
      await finish();
      await call("Emulation.setEmulatedMedia", { features: [] });
      await evaluate("document.getElementById('speed').value='1800'");
      await command("recovery start");
      await phaseIs("원본 복귀 진행");
      await evaluate("new Promise(resolve=>setTimeout(resolve,350))");
      const beforePause = await evaluate(
        "document.querySelector('[data-node=api]').transform.baseVal.consolidate().matrix.f",
      );
      assert(beforePause > 300 && beforePause < 860, String(beforePause));
      await command("response pause");
      const paused = await evaluate(
        "document.querySelector('[data-node=api]').getAttribute('transform')",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,500))");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-node=api]').getAttribute('transform')",
        ),
        paused,
      );
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=ingress]').dataset.state",
        ),
        "cut",
      );
      await command("response resume");
      await phaseIs("원본 복귀 확인");
      assert.equal(
        await evaluate(
          "document.querySelector('[data-edge=ingress]').dataset.state",
        ),
        "flow",
      );
      await choose("segment");
    },
  );
  await check(
    "CLI follows phase changes, preserves a typed draft and never submits suggestions automatically",
    async () => {
      await choose("segment");
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "inject lateral-movement --target api,worker",
      );
      await evaluate(
        "document.getElementById('speed').value='900';document.getElementById('injection-form').requestSubmit()",
      );
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "incident inspect",
      );
      assert.equal(
        await evaluate(
          "document.querySelectorAll('#injection-output .console-line.command').length",
        ),
        1,
      );
      await evaluate(
        "document.getElementById('injection-command').value='workload sta';document.getElementById('injection-command').dispatchEvent(new Event('input',{bubbles:true}))",
      );
      await phaseIs("영향·계획 확인");
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "workload sta",
      );
      await evaluate("document.getElementById('injection-example').click()");
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "incident inspect",
      );
      await phaseIs("승인 대기");
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "response approve",
      );
      await evaluate("new Promise(resolve=>setTimeout(resolve,1100))");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        "승인 대기",
      );
      assert.equal(
        await evaluate(
          "document.querySelectorAll('.map-node.isolated').length",
        ),
        0,
      );
      await evaluate(
        "document.getElementById('injection-form').requestSubmit()",
      );
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "response watch",
      );
      await phaseIs("대응 완료");
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "recovery start",
      );
      await evaluate(
        "document.getElementById('injection-form').requestSubmit()",
      );
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "response watch",
      );
      await phaseIs("원본 복귀 확인");
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "workload status",
      );
      await evaluate(
        "document.getElementById('injection-command').value='unfinished';document.getElementById('injection-command').dispatchEvent(new Event('input',{bubbles:true}))",
      );
      await choose("migrate");
      assert.equal(
        await evaluate("document.getElementById('injection-command').value"),
        "inject placement-change --target api,worker,db",
      );
    },
  );
  await check(
    "focused studio keeps flow, injection, approval and map in one viewport without the playback bar",
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
        await choose("segment");
        await evaluate(
          "if(document.body.dataset.studioView!=='focused')document.getElementById('studio-view-toggle').click()",
        );
        await new Promise((resolve) => setTimeout(resolve, 350));
        const scenarioIds = await evaluate(
          "Array.from(document.querySelectorAll('[data-scenario]')).map(n=>n.dataset.scenario)",
        );
        for (const scenario of scenarioIds) {
          await choose(scenario);
          for (const approval of [false, true]) {
            if (approval)
              await evaluate(
                "for(let i=0;i<3;i++)document.getElementById('next').click()",
              );
            const positions = await evaluate(`(() => {
            const ids = ['phase-track','injection-form','map-viewport',${approval ? "'approve'" : "'injection-command'"}];
            return ids.map(id=>{const n=document.getElementById(id),r=n.getBoundingClientRect();return {id,left:r.left,top:r.top,right:r.right,bottom:r.bottom,width:r.width,height:r.height};});
          })()`);
            assert(
              positions.every(
                (r) =>
                  r.left >= 0 &&
                  r.top >= 0 &&
                  r.right <= width + 1 &&
                  r.bottom <= height + 1 &&
                  r.height > 0,
              ),
              JSON.stringify({ width, height, approval, positions }),
            );
            assert(
              positions.find((r) => r.id === "map-viewport").height >= 160,
              JSON.stringify(positions),
            );
            assert.equal(
              await evaluate(
                "document.documentElement.scrollHeight <= innerHeight + 1 && document.documentElement.scrollWidth <= innerWidth + 1",
              ),
              true,
            );
          }
        }
      }
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
      assert.equal(
        await evaluate("document.body.dataset.studioView"),
        "focused",
      );
      await call("Emulation.setDeviceMetricsOverride", {
        width: 1440,
        height: 900,
        deviceScaleFactor: 1,
        mobile: false,
      });
      await writeFile(
        join(output, "focused-studio.png"),
        Buffer.from(
          (await call("Page.captureScreenshot", { format: "png" })).data,
          "base64",
        ),
      );
      const phase = await evaluate(
        "document.getElementById('stat-phase').textContent",
      );
      await evaluate("document.getElementById('studio-view-toggle').click()");
      assert.equal(
        await evaluate("document.getElementById('stat-phase').textContent"),
        phase,
      );
      assert.equal(
        await evaluate("document.getElementById('node-inspector').inert"),
        false,
      );
      await evaluate("document.getElementById('studio-view-toggle').click()");
      await call("Emulation.setDeviceMetricsOverride", {
        width: 390,
        height: 844,
        deviceScaleFactor: 1,
        mobile: true,
      });
      assert.equal(
        await evaluate(
          "new Promise(resolve=>setTimeout(()=>resolve(document.body.dataset.studioView),150))",
        ),
        "overview",
      );
      assert.equal(
        await evaluate("document.getElementById('studio-view-toggle').hidden"),
        true,
      );
    },
  );
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
