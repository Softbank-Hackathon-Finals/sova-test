// Actual local RKE2 mode is enabled only by the separate loopback host.
// Static scenario mode never fetches an API or obtains execution authority.
export const liveMode = document.body.dataset.runtime === "local-rke2";
let current = null, csrf = null, timer = null, callback = null;

async function request(path, body) {
  const response = await fetch(path, {
    method: body === undefined ? "GET" : "POST",
    cache: "no-store", credentials: "same-origin",
    headers: body === undefined ? {} : {"Content-Type": "application/json", ...(csrf ? {"X-Sova-CSRF": csrf} : {})},
    ...(body === undefined ? {} : {body: JSON.stringify(body)}),
  });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error || "local_runtime_unavailable");
  return value;
}

export async function connectRuntime(onState, onError) {
  if (!liveMode) return;
  callback = onState;
  try {
    const token = location.hash.slice(1);
    history.replaceState(null, "", location.pathname);
    const session = await request("/api/session", token ? {token} : undefined);
    csrf = session.csrf;
    await refreshRuntime();
    timer = setInterval(() => refreshRuntime().catch(onError), 2000);
    window.addEventListener("pagehide", () => clearInterval(timer), {once: true});
  } catch (error) {
    onError(error);
  }
}

export async function refreshRuntime() {
  current = await request("/api/state");
  if (current.kind !== "sova.local-response.v1" || current.actual_execution !== true || current.session.source !== "local-rke2") throw new Error("unexpected_runtime_contract");
  callback?.(current);
  return current;
}

export async function runtimeCommand(command) {
  if (!current || current.busy) throw new Error("실행 결과를 확인 중입니다. 잠시 기다려 주세요.");
  await request("/api/command", {
    request_id: crypto.randomUUID().replaceAll("-", ""),
    revision: current.session.revision, command,
  });
  await refreshRuntime();
}

export async function chooseRuntime(scenario) {
  await request("/api/scenario", {scenario});
  await refreshRuntime();
}

export function runtimeStatus() { return current; }

// Placement labels and DB host identities come from the served runtime; the
// local-only defaults keep older runtimes readable.
const LOCAL_TOPOLOGY = {
  name: "local",
  labels: {source: "로컬 출발지", target: "이 Mac 온프렘", control: "로컬 제어"},
  db_hosts: {"db.sova-response-source": "source", "db.sova-response-target": "target"},
};
const sideOf = environment => typeof environment !== "string" ? null : environment.endsWith("-target") ? "target" : environment.endsWith("-source") ? "source" : null;

export function localGraph(session, base) {
  // The browser's expected phase is never used as proof of an external effect.
  const observation = current?.observation;
  const topology = current?.topology || LOCAL_TOPOLOGY;
  const place = topology.labels;
  const fresh = Boolean(observation?.current && observation.expires_at_epoch * 1000 > Date.now());
  const pods = fresh ? observation.pods : {};
  const find = (side, role) => (pods?.[side] || []).filter(item => item.role === role);
  const live = (side, role) => {
    const items = find(side, role);
    return items.length ? items.every(item => item.ready) ? "healthy" : "warning" : "standby";
  };
  const mapping = {api: ["source", "api"], worker: ["source", "worker"], auth: ["source", "auth"], objects: ["source", "objects"], external: ["source", "external"], db: ["source", "db"], edge: ["control", "edge"], "target-api": ["target", "api"], "target-worker": ["target", "worker"], "target-db": ["target", "db"]};
  const isolatedRoles = session.evidence?.policy_roles || [];
  const completed = session.phase === "complete";
  const recovered = session.recovery?.phase === "recovered";
  const nodes = base.nodes.map(node => {
    const item = {...node, status: "unknown", affected: false};
    const target = mapping[item.id];
    if (target && fresh) {
      item.status = live(...target);
      const items = find(...target);
      item.subtitle = `${place[target[0]]} · ${items.length} Pod`;
      item.resources = items;
      const response = observation.http?.[target.join("/")];
      if (response && items.length && (response.status !== 200 || !response.identity_echo)) item.status = response.status === 503 ? "warning" : "unknown";
      if (isolatedRoles.includes(target[1]) && target[0] === "source" && !recovered && session.scenario !== "egress" && items.length === 0 && session.evidence?.stream_fencing?.[target[1]]?.ended === true) item.status = "isolated";
    } else if (fresh && item.id === "vault") {
      item.status = observation.secret ? "healthy" : "unknown";
      item.subtitle = "Kubernetes Secret · 값 비공개";
    } else if (fresh && item.id === "queue") {
      const db = observation.source_database;
      item.status = db && db.completed < db.jobs ? "warning" : db ? "healthy" : "unknown";
      item.subtitle = db ? `실제 PG 큐 · ${db.jobs - db.completed}건 대기` : "DB 관측 미확인";
    } else if (fresh && item.id === "extra") {
      const workers = find("source", "worker");
      item.status = workers.length > 1 ? workers.every(item => item.ready) ? "healthy" : "preparing" : "standby";
      item.subtitle = `실제 작업자 ${workers.length}개`;
      item.resources = workers;
    } else if (fresh && item.id === "standby") {
      item.status = ["patch", "rollback"].includes(session.scenario) && ["executing", "verifying", "complete"].includes(session.phase) ? live("source", "api") : "standby";
      item.subtitle = "API의 실제 RollingUpdate 실행본";
      item.resources = find("source", "api");
    }
    if (item.id === "external") item.subtitle = "로컬 시험용 외부 역할 HTTP";
    if (item.id === "auth") item.label = "로컬 접근 검사";
    if (item.id === "objects") item.label = "이웃 HTTP 서비스";
    return item;
  });
  const index = new Map(nodes.map(node => [node.id, node]));
  const verifiedCut = new Set();
  if (fresh && ["executing", "verifying", "complete"].includes(session.phase) && !recovered) {
    if (["isolate", "segment"].includes(session.scenario)) for (const link of base.edges) if (isolatedRoles.includes(link.source) || isolatedRoles.includes(link.target)) verifiedCut.add(link.id);
    if (session.scenario === "egress" && session.checks?.some(check => check.name === "controlled_external_endpoint_unreachable" && check.passed)) verifiedCut.add("egress");
  }
  const entry = observation?.entry;
  const entrySide = entry?.status === 200 ? sideOf(entry.body.environment) : null;
  const route = fresh && entrySide ? `${place[entrySide]} API` : "경로 응답 미확인";
  const edges = base.edges.map(link => {
    let state = "unknown";
    if (fresh) {
      const from = index.get(link.source), to = index.get(link.target);
      state = [from, to].some(item => ["standby", "unknown"].includes(item.status)) ? "idle" : "unknown";
      // Only the end-to-end HTTP entry and explicitly recorded checks establish
      // path results; two Ready Pods do not establish a network connection.
      if (link.id === "ingress" && entrySide === "source") state = "flow";
      if (link.id === "target-route" && entrySide === "target") state = "flow";
      if (link.id === "api-db" && entrySide === "source") state = "flow";
      if (link.id === "target-sql" && entrySide === "target") state = "flow";
      const queue = observation.source_database;
      if (["queue-worker", "worker-db"].includes(link.id) && queue?.jobs > 0 && queue.jobs === queue.completed && find("source", "worker").some(item => item.ready)) state = "flow";
      if (verifiedCut.has(link.id)) state = "cut";
      if (link.id === "replication") state = session.scenario === "migrate" && session.evidence?.source_fingerprint && session.evidence?.target_fingerprint ? "sync" : "idle";
    }
    return {...link, state};
  });
  const actualWriters = new Set();
  if (fresh) for (const side of ["source", "target"]) {
    const api = observation.http?.[side + "/api"];
    if (api?.status === 200 && api.body.write_open) {
      const db = topology.db_hosts[api.body.db_host] || null;
      if (db && observation.database_app_login?.[db]) actualWriters.add(db);
    }
  }
  return {source: "local-rke2", nodes, edges, route,
    writer: !fresh ? "미확인" : actualWriters.size === 1 ? [...actualWriters][0] === "target" ? topology.name === "local" ? "로컬 목적지 DB" : `${place.target} DB` : `${place.source} DB` : actualWriters.size > 1 ? "복수 writer 감지 · 확인 필요" : "쓰기 보류 · 허용 writer 미확인",
    availability: !fresh ? "실제 관측 연결 확인 필요" : current?.busy ? "실제 실행·검증 중" : observation.bridge && !observation.bridge.healthy ? "AWS 연결(SSM 터널) 미확인" : entry?.status === 200 ? "업무 HTTP 응답 확인" : "업무 경로 응답 미확인",
    hold: session.phase !== "normal", detected: session.phase !== "normal",
    operating: fresh && isolatedRoles.length > 0 && !recovered,
    counters: {active: nodes.filter(item => item.status === "healthy").length, isolated: nodes.filter(item => item.status === "isolated").length, cut: edges.filter(item => item.state === "cut").length},
    incidentReleased: false, executionAuthority: false, fresh, observation};
}
