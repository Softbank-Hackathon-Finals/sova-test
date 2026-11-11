import test from "node:test";
import assert from "node:assert/strict";
import {createSession, snapshot} from "./model.mjs";

globalThis.document = {body: {dataset: {runtime: "local-rke2"}}};
globalThis.location = {hash: "", pathname: "/console/"};
globalThis.history = {replaceState() {}};
globalThis.window = {addEventListener() {}};
globalThis.setInterval = () => 0;
let state;
globalThis.fetch = async path => ({ok: true, json: async () => path === "/api/session" ? {csrf: "fixed-test-csrf"} : state});
const {connectRuntime, localGraph} = await import("./runtime_client.mjs");
const session = () => ({...createSession("segment"), source: "local-rke2", history: [], evidence: {}, checks: []});
const pods = (role, uid) => ({role, uid, name: role + "-pod", phase: "Running", ready: true, images: []});
function envelope(current = true) {
  return {kind: "sova.local-response.v1", actual_execution: true, busy: false, session: session(), observation: {
    current, observed_at: new Date().toISOString(), expires_at_epoch: Date.now() / 1000 + 20,
    pods: {source: [pods("api", "api-uid"), pods("worker", "worker-uid"), pods("db", "source-db")], target: [pods("db", "target-db")], control: [pods("edge", "edge-uid")]},
    source_database: {jobs: 0, completed: 0}, target_database: {jobs: 0, completed: 0}, database_app_login: {source: true, target: true}, http: {},
  }};
}
async function graph(value) {
  state = value;
  await connectRuntime(() => {}, error => {throw error;});
  return localGraph(value.session, snapshot(value.session));
}
test("stale real observations never inherit the browser's healthy mock topology", async () => {
  const value = envelope(false);
  value.session.phase = "complete";
  const v = await graph(value);
  assert.ok(v.nodes.every(node => node.status === "unknown"));
  assert.equal(v.counters.active, 0);
  assert.ok(v.edges.every(edge => edge.state === "unknown"));
  assert.equal(v.writer, "미확인");
});
test("Ready pods alone never establish traffic flow or a database writer", async () => {
  const v = await graph(envelope());
  assert.ok(v.edges.every(edge => edge.state !== "flow"));
  assert.match(v.writer, /보류/);
});
test("writer comes from actual app gate, DB host and database login together", async () => {
  const value = envelope();
  value.observation.http["source/api"] = {status: 200, identity_echo: true, body: {write_open: true, db_host: "db.sova-response-source"}};
  assert.equal((await graph(value)).writer, "로컬 출발지 DB");
  value.observation.database_app_login.source = false;
  assert.match((await graph(value)).writer, /보류/);
});
test("two observed writer DBs are shown as ambiguous rather than a successful migration", async () => {
  const value = envelope();
  for (const side of ["source", "target"]) value.observation.http[side + "/api"] = {status: 200, identity_echo: true, body: {write_open: true, db_host: "db.sova-response-" + side}};
  assert.match((await graph(value)).writer, /복수 writer/);
});
test("a desired policy or a simulated complete phase does not establish real isolation", async () => {
  const value = envelope();
  value.session.phase = "complete";
  value.session.evidence.policy_roles = ["api", "worker"];
  const v = await graph(value);
  assert.equal(v.counters.isolated, 0);
});
test("expired snapshots clear live classifications even when their last HTTP response was successful", async () => {
  const value = envelope();
  value.observation.expires_at_epoch = Date.now() / 1000 - 1;
  value.observation.entry = {status: 200, body: {environment: "local-source"}};
  const v = await graph(value);
  assert.equal(v.fresh, false);
  assert.match(v.route, /미확인/);
});
