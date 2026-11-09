import test from "node:test";
import assert from "node:assert/strict";
import {
  SCENARIOS,
  createSession,
  advance,
  snapshot,
  requestRecovery,
  recoveryAvailable,
  currentPhase,
  isTerminal,
} from "./model.mjs";

function toPhase(id, phase, options = {}) {
  let session = createSession(id, options);
  for (let i = 0; session.phase !== phase && i < 12; i++) {
    const next = advance(session, { approve: true });
    if (next === session) break;
    session = next;
  }
  assert.equal(session.phase, phase);
  return session;
}

test("every scenario ends only with mock provenance and no execution authority", () => {
  assert.equal(new Set(SCENARIOS.map((item) => item.id)).size, 9);
  for (const { id } of SCENARIOS) {
    const session = toPhase(id, "complete");
    const view = snapshot(session);
    assert.equal(view.source, "mock");
    assert.equal(view.executionAuthority, false);
    assert.equal(view.incidentReleased, false);
    assert(session.history.every((event) => event.provenance === "mock"));
    assert.equal(advance(session), session);
  }
});

test("elapsed playback does not approve or mutate at the approval boundary", () => {
  const waiting = toPhase("patch", "awaiting_approval");
  assert.equal(waiting.approved, false);
  for (let i = 0; i < 20; i++) assert.equal(advance(waiting), waiting);
  assert.equal(snapshot(waiting).route, "AWS 업무 API");
  assert.equal(advance(waiting, { approve: true }).phase, "executing");
});

test("preapproval applies only to the scenario's supported scope", () => {
  assert.equal(
    createSession("migrate", { preapproved: true }).preapproved,
    false,
  );
  const waiting = toPhase("isolate", "awaiting_approval", {
    preapproved: true,
  });
  const executing = advance(waiting);
  assert.equal(executing.phase, "executing");
  assert.equal(executing.approved, true);
  assert.equal(
    createSession("patch", { preapproved: true }).preapproved,
    false,
  );
});

test("partial isolation changes exactly the selected API and worker, not storage or auth", () => {
  const view = snapshot(toPhase("segment", "complete"));
  assert.deepEqual(
    view.nodes
      .filter((item) => item.status === "isolated")
      .map((item) => item.id),
    ["api", "worker"],
  );
  for (const id of ["auth", "db", "objects", "vault"])
    assert.equal(view.nodes.find((item) => item.id === id).status, "healthy");
  assert(
    view.edges
      .filter(
        (item) =>
          ["api", "worker"].includes(item.source) ||
          ["api", "worker"].includes(item.target),
      )
      .every((item) => item.state === "cut"),
  );
});

test("outbound restriction preserves internal work and SQL paths", () => {
  const view = snapshot(toPhase("egress", "complete"));
  assert.deepEqual(
    view.edges.filter((item) => item.state === "cut").map((item) => item.id),
    ["egress"],
  );
  for (const id of ["queue-worker", "worker-db", "ingress"])
    assert.equal(view.edges.find((item) => item.id === id).state, "flow");
});

for (const outcome of ["fail", "unknown"])
  test(`${outcome} blocks route and writer promotion`, () => {
    for (const id of ["patch", "rollback", "migrate"]) {
      const held = toPhase(id, "held", { outcome });
      const view = snapshot(held);
      assert.equal(view.route, "AWS 업무 API");
      assert.equal(view.hold, true);
      assert.notEqual(view.writer, "목적지 DB");
      assert.notEqual(
        view.nodes.find((item) => item.id === "standby").status,
        "patched",
      );
      assert.equal(advance(held, { approve: true }), held);
    }
  });

test("unknown isolation is not labeled verified isolation", () => {
  const view = snapshot(toPhase("segment", "held", { outcome: "unknown" }));
  assert.equal(view.counters.isolated, 0);
  assert.equal(view.counters.cut, 0);
  assert.equal(view.nodes.find((item) => item.id === "api").status, "unknown");
});

test("app restart keeps placement, DB writer and request route", () => {
  const view = snapshot(toPhase("restart", "complete"));
  assert.equal(view.writer, "출발지 DB");
  assert.equal(view.route, "AWS 업무 API");
  assert.equal(
    view.nodes.find((item) => item.id === "target-db").status,
    "standby",
  );
  assert.match(
    view.nodes.find((item) => item.id === "worker").subtitle,
    /실행본 2/,
  );
});

test("migration fences source before activating the destination writer", () => {
  const preparing = snapshot(toPhase("migrate", "executing"));
  assert.equal(preparing.writer, "없음 · 출발지 차단, 목적지 대기");
  assert.equal(preparing.route, "AWS 업무 API");
  const complete = snapshot(toPhase("migrate", "complete"));
  assert.equal(complete.writer, "목적지 DB");
  assert.equal(complete.route, "온프렘 목적지 API");
  assert.equal(
    complete.nodes.find((item) => item.id === "db").status,
    "replaced",
  );
});

test("image rollback preserves the current DB rather than restoring old data", () => {
  const view = snapshot(toPhase("rollback", "complete"));
  assert.equal(view.writer, "출발지 DB");
  assert.match(view.nodes.find((item) => item.id === "standby").subtitle, /v0/);
});

test("changing scenario starts a clean unapproved run", () => {
  const previous = toPhase("segment", "complete");
  const next = createSession("migrate");
  assert.equal(previous.approved, true);
  assert.equal(next.approved, false);
  assert.equal(next.phase, "normal");
  assert.equal(next.history.length, 1);
  assert.equal(snapshot(next).counters.isolated, 0);
});

test("unknown scenario and result cannot silently create a normal success", () => {
  assert.throws(() => createSession("arbitrary-command"));
  assert.throws(() => createSession("patch", { outcome: "skip-checks" }));
});

test("recovery is scoped to finished isolation and never rewinds migrations, images or credentials", () => {
  for (const spec of SCENARIOS) {
    const normal = createSession(spec.id);
    assert.equal(requestRecovery(normal), normal);
    const completed = toPhase(spec.id, "complete");
    const supported = ["isolate", "segment"].includes(spec.id);
    assert.equal(recoveryAvailable(completed), supported);
    if (!supported) assert.equal(requestRecovery(completed), completed);
  }
});
test("recovery preserves containment until revalidation and only then restores the exact target", () => {
  for (const id of ["isolate", "segment"]) {
    const completed = toPhase(id, "complete");
    const checking = requestRecovery(completed);
    assert.equal(isTerminal(checking), false);
    assert.equal(currentPhase(checking), "recovery_checking");
    assert.deepEqual(snapshot(checking), snapshot(completed));
    assert.equal(requestRecovery(checking), checking);
    const restoring = advance(checking);
    assert.equal(currentPhase(restoring), "recovery_restoring");
    assert.equal(
      snapshot(restoring).counters.cut,
      snapshot(completed).counters.cut,
    );
    const restored = advance(restoring);
    assert.equal(currentPhase(restored), "recovered");
    assert.equal(isTerminal(restored), true);
    const view = snapshot(restored);
    assert.equal(view.counters.cut, 0);
    assert.equal(view.counters.isolated, 0);
    assert.equal(view.route, "AWS 업무 API");
    assert.equal(view.writer, "출발지 DB");
    assert.equal(view.hold, true);
    assert.equal(view.incidentReleased, false);
    assert.equal(view.executionAuthority, false);
    assert.equal(restored.history.length, completed.history.length + 3);
    assert.equal(advance(restored), restored);
    assert(restored.history.every((event) => event.provenance === "mock"));
  }
});
for (const outcome of ["fail", "unknown"])
  test(`recovery ${outcome} never releases containment or changes a writer`, () => {
    const held = toPhase("segment", "held", { outcome });
    const checking = requestRecovery(held);
    const blocked = advance(checking);
    assert.equal(currentPhase(blocked), "recovery_held");
    assert.deepEqual(snapshot(blocked).edges, snapshot(held).edges);
    assert.deepEqual(snapshot(blocked).nodes, snapshot(held).nodes);
    assert.equal(snapshot(blocked).writer, snapshot(held).writer);
    assert.equal(advance(blocked), blocked);
    assert.equal(requestRecovery(blocked), blocked);
  });
