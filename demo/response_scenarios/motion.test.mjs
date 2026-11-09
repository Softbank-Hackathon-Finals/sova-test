import test from "node:test";
import assert from "node:assert/strict";
import { createSession, advance, snapshot } from "./model.mjs";
import { createMotionClock, motionPlan } from "./motion.mjs";

function sessionAt(id, phase, outcome = "pass") {
  let session = createSession(id, { outcome });
  while (session.phase !== phase) session = advance(session, { approve: true });
  return session;
}
function clockHarness() {
  let at = 0,
    serial = 0;
  const tasks = new Map(),
    frames = [];
  const clock = createMotionClock((value) => frames.push(value), {
    now: () => at,
    request: (fn) => {
      tasks.set(++serial, fn);
      return serial;
    },
    cancel: (id) => tasks.delete(id),
  });
  return {
    clock,
    frames,
    step(ms) {
      at += ms;
      const current = [...tasks.values()];
      tasks.clear();
      for (const task of current) task();
    },
  };
}
test("logical isolation moves only the selected components, inside the same AWS zone", () => {
  const s = sessionAt("segment", "executing"),
    view = snapshot(s),
    plan = motionPlan(s, view);
  assert.deepEqual(plan.positions.api, { x: 550, y: 860 });
  assert.deepEqual(plan.positions.worker, { x: 790, y: 860 });
  for (const id of ["db", "vault", "auth", "objects", "target-api"]) {
    const original = view.nodes.find((n) => n.id === id);
    assert.deepEqual(plan.positions[id], { x: original.x, y: original.y });
  }
});
test("migration moves deployment representations while preserving original resources", () => {
  const s = sessionAt("migrate", "executing"),
    view = snapshot(s),
    plan = motionPlan(s, view);
  assert.deepEqual(
    plan.transfers.map((t) => t.to),
    ["target-api", "target-worker", "target-db"],
  );
  assert.equal(plan.positions.api.x, view.nodes.find((n) => n.id === "api").x);
  assert.equal(plan.executionAuthority, false);
});
test("held and waiting phases do not animate successful deployment transfers", () => {
  for (const phase of ["awaiting_approval", "held"]) {
    const s = sessionAt("migrate", phase, "unknown");
    assert.equal(motionPlan(s, snapshot(s)).transfers.length, 0);
  }
});
test("outbound restriction does not move or restart a workload", () => {
  const s = sessionAt("egress", "executing"),
    view = snapshot(s),
    plan = motionPlan(s, view);
  assert.equal(plan.transfers.length, 0);
  assert.equal(plan.entering.length, 0);
  assert.equal(
    plan.positions.worker.y,
    view.nodes.find((n) => n.id === "worker").y,
  );
});
test("movement is interpolated rather than teleporting", () => {
  const { clock, step } = clockHarness();
  clock.transition({ a: { x: 0, y: 0 } }, { identity: "normal" });
  clock.transition(
    { a: { x: 100, y: 200 } },
    { identity: "moving", duration: 1000 },
  );
  step(500);
  assert.equal(clock.read().positions.a.x, 50);
  assert.equal(clock.read().positions.a.y, 100);
  step(500);
  assert.equal(clock.read().positions.a.x, 100);
  assert.equal(clock.read().state, "settled");
});
test("pause freezes movement and resume retains the remaining duration", () => {
  const { clock, step } = clockHarness();
  clock.transition({ a: { x: 0, y: 0 } }, { identity: "normal" });
  clock.transition(
    { a: { x: 100, y: 0 } },
    { identity: "moving", duration: 1000 },
  );
  step(250);
  clock.pause();
  const before = clock.read();
  step(5000);
  assert.deepEqual(clock.read().positions, before.positions);
  assert.equal(clock.read().state, "paused");
  clock.resume();
  step(750);
  assert.equal(clock.read().positions.a.x, 100);
});
test("same-state inspector redraw does not restart movement", () => {
  const { clock, step } = clockHarness();
  clock.transition({ a: { x: 0, y: 0 } }, { identity: "normal" });
  clock.transition(
    { a: { x: 100, y: 0 } },
    { identity: "moving", duration: 1000 },
  );
  step(500);
  clock.transition(
    { a: { x: 100, y: 0 } },
    { identity: "moving", duration: 1000 },
  );
  step(500);
  assert.equal(clock.read().state, "settled");
});
test("reset cancels an old animation and immediate mode skips movement", () => {
  const { clock, step } = clockHarness();
  clock.transition({ a: { x: 0, y: 0 } }, { identity: "normal" });
  clock.transition({ a: { x: 100, y: 0 } }, { identity: "moving" });
  clock.clear();
  clock.transition({ a: { x: 5, y: 0 } }, { identity: "new" });
  step(5000);
  assert.equal(clock.read().positions.a.x, 5);
  clock.transition(
    { a: { x: 10, y: 0 } },
    { identity: "reduced-motion", immediate: true },
  );
  assert.equal(clock.read().positions.a.x, 10);
  assert.equal(clock.read().state, "settled");
});
