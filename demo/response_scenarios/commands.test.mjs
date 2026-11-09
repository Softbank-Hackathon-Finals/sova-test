import test from "node:test";
import assert from "node:assert/strict";
import { SCENARIOS, createSession, currentPhase, snapshot } from "./model.mjs";
import {
  injectionCommand,
  nextCommand,
  parseCommand,
  executeCommand,
} from "./commands.mjs";

const response = [
  "response plan",
  "response submit",
  "response approve",
  "response verify",
  "response finalize",
];
function completed(id = "segment", outcome = "pass") {
  let session = createSession(id, { outcome });
  for (const raw of [injectionCommand(id), ...response])
    session = executeCommand(session, raw).session;
  return session;
}
test("each scoped injection changes one phase and wrong scenario or expanded scope is rejected", () => {
  for (const spec of SCENARIOS) {
    const normal = createSession(spec.id);
    const result = executeCommand(normal, injectionCommand(spec.id));
    assert.equal(result.session.phase, "detected");
    assert.equal(result.session.history.length, normal.history.length + 1);
    assert.deepEqual(result.command.targets, spec.targets);
    const other = createSession(SCENARIOS.find((s) => s.id !== spec.id).id);
    assert.equal(
      executeCommand(other, injectionCommand(spec.id)).session,
      other,
    );
  }
  for (const raw of [
    "inject lateral-movement --target api",
    "inject lateral-movement --target api,api",
    "inject lateral-movement --target api,worker,db",
  ])
    assert.equal(parseCommand(raw, createSession()).kind, "error");
});
test("each stage needs its exact command, including an explicit approval for preapproved scope", () => {
  for (const spec of SCENARIOS)
    for (const outcome of ["pass", "fail", "unknown"])
      for (const preapproved of [false, true]) {
        let session = createSession(spec.id, { outcome, preapproved });
        const phases = [
          "detected",
          "planned",
          "awaiting_approval",
          "executing",
          "verifying",
          outcome === "pass" ? "complete" : "held",
        ];
        for (const [i, raw] of [
          injectionCommand(spec.id),
          ...response,
        ].entries()) {
          assert.equal(nextCommand(session), raw);
          const before = session;
          session = executeCommand(session, raw).session;
          assert.equal(session.phase, phases[i]);
          assert.equal(session.history.length, before.history.length + 1);
          if (i < 3) assert.equal(session.approved, false);
        }
        assert.equal(snapshot(session).executionAuthority, false);
      }
});
test("wrong-phase and repeated mutation commands never skip or repeat a step", () => {
  let session = createSession();
  const commands = [injectionCommand("segment"), ...response];
  for (const expected of commands) {
    for (const raw of commands.filter((raw) => raw !== expected)) {
      const result = executeCommand(session, raw);
      assert.equal(result.command.kind, "error", raw);
      assert.equal(result.session, session);
    }
    session = executeCommand(session, expected).session;
  }
  for (const raw of commands)
    assert.equal(executeCommand(session, raw).session, session);
});
test("observation commands never advance, approve, verify or release containment", () => {
  let session = createSession();
  for (const step of [injectionCommand("segment"), ...response]) {
    const before = structuredClone(session);
    for (const raw of [
      "help",
      "status",
      "workload status",
      "incident inspect",
      "response watch",
      "clear",
    ]) {
      assert.notEqual(parseCommand(raw, session).kind, "error");
      assert.equal(executeCommand(session, raw).session, session);
    }
    assert.deepEqual(session, before);
    session = executeCommand(session, step).session;
  }
});
test("recovery requires three explicit commands, fixes its outcome and blocks early reconnection", () => {
  for (const outcome of ["pass", "fail", "unknown"]) {
    let session = completed();
    assert.equal(nextCommand(session), "recovery start");
    session = executeCommand(session, "recovery start", {
      recoveryOutcome: outcome,
    }).session;
    assert.equal(currentPhase(session), "recovery_checking");
    assert.equal(snapshot(session).counters.isolated, 2);
    assert.equal(executeCommand(session, "recovery finalize").session, session);
    assert.equal(executeCommand(session, "recovery start").session, session);
    assert.equal(nextCommand(session), "recovery verify");
    session = executeCommand(session, "recovery verify", {
      recoveryOutcome: "pass",
    }).session;
    assert.equal(
      currentPhase(session),
      outcome === "pass" ? "recovery_restoring" : "recovery_held",
    );
    assert(snapshot(session).counters.cut > 0);
    if (outcome === "pass") {
      assert.equal(nextCommand(session), "recovery finalize");
      session = executeCommand(session, "recovery finalize").session;
      assert.equal(currentPhase(session), "recovered");
      assert.equal(snapshot(session).counters.cut, 0);
      assert.equal(snapshot(session).hold, true);
    } else
      assert.equal(
        executeCommand(session, "recovery finalize").session,
        session,
      );
    assert.equal(snapshot(session).incidentReleased, false);
    assert.equal(executeCommand(session, "recovery start").session, session);
  }
});
test("unsupported recoveries and failed responses do not gain a return path", () => {
  for (const spec of SCENARIOS)
    for (const outcome of ["pass", "fail", "unknown"]) {
      const session = completed(spec.id, outcome);
      const supported =
        ["isolate", "segment"].includes(spec.id) && outcome === "pass";
      assert.equal(
        parseCommand("recovery start", session).kind,
        supported ? "recover" : "error",
      );
    }
});
test("shell payloads, extra scope, forced completion and old playback commands are refused", () => {
  const session = createSession();
  for (const raw of [
    "kubectl delete pod api",
    "inject lateral-movement --target $(id)",
    "response approve --force",
    "response verify; response finalize",
    "response\napprove",
    "response finalize --skip-checks",
    "recovery start --target db",
    "constructor",
    "__proto__",
    "toString",
    "<script>alert(1)</script>",
    "response resume",
    "response pause",
    "next",
    "autoplay",
    "",
    "x".repeat(257),
  ]) {
    const result = executeCommand(session, raw);
    assert.equal(result.command.kind, "error", raw);
    assert.equal(result.session, session);
  }
});
test("terminal reset starts an unapproved run with the same scenario and no real authority", () => {
  const original = completed();
  const reset = executeCommand(original, "response reset").session;
  assert.equal(reset.scenario, original.scenario);
  assert.equal(reset.phase, "normal");
  assert.equal(reset.approved, false);
  assert.equal(reset.recovery, null);
  assert.equal(reset.history.length, 1);
  assert.equal(reset.source, "mock");
});
