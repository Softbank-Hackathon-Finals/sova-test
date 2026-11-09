import test from "node:test";
import assert from "node:assert/strict";
import {
  SCENARIOS,
  createSession,
  advance,
  requestRecovery,
} from "./model.mjs";
import { injectionCommand, parseCommand, nextCommand } from "./commands.mjs";

test("each preset command is bound to the selected scenario and complete target set", () => {
  for (const spec of SCENARIOS) {
    const parsed = parseCommand(
      injectionCommand(spec.id),
      createSession(spec.id),
    );
    assert.equal(parsed.kind, "inject");
    assert.deepEqual(parsed.targets, spec.targets);
    const other = SCENARIOS.find((item) => item.id !== spec.id);
    assert.equal(
      parseCommand(injectionCommand(spec.id), createSession(other.id)).kind,
      "error",
    );
  }
});
test("missing, duplicate and expanded target scopes are rejected", () => {
  for (const command of [
    "inject lateral-movement --target api",
    "inject lateral-movement --target api,api",
    "inject lateral-movement --target api,worker,db",
    "inject lateral-movement --target api,other",
  ])
    assert.equal(parseCommand(command, createSession("segment")).kind, "error");
});
test("shell commands, substitutions, markup and unsupported arguments never execute", () => {
  for (const command of [
    "kubectl delete pod api",
    "inject access-violation --target worker;whoami",
    "inject access-violation --target $(id)",
    "<script>alert(1)</script>",
    "inject access-violation --target worker --force",
    "inject access-violation --target worker\nrm -rf /",
    "",
    "x".repeat(257),
  ])
    assert.equal(parseCommand(command, createSession("isolate")).kind, "error");
});
test("a repeated injection cannot reset or bypass an in-progress approval", () => {
  let session = createSession("segment");
  for (let i = 0; i < 3; i++) session = advance(session);
  assert.equal(session.phase, "awaiting_approval");
  assert.equal(
    parseCommand(injectionCommand("segment"), session).kind,
    "error",
  );
  assert.equal(session.approved, false);
});
test("console inspection commands do not confer approval or execution", () => {
  const session = createSession("migrate");
  for (const value of ["help", "status", "clear"])
    assert.deepEqual(parseCommand(value, session), { kind: value });
  for (const value of ["approve", "skip", "resume --force"])
    assert.equal(parseCommand(value, session).kind, "error");
  assert.equal(session.phase, "normal");
});

test("inspection is available in every phase without changing session or approval", () => {
  let s = createSession("segment");
  for (let i = 0; i < 9; i++) {
    const before = structuredClone(s);
    for (const [raw, kind] of [
      ["workload status", "workload_status"],
      ["incident inspect", "incident_inspect"],
      ["response watch", "watch"],
    ])
      assert.deepEqual(parseCommand(raw, s), { kind });
    assert.deepEqual(s, before);
    s = advance(s, { approve: true });
  }
});
test("approval and resume cannot skip planning, an approval boundary or a completed run", () => {
  let s = createSession("migrate");
  for (let i = 0; i < 7; i++) {
    assert.equal(
      parseCommand("response approve", s).kind,
      s.phase === "awaiting_approval" ? "approve" : "error",
    );
    if (["normal", "awaiting_approval", "complete"].includes(s.phase))
      assert.equal(parseCommand("response resume", s).kind, "error");
    s = advance(s, { approve: true });
  }
});
test("recovery commands are restricted by type, lifecycle and duplicate requests", () => {
  for (const id of ["segment", "migrate", "patch", "credentials"]) {
    let s = createSession(id);
    assert.equal(parseCommand("recovery start", s).kind, "error");
    for (let i = 0; i < 7; i++) s = advance(s, { approve: true });
    assert.equal(
      parseCommand("recovery start", s).kind,
      id === "segment" ? "recover" : "error",
    );
    if (id === "segment") {
      s = requestRecovery(s);
      assert.equal(parseCommand("recovery start", s).kind, "error");
      assert.equal(parseCommand("response approve", s).kind, "error");
      assert.equal(parseCommand("response pause", s).kind, "pause");
      assert.equal(parseCommand("response resume", s).kind, "resume");
    }
  }
});
test("operator commands reject extra scope, chaining, prototypes and approval bypass flags", () => {
  let s = createSession("segment");
  for (let i = 0; i < 3; i++) s = advance(s);
  for (const raw of [
    "response approve --force",
    "response approve --target db",
    "response approve; recovery start",
    "response\napprove",
    "recovery start --skip-checks",
    "recovery start --target db",
    "response watch --approve",
    "constructor",
    "__proto__",
    "toString",
    "response approve && id",
  ])
    assert.equal(parseCommand(raw, s).kind, "error", raw);
});

test("next suggestions follow each lifecycle without advancing or granting approval", () => {
  for (const spec of SCENARIOS)
    for (const outcome of ["pass", "fail", "unknown"]) {
      let session = createSession(spec.id, { outcome });
      assert.equal(nextCommand(session), injectionCommand(spec.id));
      for (let i = 0; i < 8; i++) {
        const before = structuredClone(session);
        for (const playing of [true, false])
          assert.notEqual(
            parseCommand(nextCommand(session, { playing }), session).kind,
            "error",
          );
        assert.deepEqual(session, before);
        if (session.phase === "awaiting_approval" && !session.preapproved)
          assert.equal(nextCommand(session), "response approve");
        session = advance(session, { approve: true });
      }
      if (outcome !== "pass")
        assert.equal(nextCommand(session), "incident inspect");
      else if (["isolate", "segment"].includes(spec.id)) {
        assert.equal(nextCommand(session), "recovery start");
        session = requestRecovery(session);
        assert.equal(nextCommand(session), "response watch");
        assert.equal(
          nextCommand(session, { playing: false }),
          "response resume",
        );
        session = advance(advance(session));
        assert.equal(nextCommand(session), "workload status");
      } else assert.equal(nextCommand(session), "workload status");
    }
});
test("preapproved waiting suggests observation or resume instead of another approval", () => {
  let session = createSession("segment", { preapproved: true });
  for (let i = 0; i < 3; i++) session = advance(session);
  assert.equal(nextCommand(session), "response watch");
  assert.equal(nextCommand(session, { playing: false }), "response resume");
  assert.equal(session.approved, false);
});
