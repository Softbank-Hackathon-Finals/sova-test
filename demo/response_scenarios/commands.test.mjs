import test from "node:test";
import assert from "node:assert/strict";
import { SCENARIOS, createSession, advance } from "./model.mjs";
import { injectionCommand, parseCommand } from "./commands.mjs";

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
