import assert from "node:assert/strict";
import { test } from "node:test";
import { migrationSnapshot } from "./migration_view.js";

const now = Date.parse("2026-01-01T00:00:00Z");
const value = () => ({
  environments: [
    {
      lane: "source",
      status: "CURRENT",
      observed_at: new Date(now).toISOString(),
    },
  ],
  facets: { pod: { ready: true }, unrelated: { ready: true } },
  view: {
    nodes: [
      {
        id: "svc",
        resource_uid: "svc-uid",
        lane: "source",
        column: 0,
        kind: "app",
        label: "채팅",
        health: "unknown",
      },
      { id: "pod", resource_uid: "pod-uid", lane: "source", column: 1 },
      { id: "unrelated", resource_uid: "other-pod", lane: "source", column: 1 },
      {
        id: "container",
        resource_uid: "container-uid",
        lane: "source",
        column: 2,
      },
    ],
    edges: [{ source: "svc", target: "pod", label: "Service selector" }],
  },
});

test("counts selected Pods, not containers or unrelated Pods", () => {
  const [source, target] = migrationSnapshot(value(), now);
  assert.equal(source.services[0].pods, 1);
  assert.equal(source.services[0].ready, 1);
  assert.equal(source.services[0].http, false);
  assert.equal(target.current, false);
});
test("expired observations withdraw current counts and HTTP claims", () => {
  const doc = value();
  doc.view.nodes[0].health = "ready";
  const [source] = migrationSnapshot(doc, now + 90000);
  assert.equal(source.current, false);
  assert.equal(source.services[0].ready, null);
  assert.equal(source.services[0].http, false);
  assert.deepEqual(source.services[0].podUIDs, []);
});
test("failed collection withdraws still-young observations", () => {
  const doc = value();
  doc.environments[0].status = "STALE";
  assert.equal(migrationSnapshot(doc, now)[0].services[0].pods, null);
});
test("no observation does not synthesize a running app", () => {
  assert(
    migrationSnapshot(null, now).every((e) => !e.current && !e.services.length),
  );
});
