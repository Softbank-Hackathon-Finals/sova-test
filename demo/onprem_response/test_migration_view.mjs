import assert from "node:assert/strict";
import { test } from "node:test";
import { migrationSnapshot, planConnectionState } from "./migration_view.js";

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

test("fresh denied plan read identifies missing access without authorizing actions", () => {
  const result = planConnectionState(
    {
      current: true,
      checked_at: new Date(now).toISOString(),
      last_http_status: 403,
    },
    now,
  );
  assert.equal(result.fresh, true);
  assert.equal(result.tone, "attention");
  assert.equal(result.label, "계획 조회 권한 필요");
});
test("expired, future, or withdrawn receipts cannot claim current access denial", () => {
  for (const [current, offset] of [
    [true, -180000],
    [true, 1],
    [false, 0],
  ]) {
    const state = planConnectionState(
      {
        current,
        checked_at: new Date(now + offset).toISOString(),
        last_http_status: 403,
      },
      now,
    );
    assert.equal(state.fresh, false);
    assert.equal(state.tone, "unknown");
  }
});
test("HTTP 200 cannot claim a bound plan or approval", () => {
  const state = planConnectionState(
    {
      current: true,
      checked_at: new Date(now).toISOString(),
      last_http_status: 200,
    },
    now,
  );
  assert.equal(state.tone, "unknown");
  assert.equal(state.label, "계획 결속 확인 필요");
});
test("missing receipt and authentication failures do not claim readiness", () => {
  assert.equal(planConnectionState(null, now).fresh, false);
  for (const code of [401, 404, 503])
    assert.equal(
      planConnectionState(
        {
          current: true,
          checked_at: new Date(now).toISOString(),
          last_http_status: code,
        },
        now,
      ).label,
      "계획 조회 미완료",
    );
});
