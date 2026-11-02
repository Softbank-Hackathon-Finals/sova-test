import { expect, it } from "vitest";
import { readiness } from "./readiness";

const now = Date.now();
const ids = [
  "migration",
  "governance",
  "destination",
  "ai_residency",
  "sandbox",
  "cost_observability",
];
function fixture() {
  const catalog = ids.map((id) => ({
    id,
    title: id,
    requirements: [
      { id: id + ":test", objective: "test contract", due_gate: 7 },
    ],
  }));
  return {
    status: "connected",
    catalog,
    observed_at: new Date(now).toISOString(),
    expires_at: new Date(now + 8000).toISOString(),
    report: {
      status: "assessment-only",
      program_digest: "a".repeat(64),
      execution_authorized: false,
      all_areas_verified: false,
      gate_accepted: false,
      carry_forward: [],
      areas: catalog.map((a) => ({
        ...a,
        requirements: a.requirements.map((r) => ({
          ...r,
          result: "unknown",
          evidence_id: null as string | null,
        })),
      })),
    },
  };
}
it("shows unavailable definitions without creating a verified report", () => {
  expect(
    readiness(
      { status: "unavailable", catalog: fixture().catalog, report: null },
      now,
    ).report,
  ).toBeNull();
});
it("accepts bound unknown obligations but never grants execution", () => {
  expect(readiness(fixture(), now).report?.execution_authorized).toBe(false);
});
it("expires the display when the underlying short-lived evidence expires", () => {
  expect(() => readiness(fixture(), now + 9000)).toThrow();
});
it("rejects missing areas and omitted report obligations", () => {
  const f = fixture();
  f.catalog.pop();
  expect(() => readiness(f, now)).toThrow();
  const omitted = fixture();
  omitted.report.areas[0].requirements = [];
  expect(() => readiness(omitted, now)).toThrow();
});
it("does not accept a pass without an evidence reference", () => {
  const f = fixture();
  f.report.areas[0].requirements[0].result = "pass";
  expect(() => readiness(f, now)).toThrow();
});
it("rejects a changed gate or execution authority claim", () => {
  const f = fixture();
  f.report.areas[0].requirements[0].due_gate = 8;
  expect(() => readiness(f, now)).toThrow();
  expect(() =>
    readiness(
      {
        ...fixture(),
        report: { ...fixture().report, execution_authorized: true },
      },
      now,
    ),
  ).toThrow();
});
