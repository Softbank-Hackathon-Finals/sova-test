import { describe, expect, it } from "vitest";
import { migrationEnvelope, migrationTopology } from "./migration";
import type { MigrationState } from "./migration";

const now = Date.now();
function state(): MigrationState {
  return {
    now: now / 1000,
    route: "aws",
    route_revision: 1,
    revision: "a".repeat(64),
    expires_at: new Date(now + 60000).toISOString(),
    scope: "stateless test fixture",
    observations: {
      aws: { available: true, observed_at: now / 1000 },
      vm: { available: true, observed_at: now / 1000 },
    },
    workloads: {
      aws: { runtime: "Fargate", database: false },
      vm: { runtime: "Lima", database: false },
    },
    operation: null,
    workflows: [],
    events: [],
    requests: [],
    security: { state: "normal" },
    metrics: { sample_count: 0, success_percent: null, p95_ms: null },
  };
}
describe("actual migration projection", () => {
  it("expanded cluster graph animates only the Pod identified by an actual request", () => {
    const s: MigrationState = { ...state(), profile: "eks-rke2-stateless-v1" };
    s.workloads.aws.pod_uids = ["aws-pod-one", "aws-pod-two"];
    s.workloads.vm.pod_uids = ["vm-pod-one", "vm-pod-two"];
    s.observations.aws.pod_uid = "aws-pod-one";
    s.observations.vm.pod_uid = "vm-pod-two";
    s.requests = [
      {
        id: "actual-pod-request",
        at: now / 1000,
        environment: "aws",
        ok: true,
        latency_ms: 5,
        pod_uid: "aws-pod-one",
      },
    ];
    const graph = migrationTopology(s, true, now, true);
    expect(graph.nodes).toHaveLength(7);
    expect(
      graph.edges.filter((e) => e.state === "flow").map((e) => e.target),
    ).toEqual(["aws:aws-pod-one"]);
    expect(graph.nodes.find((n) => n.key === "aws:aws-pod-two")?.health).toBe(
      "unknown",
    );
    expect(
      graph.edges
        .filter((e) => e.id.startsWith("owns:"))
        .every((e) => e.state === "idle" && !e.requestId),
    ).toBe(true);
    s.requests[0].pod_uid = "unregistered-pod";
    expect(
      migrationTopology(s, true, now, true).edges.every((e) => !e.requestId),
    ).toBe(true);
    expect(
      migrationTopology(s, false, now, true).nodes.every(
        (n) => n.health === "unknown",
      ),
    ).toBe(true);
  });
  it("accepts the explicit stateless cluster profile and rejects unknown profiles", () => {
    const s = { ...state(), profile: "eks-rke2-stateless-v1" };
    expect(
      migrationEnvelope({ status: "connected", state: s }, now).status,
    ).toBe("connected");
    expect(() =>
      migrationEnvelope(
        { status: "connected", state: { ...s, profile: "unknown" } },
        now,
      ),
    ).toThrow();
  });
  it("unavailable backend has no implied running route or traffic", () => {
    expect(
      migrationEnvelope(
        { status: "unavailable", state: null, reason: "stopped" },
        now,
      ).state,
    ).toBeNull();
    const graph = migrationTopology(null, false, now);
    expect(graph.nodes.every((n) => n.health === "unknown")).toBe(true);
    expect(graph.edges.every((e) => e.state === "idle" && !e.requestId)).toBe(
      true,
    );
  });
  it("a route readback alone is not a successful request", () => {
    expect(
      migrationTopology(state(), true, now).edges.every(
        (e) => e.state === "idle",
      ),
    ).toBe(true);
  });
  it("only a recent actual request animates the matching route", () => {
    const s = state();
    s.requests = [
      {
        id: "actual-request",
        at: now / 1000,
        environment: "aws",
        ok: true,
        latency_ms: 42,
      },
    ];
    const graph = migrationTopology(s, true, now);
    expect(graph.edges[0].state).toBe("flow");
    expect(graph.edges[0].requestId).toBe("actual-request");
    expect(graph.edges[1].requestId).toBeUndefined();
    expect(
      migrationTopology(s, true, now + 9000).edges.every((e) => !e.requestId),
    ).toBe(true);
    expect(
      migrationTopology(s, false, now).nodes.every(
        (n) => n.health === "unknown",
      ),
    ).toBe(true);
  });
  it("request failures remain failures", () => {
    const s = state();
    s.requests = [
      {
        id: "failed-request",
        at: now / 1000,
        environment: "aws",
        ok: false,
        latency_ms: 4000,
      },
    ];
    expect(migrationTopology(s, true, now).edges[0].state).toBe("error");
  });
  it.each([
    { now: now / 1000 - 60 },
    { now: Number.NaN },
    { expires_at: new Date(now - 1).toISOString() },
    { route_revision: true },
    { revision: "not-a-digest" },
    { workloads: { aws: { database: true } } },
  ])("rejects stale, expired or unsupported registrations %j", (change) => {
    expect(() =>
      migrationEnvelope(
        { status: "connected", state: { ...state(), ...change } },
        now,
      ),
    ).toThrow();
  });
});
