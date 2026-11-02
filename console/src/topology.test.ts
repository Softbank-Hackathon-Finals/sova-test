import { describe, expect, it } from "vitest";
import {
  dependencyTopology,
  fresh,
  layout,
  securityTopology,
} from "./topology";
import type { DependencyState, SecurityState, Topology } from "./types";

const dependency = (): DependencyState => ({
  now: Date.now() / 1000,
  revision: 1,
  expires_at: new Date(Date.now() + 60000).toISOString(),
  application: {
    id: "app",
    name: "App",
    description: "",
    entry: "api",
    fault_default: "worker",
    isolation_default: ["worker"],
  },
  applications: [],
  nodes: ["api", "worker"].map((id) => ({
    id,
    name: id,
    kind: "service",
    description: "",
    state: "healthy",
    stale: false,
    called: true,
    dependencies: [],
    observation: { at: Date.now() / 1000, pid: 123, available: true },
  })),
  edges: [{ source: "api", target: "worker", required: false }],
  last_request: {
    request_id: "measured-request",
    at: Date.now() / 1000,
    ok: true,
    degraded: false,
    duration_ms: 1,
    edges: [{ source: "api", target: "worker", ok: true }],
    spans: [],
    failures: [],
  },
  events: [],
  isolated: [],
  requests: 1,
  successes: 1,
  scope: "registered local demo;",
});
describe("evidence-driven map", () => {
  it("shows only an observed request as a flow", () => {
    expect(dependencyTopology(dependency(), true).edges[0].requestId).toBe(
      "measured-request",
    );
    const data = dependency();
    data.last_request!.at -= 20;
    expect(dependencyTopology(data, true).edges[0]).toMatchObject({
      state: "idle",
      requestId: undefined,
    });
  });
  it("never retains healthy colors or active traffic after disconnect", () => {
    const map = dependencyTopology(dependency(), false);
    expect(map.nodes.every((n) => n.health === "unknown")).toBe(true);
    expect(map.edges.every((e) => e.state === "idle" && !e.requestId)).toBe(
      true,
    );
  });
  it("keeps partial isolation scoped to the selected subject", () => {
    const data = dependency();
    data.nodes[1].state = "isolated";
    data.isolated = ["worker"];
    const map = dependencyTopology(data, true);
    expect(map.nodes[0].health).toBe("healthy");
    expect(map.nodes[1].health).toBe("isolated");
    expect(map.edges[0]).toMatchObject({ state: "cut", requestId: undefined });
  });
  it("distinguishes possible neighboring impact from confirmed impact", () => {
    const data = dependency();
    data.nodes[1].state = "failed";
    data.nodes[0].called = false;
    expect(dependencyTopology(data, true).nodes[0]).toMatchObject({
      health: "healthy",
      potential: true,
    });
  });
  it("handles cyclic registered relationships without recursion", () => {
    const map = dependencyTopology(dependency(), true);
    map.edges.push({
      id: "back",
      source: "worker",
      target: "api",
      label: "",
      state: "idle",
    });
    const points = layout(map);
    expect(Object.keys(points)).toHaveLength(2);
    expect(
      Object.values(points).every(
        (p) => Number.isFinite(p.x) && Number.isFinite(p.y),
      ),
    ).toBe(true);
  });
  it("rejects future and stale probe timestamps", () => {
    expect(fresh(Date.now() / 1000 + 20)).toBe(false);
    expect(fresh(Date.now() / 1000 - 20)).toBe(false);
  });
  it("does not turn Kubernetes declared relations into observed requests", () => {
    const s = {
      at: new Date().toISOString(),
      snapshots: {
        blue: {
          stale: false,
          graph: {
            observed_at: new Date().toISOString(),
            resources: [
              {
                id: "service:api",
                name: "API",
                kind: "edge",
                scope: { environment_id: "blue", resource_id: "service" },
              },
              {
                id: "deployment:api",
                name: "API",
                kind: "service",
                scope: { environment_id: "blue", resource_id: "app" },
              },
            ],
            relations: [{ source: "service:api", target: "deployment:api" }],
          },
          findings: [],
        },
      },
      route: { environment_id: "blue", revision: 1 },
      probes: {
        blue: {
          ok: true,
          request_id: "real",
          observed_at: new Date().toISOString(),
        },
      },
      isolation_proof: null,
    } as unknown as SecurityState;
    const map = securityTopology(s, true);
    expect(
      map.edges.find((e) => e.id.startsWith("blue:"))?.requestId,
    ).toBeUndefined();
    expect(map.edges.find((e) => e.id === "route-blue")?.requestId).toBe(
      "real",
    );
  });
  it("lays out the two Kubernetes environments separately", () => {
    const topology: Topology = {
      nodes: [
        { key: "b", lane: "blue" },
        { key: "g", lane: "green" },
      ] as Topology["nodes"],
      edges: [],
    };
    expect(layout(topology).b.y).not.toBe(layout(topology).g.y);
  });
});
