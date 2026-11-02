import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  dependencyState,
  mergeSecurityEvents,
  operatorProof,
  request,
  securityState,
} from "./api";
import type { SecurityState } from "./types";

beforeEach(() => {
  vi.stubGlobal("localStorage", {
    getItem: () =>
      JSON.stringify({
        token: "origin-proof-only",
        expires_at: new Date(Date.now() + 60000).toISOString(),
      }),
  });
});
afterEach(() => vi.unstubAllGlobals());
describe("operator boundary", () => {
  it("does not send any request without a current origin proof", async () => {
    vi.stubGlobal("localStorage", { getItem: () => "{}" });
    const fetcher = vi.fn();
    vi.stubGlobal("fetch", fetcher);
    await expect(request("/api/action", { action: "approve" })).rejects.toThrow(
      "로그인",
    );
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("treats invalid or expired storage as unauthenticated", () => {
    expect(operatorProof({ getItem: () => "{" })).toBe("");
    expect(
      operatorProof({
        getItem: () => JSON.stringify({ token: "x", expires_at: "2000-01-01" }),
      }),
    ).toBe("");
  });
  it("uses same-origin cookies and explicit proof without forwarding a cloud credential", async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValue(new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetcher);
    await request("/api/dependency/action", {
      action: "restore",
      nodes: ["processor"],
    });
    const options = fetcher.mock.calls[0][1];
    expect(options.credentials).toBe("same-origin");
    expect(options.headers).toEqual({
      "X-Sova-CSRF": "origin-proof-only",
      "Content-Type": "application/json",
    });
  });
  it("never automatically retries an uncertain mutation", async () => {
    const fetcher = vi.fn().mockRejectedValue(new Error("socket closed"));
    vi.stubGlobal("fetch", fetcher);
    await expect(
      request("/api/action", {
        action: "approve",
        plan_digest: "bound-digest",
      }),
    ).rejects.toThrow("자동 재시도하지 않습니다");
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
  it("does not expose a server error body or claim success on denial", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response("private-internal-error", { status: 403 }),
        ),
    );
    await expect(request("/api/state")).rejects.toMatchObject({ status: 403 });
  });
});
describe("observation freshness", () => {
  const graph = () => ({
    now: Date.now() / 1000,
    revision: 1,
    expires_at: new Date(Date.now() + 60000).toISOString(),
    application: {},
    nodes: [{ id: "api", name: "API", state: "healthy", observation: {} }],
    edges: [],
    events: [],
    applications: [],
  });
  it("does not accept a stale response as current", () => {
    expect(() =>
      dependencyState({ ...graph(), now: Date.now() / 1000 - 20 }),
    ).toThrow();
  });
  it("rejects malformed node states, expiry and future observations", () => {
    for (const value of [
      { ...graph(), now: Date.now() / 1000 + 30 },
      { ...graph(), expires_at: "invalid" },
      {
        ...graph(),
        nodes: [
          { id: "x", name: "x", state: "verified-by-ai", observation: {} },
        ],
      },
    ]) {
      expect(() => dependencyState(value)).toThrow();
    }
  });
  it("rejects a missing security scope rather than rendering a healthy view", () => {
    expect(() =>
      securityState({ at: new Date().toISOString(), snapshots: {} }),
    ).toThrow();
  });
});
it("merges paginated execution events without losing new records or growing unbounded", () => {
  const event = (sequence: number) =>
    ({ sequence, kind: "observed" }) as SecurityState["events"][number];
  const merged = mergeSecurityEvents(
    Array.from({ length: 500 }, (_, i) => event(i + 1)),
    [event(500), event(501)],
  );
  expect(merged).toHaveLength(500);
  expect(merged[0].sequence).toBe(2);
  expect(merged.at(-1)?.sequence).toBe(501);
  expect(() => mergeSecurityEvents([], [event(NaN)])).toThrow();
});
