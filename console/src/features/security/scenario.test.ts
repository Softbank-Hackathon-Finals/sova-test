import { describe, expect, it } from "vitest";
import { scenarioProgress } from "./scenario";
import type { SecurityState } from "../../types";

const now = Date.now();
const timestamp = new Date(now).toISOString();
function completed(): SecurityState {
  return {
    at: timestamp,
    expires_at: new Date(now + 60000).toISOString(),
    application_id: "app",
    snapshots: Object.fromEntries(
      ["blue", "green"].map((env) => [
        env,
        {
          digest: env,
          stale: false,
          graph: {
            observed_at: timestamp,
            resources: [
              {
                id: "api",
                name: "api",
                kind: "service",
                scope: {
                  tenant_id: "tenant",
                  application_id: "app",
                  environment_id: env,
                  resource_id: env,
                },
              },
            ],
            relations: [],
          },
          findings: [],
        },
      ]),
    ),
    holds: [
      {
        hold_id: "incident",
        scope: {
          tenant_id: "tenant",
          application_id: "app",
          environment_id: "blue",
          resource_id: "blue",
        },
        reason: "test",
        raised_at: timestamp,
      },
    ],
    route: { environment_id: "green", revision: 2 },
    probes: {
      blue: {
        ok: false,
        target: "blue",
        request_id: "blocked",
        observed_at: timestamp,
        new_connection_blocked: true,
      },
      green: {
        ok: true,
        target: "green",
        request_id: "reply",
        observed_at: timestamp,
      },
    },
    phase: "response_verified_hold_retained",
    busy: false,
    error: null,
    steps: [
      "apply_isolation",
      "activate_replacement",
      "verify_replacement",
      "switch_route",
    ].map((action) => ({
      action,
      status: "confirmed_applied",
      at: timestamp,
      effect_digest: action,
    })),
    operation: {
      status: "response_verified",
      operation_id: "operation",
      completion_digest: "receipt",
    },
    prepared: null,
    isolation_proof: { status: "confirmed_applied", observed_at: timestamp },
    protection_comparison: {
      basis: "configuration_only",
      execution_authority: false,
      accepted: false,
    },
    events: [],
  };
}
describe("team demo's current result versus execution history", () => {
  it("requires actual isolation, current Green response and a completion receipt", () => {
    expect(scenarioProgress(completed(), true, now).verified).toBe(true);
    const s = completed();
    s.operation!.completion_digest = undefined;
    expect(scenarioProgress(s, true, now).verified).toBe(false);
  });
  it("retains history without claiming current success after disconnect or expiry", () => {
    const s = completed();
    expect(scenarioProgress(s, false, now)).toMatchObject({
      completed: true,
      verified: false,
      current: false,
    });
    expect(scenarioProgress(s, true, now + 61000).verified).toBe(false);
  });
  it("does not mistake an HTTP failure for a confirmed network isolation", () => {
    const s = completed();
    s.probes.blue.new_connection_blocked = false;
    expect(scenarioProgress(s, true, now).verified).toBe(false);
  });
  it("revokes current success when isolation proof or Green response becomes stale", () => {
    const s = completed();
    s.probes.green.observed_at = new Date(now - 9000).toISOString();
    expect(scenarioProgress(s, true, now).verified).toBe(false);
    expect(scenarioProgress(completed(), true, now + 16000).verified).toBe(
      false,
    );
  });
  it("requires every applied effect and keeps unresolved outcomes unverified", () => {
    const s = completed();
    s.steps[1].status = "unknown";
    expect(scenarioProgress(s, true, now).verified).toBe(false);
    const pending = completed();
    pending.error = "needs_recovery";
    expect(scenarioProgress(pending, true, now).verified).toBe(false);
  });
});
