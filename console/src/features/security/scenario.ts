import type { SecurityState } from "../../types";
import { activeEnvironment, fresh } from "../../topology";

export function scenarioProgress(
  state: SecurityState | null,
  connected: boolean,
  now = Date.now(),
) {
  const snapshots = Object.values(state?.snapshots || {});
  const current =
    connected &&
    snapshots.length === 2 &&
    snapshots.every(
      (s) => !s.stale && fresh(s.graph.observed_at, 15000, now),
    ) &&
    now < Date.parse(state?.expires_at || "");
  const effect = (action: string) =>
    !!state?.steps.some(
      (s) => s.action === action && s.status === "confirmed_applied",
    );
  const violation = !!state?.events.some(
    (e) => e.kind === "security_hold_opened",
  );
  const approved = !!state?.events.some((e) => e.kind === "response_approved");
  const active = state ? activeEnvironment(state) : undefined;
  const probe = active ? state?.probes[active] : undefined;
  const blue = state?.probes.blue;
  const isolation =
    current &&
    state?.isolation_proof?.status === "confirmed_applied" &&
    fresh(state.isolation_proof.observed_at, 12000, now) &&
    blue?.new_connection_blocked === true &&
    fresh(blue.observed_at, 8000, now);
  const response =
    current && !!probe?.ok && fresh(probe.observed_at, 8000, now);
  const completed =
    !!state?.operation?.completion_digest &&
    state.operation.status === "response_verified" &&
    [
      "apply_isolation",
      "activate_replacement",
      "verify_replacement",
      "switch_route",
    ].every(effect);
  const verified =
    !!completed &&
    !!isolation &&
    !!response &&
    active === "green" &&
    !!state?.holds.length &&
    !state.error;
  return {
    current,
    verified,
    completed,
    isolation: !!isolation,
    response: !!response,
    active,
    steps: [
      {
        title: "정상 서비스·관계 확인",
        done:
          current &&
          !!state?.probes.blue?.ok &&
          fresh(state.probes.blue.observed_at, 8000, now),
        history: violation,
      },
      {
        title: "통제된 설정 위반",
        done:
          current &&
          snapshots.some((s) =>
            s.findings.some(
              (f) => f.control_id === "read-only-root" && f.result === "fail",
            ),
          ),
        history: violation,
      },
      {
        title: "근거·영향·보류 확인",
        done: current && !!state?.holds.length,
        history: violation,
      },
      { title: "계획 검토·사람 승인", done: approved, history: approved },
      {
        title: "실제 격리·대체·전환",
        done: !!isolation && !!response && active === "green",
        history: !!completed,
      },
      { title: "결과·미검증 범위 확인", done: verified, history: !!completed },
    ],
  };
}
