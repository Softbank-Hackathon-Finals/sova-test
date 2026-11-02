import { Check, CircleHelp, ShieldCheck } from "lucide-react";
import type { SecurityState } from "../../types";
import { scenarioProgress } from "./scenario";

export function SecurityScenario({
  state,
  connected,
  tick,
}: {
  state: SecurityState | null;
  connected: boolean;
  tick: number;
}) {
  const progress = scenarioProgress(state, connected, tick);
  return (
    <section className="scenario-card" aria-label="팀 공유 6단계 시나리오">
      <div className="scenario-heading">
        <div>
          <span className="eyebrow">팀 공유 · 약 5분</span>
          <h2>관측부터 승인된 대응까지</h2>
        </div>
        <span
          className={`connection-badge ${progress.verified ? "online" : ""}`}
          data-testid="scenario-result"
        >
          <ShieldCheck size={15} />
          {progress.verified
            ? "현재 대응 결과 확인"
            : progress.completed
              ? "완료 이력 있음 · 현재 근거 확인 필요"
              : "단계별 실제 근거 확인"}
        </span>
      </div>
      <ol className="scenario-list">
        {progress.steps.map((step, i) => (
          <li
            key={step.title}
            className={
              step.done ? "verified" : step.history ? "historical" : ""
            }
          >
            <span>{step.done ? <Check size={14} /> : i + 1}</span>
            <b>{step.title}</b>
            <small>
              {step.done ? "확인" : step.history ? "실행 이력" : "대기"}
            </small>
          </li>
        ))}
      </ol>
      <div className="scenario-evidence">
        <span>
          새 연결 격리 <b>{progress.isolation ? "실측 확인" : "미확인"}</b>
        </span>
        <span>
          현재 요청 경로{" "}
          <b>
            {progress.current
              ? progress.active?.toUpperCase() || "미확인"
              : "미확인"}
          </b>
        </span>
        <span>
          현재 HTTP 응답 <b>{progress.response ? "실측 확인" : "미확인"}</b>
        </span>
        <span>
          독립 보안 보류{" "}
          <b>
            {connected && state
              ? `${state.holds.length}건 · 전환 후 유지`
              : "미확인"}
          </b>
        </span>
      </div>
      {state?.operation?.completion_digest && (
        <p className="scenario-receipt">
          불변 완료 영수증 <code>{state.operation.completion_digest}</code>
        </p>
      )}
      <p className="panel-note">
        <CircleHelp size={14} /> 실제 로컬 Kubernetes 대응입니다. 원본 격리 후
        대체하므로 중단이 생길 수 있습니다. 공격 탐지·클라우드 간 이전·DB 및
        세션 이전·무중단 운영은 이 시연의 검증 범위가 아닙니다.
      </p>
    </section>
  );
}
