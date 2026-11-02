import {
  Check,
  FileCheck2,
  Fingerprint,
  ShieldCheck,
  TriangleAlert,
} from "lucide-react";
import type { SecurityState } from "../../types";
interface Props {
  security: SecurityState | null;
  connected: boolean;
  staleSubjects: boolean;
  disabled: boolean;
  tick: number;
  active?: string;
  securityAction: (action: string) => void;
  formatTime: (value?: string | number) => string;
}
export function SecurityControls({
  security,
  connected,
  staleSubjects,
  disabled,
  tick,
  active,
  securityAction,
  formatTime: time,
}: Props) {
  return (
    <>
      <div className="response-steps">
        {[
          "보안 위반 관측",
          "원본 네트워크 격리",
          "Green 기동·응답 검증",
          "시험 업무 경로 전환",
        ].map((label, i) => {
          const complete =
            connected &&
            (i === 0
              ? !!security?.holds.length
              : i === 1
                ? security?.steps.some((s) => s.action === "apply_isolation")
                : i === 2
                  ? security?.steps.some(
                      (s) => s.action === "verify_replacement",
                    )
                  : security?.steps.some((s) => s.action === "switch_route"));
          return (
            <div key={label} className={complete ? "done" : ""}>
              <span>
                {complete ? (
                  <Check size={12} />
                ) : (
                  String(i + 1).padStart(2, "0")
                )}
              </span>
              <b>{label}</b>
            </div>
          );
        })}
      </div>
      <button
        className="button secondary full"
        disabled={disabled || !!security?.holds.length || active !== "blue"}
        onClick={() => securityAction("inject")}
      >
        <TriangleAlert size={15} />
        1. 통제된 설정 위반
      </button>
      <button
        className="button secondary full"
        disabled={disabled || !security?.holds.length || active !== "blue"}
        onClick={() => securityAction("prepare")}
      >
        <FileCheck2 size={15} />
        2. 대응 계획 검토
      </button>
      <button
        className="button primary full"
        disabled={
          disabled ||
          !security?.prepared ||
          tick >= Date.parse(security?.prepared?.expires_at || "") ||
          !!security?.operation
        }
        onClick={() => securityAction("approve")}
      >
        <ShieldCheck size={15} />
        3. 계획 승인·실행
      </button>
      {security?.prepared && (
        <div className="plan-binding">
          <span>
            <Fingerprint size={13} />
            {security.operation ? "실행 이력의 승인 대상" : "고정된 승인 대상"}
          </span>
          <code>{security.prepared.plan_digest}</code>
          <small>
            {tick >= Date.parse(security.prepared.expires_at)
              ? `승인 기한 종료 · ${time(security.prepared.expires_at)}`
              : `${time(security.prepared.expires_at)}까지 유효`}
          </small>
        </div>
      )}
      <p className="panel-note">
        원본 격리와 보안 보류는 전환 후에도 유지됩니다. 보류 해제는 이 화면에서
        제공하지 않습니다.
      </p>
      <div className="phase-box">
        <span className={`tiny-dot ${security?.busy ? "busy-dot" : ""}`} />
        {!connected || staleSubjects
          ? "현재 상태 미확인 · 과거 이력 유지"
          : security?.busy
            ? "변경 중 · 검증 결과 대기"
            : security?.operation?.status === "response_verified"
              ? "검증된 대응 이력 · 보류 유지"
              : security?.error
                ? "복구 검토 필요"
                : security?.prepared
                  ? "계획 검토 후 승인 대기"
                  : security?.holds.length
                    ? "보류 등록 · 계획 검토 필요"
                    : "관측 중"}
      </div>
    </>
  );
}
