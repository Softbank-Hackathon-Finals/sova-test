import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  RefreshCw,
  ShieldCheck,
  TriangleAlert,
  X,
} from "lucide-react";
import { request } from "../../api";
import { migrationEnvelope, migrationTopology } from "./migration";
import type { MigrationEnvelope, MigrationState } from "./migration";
import { WorkloadMap } from "../../components/WorkloadMap";
import { ProgramReadiness } from "../../components/ProgramReadiness";

const stamp = (n: number) =>
  new Date(n * 1000).toLocaleTimeString("ko-KR", { hour12: false });
const env = (s: string) => (s === "aws" ? "AWS" : "온프렘 VM");
const statusLabel: Record<string, string> = {
  pending: "대기",
  running: "실행 중",
  succeeded: "검증 완료",
  needs_attention: "검토 필요",
  failed: "실패",
  blocked: "차단",
};

export function MigrationPanel() {
  const [data, setData] = useState<MigrationEnvelope | null>(null);
  const [error, setError] = useState("");
  const [received, setReceived] = useState(0);
  const [tick, setTick] = useState(Date.now());
  const [connected, setConnected] = useState(false);
  const [pending, setPending] = useState(false);
  const [accepted, setAccepted] = useState("");
  const [expanded, setExpanded] = useState(false);
  const [confirm, setConfirm] = useState<{
    target: "aws" | "vm";
    revision: string;
    route: number;
  } | null>(null);
  const poll = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  async function refresh() {
    if (poll.current) return;
    const controller = new AbortController();
    poll.current = controller;
    const timer = setTimeout(() => controller.abort(), 9000);
    try {
      const next = migrationEnvelope(
        await request<unknown>(
          "/api/migration/state",
          undefined,
          controller.signal,
        ),
      );
      if (!mounted.current || controller.signal.aborted) return;
      setData(next);
      setReceived(Date.now());
      setConnected(next.status === "connected");
      setError("");
    } catch (e) {
      if (mounted.current) {
        setConnected(false);
        setError(e instanceof Error ? e.message : "이전 관측 실패");
      }
    } finally {
      clearTimeout(timer);
      if (poll.current === controller) poll.current = null;
    }
  }
  useEffect(() => {
    mounted.current = true;
    void refresh();
    const timer = setInterval(() => {
      setTick(Date.now());
      void refresh();
    }, 2500);
    return () => {
      mounted.current = false;
      clearInterval(timer);
      poll.current?.abort();
      poll.current = null;
    };
    // One fixed upstream per mounted screen; no automatic mutation retries.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  const state: MigrationState | null =
    data?.status === "connected" ? data.state : null;
  const clusters = state?.profile === "eks-rke2-stateless-v1";
  const current =
    connected &&
    !!state &&
    tick - received < 12000 &&
    tick < Date.parse(state.expires_at);
  const disabled = !current || pending || !!state?.operation;
  const workflow = state?.operation || state?.workflows[0];
  async function act(action: "switch" | "probe", target: "aws" | "vm") {
    if (disabled || !state) return;
    const binding =
      action === "switch"
        ? confirm
        : { revision: state.revision, route: state.route_revision };
    if (
      !binding ||
      binding.revision !== state.revision ||
      binding.route !== state.route_revision
    ) {
      setConfirm(null);
      setError("승인 대상이 변경됐습니다. 다시 검토하세요.");
      return;
    }
    setPending(true);
    setAccepted("");
    setError("");
    try {
      const result = await request<{
        status: string;
        result: { ok?: boolean };
      }>("/api/migration/action", {
        action,
        environment: target,
        revision: binding.revision,
        route_revision: binding.route,
      });
      if (mounted.current)
        setAccepted(
          action === "switch"
            ? "전환 요청 접수 · 완료는 아래 실제 단계와 응답으로 확인합니다."
            : result.result.ok
              ? "실제 업무 요청 응답 확인"
              : "업무 요청 결과를 확인하지 못했습니다.",
        );
    } catch (e) {
      if (mounted.current)
        setError(e instanceof Error ? e.message : "실행 결과 미확인");
    } finally {
      if (mounted.current) {
        setPending(false);
        setConfirm(null);
        void refresh();
      }
    }
  }
  return (
    <section className="migration-page">
      <section className="page-heading">
        <div>
          <p className="eyebrow">AWS → ON-PREM · VERIFY · RETURN</p>
          <h1>환경을 옮기고, 실제 응답으로 확인합니다.</h1>
          <p>
            {clusters ? "실제 AWS EKS·Linux VM RKE2" : "기존 AWS·Linux VM"} 시험
            경로를 연결했습니다. 현재 범위는 무상태 앱의 요청 경로 전환입니다.
          </p>
        </div>
        <button
          className="button secondary"
          onClick={() => void refresh()}
          disabled={pending}
        >
          <RefreshCw size={15} />
          상태 확인
        </button>
      </section>
      <div className="scope-banner">
        <ShieldCheck size={18} />
        <span>
          <b>실제 경로 전환과 전체 이전을 구분합니다.</b> 두 앱은 미리
          실행됩니다. 앱·DB·세션 복사, 무중단 보장, AWS ALB·DNS 전환은 포함하지
          않습니다.
        </span>
      </div>
      {(!current || error) && (
        <div className="migration-notice" role="status">
          <TriangleAlert size={20} />
          <div>
            <strong>
              {data?.status === "unavailable"
                ? "AWS·온프렘 실행 환경 미연결"
                : "현재 실행 상태 미확인"}
            </strong>
            <p>
              {error ||
                (data?.status === "unavailable"
                  ? data.reason
                  : "현재 관측을 기다리고 있습니다.")}
            </p>
            <p>
              아래 환경은 연결 대상 표시입니다. 자원 생성·이전 성공을 뜻하지
              않으며 변경 버튼은 차단됩니다.
            </p>
          </div>
        </div>
      )}
      <details className="migration-readiness">
        <summary>전체 이전에 필요한 여섯 영역의 검증 범위 보기</summary>
        <ProgramReadiness />
      </details>
      <div className="migration-summary">
        <article>
          <small>현재 요청 경로</small>
          <strong>{current && state ? env(state.route) : "미확인"}</strong>
          <span>
            {current
              ? `경로 revision ${state!.route_revision}`
              : "이전 관측으로 현재 위치를 추정하지 않음"}
          </span>
        </article>
        <article>
          <small>실제 요청 표본</small>
          <strong>{current ? state!.metrics.sample_count : "—"}</strong>
          <span>
            {clusters ? "게이트웨이 시작 이후" : "최근 60초"} · 클라우드 전체
            트래픽 아님
          </span>
        </article>
        <article>
          <small>
            응답 성공률 / P95{clusters ? " (최근 최대 1만 표본)" : ""}
          </small>
          <strong>
            {current && state!.metrics.success_percent !== null
              ? `${state!.metrics.success_percent}%`
              : "—"}
          </strong>
          <span>
            {current && state!.metrics.p95_ms !== null
              ? `${state!.metrics.p95_ms} ms`
              : "측정된 표본 대기"}
          </span>
        </article>
      </div>
      <div className="migration-layout">
        <section className="panel">
          <div className="panel-heading">
            <h2>{clusters ? "EKS → RKE2" : "AWS → 온프렘"} 실행 지도</h2>
            {clusters && (
              <button
                className="button secondary"
                onClick={() => setExpanded(!expanded)}
              >
                {expanded ? "서비스 단위로 보기" : "등록된 Pod 펼치기"}
              </button>
            )}
          </div>
          <WorkloadMap
            topology={migrationTopology(state, current, tick, expanded)}
            selected={[]}
            onSelect={() => {}}
            connected={current}
            identity={expanded ? "eks-rke2-pods" : "aws-vm-migration"}
          />
          <p className="panel-note">
            실제 새 요청 응답이 확인된 연결에서만 요청 애니메이션을 표시합니다.
            온프렘 대상은 이 Mac의 Lima Linux VM입니다.
            {expanded &&
              " 배치 관계는 등록 정보이며, Pod의 초록 상태와 요청 애니메이션은 실제 응답 UID가 일치할 때만 표시됩니다."}
          </p>
        </section>
        <aside className="panel migration-controls">
          <h2>이전 실행</h2>
          {state?.recovery_required && (
            <p role="status">
              미완료 검증 기록이 있어 변경을 보류합니다. 효과 재조회와 운영자
              검토가 필요합니다.
            </p>
          )}
          <p>
            목적지 확인 → 실제 요청 리허설 → 경로 적용·재조회 → 새 응답 검증
          </p>
          {(["vm", "aws"] as const).map((target) => (
            <button
              key={target}
              className="button primary full"
              disabled={
                disabled ||
                state?.recovery_required === true ||
                state?.route === target ||
                (clusters &&
                  (!state?.observations[target]?.available ||
                    tick - state.observations[target].observed_at * 1000 >=
                      8000)) ||
                (target === "aws" && state?.security.state !== "normal")
              }
              onClick={() =>
                state &&
                setConfirm({
                  target,
                  revision: state.revision,
                  route: state.route_revision,
                })
              }
            >
              {target === "vm" ? "온프렘으로 전환" : "AWS로 복귀"}
              <ArrowRight size={15} />
            </button>
          ))}
          <button
            className="button secondary full"
            disabled={disabled}
            onClick={() => state && void act("probe", state.route)}
          >
            실제 업무 요청 확인
          </button>
          <p className="panel-note">
            {clusters &&
              "최근 업무 응답이 확인되지 않은 대상에는 전환할 수 없습니다. "}
            AWS가 시험 격리된 상태에서는 복귀할 수 없습니다. 이 화면은 보안
            격리를 해제하지 않습니다.
          </p>
          <h3>전체 이전의 후속 단계</h3>
          <ul className="migration-obligations">
            <li>앱·데이터·Secret 의존성 조사 — 미연결</li>
            <li>목적지 보호 요구 검증 — 미연결</li>
            <li>DB 최종 동기화·쓰기 권한 전환 — 미구현</li>
            <li>신규 데이터·세션·복구 검증 — 미연결</li>
          </ul>
        </aside>
      </div>
      {accepted && (
        <p className="migration-notice" role="status">
          {accepted}
        </p>
      )}
      <section className="panel migration-history">
        <h2>실제 전환 단계</h2>
        {!current && (
          <p>
            현재 실행 상태 미확인. 아래에 남은 기록이 있더라도 과거 이력입니다.
          </p>
        )}
        {workflow ? (
          <>
            <p>
              {env(workflow.target)} ·{" "}
              {statusLabel[workflow.status] || workflow.status} · {workflow.id}
            </p>
            <ol>
              {workflow.steps.map((s) => (
                <li key={s.id}>
                  <strong>{s.label}</strong>
                  <span>{statusLabel[s.status] || s.status}</span>
                </li>
              ))}
            </ol>
          </>
        ) : (
          <p>
            전환 이력이 없습니다. 아직 어떤 단계도 완료로 표시하지 않습니다.
          </p>
        )}
      </section>
      <section className="panel migration-history">
        <h2>요청·실행 근거</h2>
        <p>
          환경 미연결 시 기록을 생성하거나 과거 요청 애니메이션을 재생하지
          않습니다.
        </p>
        {state?.events
          .slice()
          .reverse()
          .slice(0, 30)
          .map((e) => (
            <div className="migration-event" key={e.seq}>
              <time>{stamp(e.at)}</time>
              <b>{env(e.environment)}</b>
              <span>{e.detail}</span>
            </div>
          ))}
        {!state?.events.length && (
          <p>실제 실행 서버의 연결과 새 관측을 기다립니다.</p>
        )}
      </section>
      {confirm && (
        <div className="modal-backdrop">
          <section
            className="confirm-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="migration-confirm"
          >
            <button
              className="icon-button modal-close"
              aria-label="닫기"
              disabled={pending}
              onClick={() => setConfirm(null)}
            >
              <X size={18} />
            </button>
            <h2 id="migration-confirm">
              {env(confirm.target)} 경로 전환을 승인할까요?
            </h2>
            <p>
              이미 실행 중인 시험 앱으로 새 요청 경로를 변경합니다. DB·세션 이전
              승인은 포함하지 않습니다.
            </p>
            <p>
              실행본 {confirm.revision.slice(0, 12)} · 현재 경로 revision{" "}
              {confirm.route}
            </p>
            <div className="modal-actions">
              <button
                className="button secondary"
                disabled={pending}
                onClick={() => setConfirm(null)}
              >
                취소
              </button>
              <button
                className="button primary"
                disabled={disabled}
                onClick={() => void act("switch", confirm.target)}
              >
                확인 후 실행
              </button>
            </div>
          </section>
        </div>
      )}
    </section>
  );
}
