import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Check,
  ChevronDown,
  CircleHelp,
  Clock3,
  Database,
  ExternalLink,
  GitBranch,
  Layers3,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Radio,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  TriangleAlert,
  X,
} from "lucide-react";
import type { ReactNode } from "react";
import { request } from "./api";
import { WorkloadMap } from "./components/WorkloadMap";
import { DependencyControls } from "./features/demo/DependencyControls";
import { SecurityControls } from "./features/security/SecurityControls";
import { MigrationPanel } from "./features/migration/MigrationPanel";
import { SecurityScenario } from "./features/security/SecurityScenario";
import { useObservation } from "./hooks/useObservation";
import {
  activeEnvironment,
  dependencyTopology,
  fresh,
  healthLabels,
  securityTopology,
} from "./topology";
import type { Mode, Topology } from "./types";

const controls: Record<string, string> = {
  "no-privileged": "특권 컨테이너 금지",
  "non-root": "비루트 실행",
  "no-escalation": "권한 상승 방지",
  "drop-capabilities": "Linux 권한 제한",
  "read-only-root": "읽기 전용 루트",
  "runtime-seccomp": "seccomp 설정",
  "no-host-namespaces": "호스트 namespace 분리",
  "no-host-mounts": "호스트 경로 제한",
  "no-auto-token": "자동 토큰 마운트 제한",
  "no-literal-sensitive-env": "알려진 민감값 직접 지정 제한",
  "digest-pinned-images": "이미지 digest 고정",
  "bounded-resources": "CPU·메모리 제한",
};
const actions: Record<string, string> = {
  apply_isolation: "원본 네트워크 격리",
  activate_replacement: "Green 기동",
  verify_replacement: "Green 응답 검증",
  switch_route: "시험 경로 전환",
};
const events: Record<string, string> = {
  security_observed: "보안 설정 관측",
  security_hold_opened: "보안 보류 등록",
  response_planned: "대응 계획 고정",
  response_approved: "운영자 승인",
  isolation_verified: "새 연결 차단 확인",
  replacement_verified: "대체 실행본 응답 확인",
  route_switched: "시험 경로 전환",
  effect_unknown: "결과 미확인",
};
const time = (value?: string | number) => {
  if (!value) return "—";
  const date = new Date(typeof value === "number" ? value * 1000 : value);
  return Number.isFinite(date.getTime())
    ? date.toLocaleTimeString("ko-KR", { hour12: false })
    : "—";
};
type Confirmation = {
  title: string;
  description: string;
  subjects: string[];
  danger?: boolean;
  execute: () => Promise<unknown>;
};
function Stat({
  label,
  value,
  detail,
  icon,
  tone = "",
}: {
  label: string;
  value: ReactNode;
  detail: string;
  icon: ReactNode;
  tone?: string;
}) {
  return (
    <article className={`stat ${tone}`}>
      <div className="stat-label">
        {label}
        <span>{icon}</span>
      </div>
      <strong>{value}</strong>
      <small>{detail}</small>
    </article>
  );
}

export default function App() {
  const [migrationOpen, setMigrationOpen] = useState(false);
  const [mode, setMode] = useState<Mode>("security");
  const [selected, setSelected] = useState<string[]>([]);
  const [detail, setDetail] = useState<string | null>(null);
  const [faultTarget, setFaultTarget] = useState("");
  const [pending, setPending] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [actionError, setActionError] = useState("");
  const [accepted, setAccepted] = useState("");
  const timeline = useRef<HTMLElement>(null);
  const observation = useObservation(mode, pending || migrationOpen);
  const { dependency, security, connection, error, receivedAt, refresh } =
    observation;
  const connected = connection === "connected";
  const [tick, setTick] = useState(Date.now());
  useEffect(() => {
    const t = setInterval(() => setTick(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  useEffect(() => {
    setSelected([]);
    setDetail(null);
    setConfirmation(null);
    setActionError("");
    setAccepted("");
  }, [mode, migrationOpen, dependency?.application.id]);
  useEffect(() => {
    if (dependency) setFaultTarget(dependency.application.fault_default);
  }, [dependency?.application.id]);
  useEffect(() => {
    if (!confirmation) return;
    const previous = document.activeElement as HTMLElement | null;
    const dialog = document.querySelector<HTMLElement>('[role="dialog"]');
    const buttons = () => [
      ...(dialog?.querySelectorAll<HTMLButtonElement>(
        "button:not(:disabled)",
      ) || []),
    ];
    buttons()[0]?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !pending) {
        event.preventDefault();
        setConfirmation(null);
      }
      if (event.key !== "Tab") return;
      const list = buttons(),
        first = list[0],
        last = list.at(-1);
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last?.focus();
      }
      if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      if (previous?.isConnected) previous.focus();
    };
  }, [confirmation, pending]);
  const topology: Topology = useMemo(
    () =>
      mode === "dependency"
        ? dependency
          ? dependencyTopology(dependency, connected)
          : { nodes: [], edges: [] }
        : security
          ? securityTopology(security, connected)
          : { nodes: [], edges: [] },
    [mode, dependency, security, connected, tick],
  );
  const chosen =
    topology.nodes.find((n) => n.key === detail) ||
    topology.nodes.find((n) => n.kind !== "edge") ||
    topology.nodes[0];
  const active = security ? activeEnvironment(security) : undefined;
  const currentProbe = active ? security?.probes[active] : undefined;
  const currentRequest =
    mode === "dependency" ? dependency?.last_request : currentProbe;
  const requestVerified =
    connected &&
    !!currentRequest?.ok &&
    (mode === "dependency"
      ? fresh(dependency?.last_request?.at)
      : fresh(currentProbe?.observed_at));
  const expiry =
    mode === "dependency" ? dependency?.expires_at : security?.expires_at;
  const expired = !!expiry && tick >= Date.parse(expiry);
  const staleSubjects =
    mode === "security" &&
    !!security &&
    Object.values(security.snapshots).some(
      (s) => s.stale || !fresh(s.graph.observed_at, 15000),
    );
  const disabled =
    !connected ||
    pending ||
    expired ||
    staleSubjects ||
    (mode === "security" && !!security?.busy);
  const stateText =
    connection === "expired"
      ? "로그인 확인 필요"
      : expired
        ? "실험 기한 종료"
        : connected
          ? "실시간 관측"
          : connection === "loading"
            ? "관측 연결 중"
            : "현재 상태 미확인";

  function choose(id: string) {
    setDetail(id);
    if (mode === "dependency") {
      setSelected((items) =>
        items.includes(id) ? items.filter((x) => x !== id) : [...items, id],
      );
      setFaultTarget(id);
    } else setSelected([id]);
  }
  async function execute(action: () => Promise<unknown>) {
    if (disabled) return;
    setConfirmation(null);
    setPending(true);
    setActionError("");
    setAccepted("");
    try {
      await action();
      setAccepted(
        "요청을 접수했습니다. 실제 상태와 실행 결과를 다시 확인합니다.",
      );
    } catch (cause) {
      setActionError(
        cause instanceof Error
          ? cause.message
          : "결과 미확인 · 자동 재시도하지 않습니다.",
      );
    } finally {
      setPending(false);
    }
  }
  async function logout() {
    if (signingOut) return;
    setSigningOut(true);
    try {
      await request("/api/logout", {});
      localStorage.removeItem("sova_operator_proof");
      location.replace("/");
    } catch {
      setActionError(
        "로그아웃을 확인하지 못했습니다. 운영자 세션 종료가 필요합니다.",
      );
      setSigningOut(false);
    }
  }
  function processAction(
    action: string,
    ids: string[],
    title: string,
    description: string,
    danger = false,
  ) {
    if (disabled || !dependency) return;
    setConfirmation({
      title,
      description,
      subjects: ids.map(
        (id) => dependency.nodes.find((n) => n.id === id)?.name || id,
      ),
      danger,
      execute: () => request("/api/dependency/action", { action, nodes: ids }),
    });
  }
  function securityAction(action: string) {
    if (disabled || !security) return;
    const plan = security.prepared;
    setConfirmation({
      title:
        action === "inject"
          ? "통제된 설정 위반을 주입할까요?"
          : action === "prepare"
            ? "대응 계획을 검토할까요?"
            : "이 계획을 승인하고 실행할까요?",
      description:
        action === "inject"
          ? "등록된 Blue 시험앱의 읽기 전용 루트 설정을 변경합니다. 실제 공격을 실행하는 동작은 아닙니다."
          : action === "prepare"
            ? "현재 원본·대상·이미지·설정·보류·기한에 결합된 대응 계획을 만듭니다. 아직 격리나 기동은 실행하지 않습니다."
            : "원본의 새 연결을 차단하고 Green을 기동·검증한 뒤 시험 경로를 전환합니다. 중간 실패 시 서비스 중단이 발생할 수 있으며 보류는 유지됩니다.",
      subjects:
        action === "approve" && plan
          ? [
              `계획 ${plan.plan_digest}`,
              `유효 기한 ${time(plan.expires_at)}`,
              ...plan.actions.map((a) => actions[a] || a),
            ]
          : ["등록된 로컬 k3s 시험앱", "앱 데이터·세션 이전은 포함하지 않음"],
      danger: action !== "prepare",
      execute: () =>
        request("/api/action", {
          action,
          ...(action === "approve" ? { plan_digest: plan?.plan_digest } : {}),
        }),
    });
  }
  const selectApplication = (id: string) => {
    if (!dependency || id === dependency.application.id || disabled) return;
    setConfirmation({
      title: "시험 애플리케이션을 전환할까요?",
      description:
        "현재 시험 프로세스를 종료하고 선택한 등록 예제의 프로세스를 다시 구성합니다.",
      subjects: [dependency.applications.find((a) => a.id === id)?.name || id],
      execute: () =>
        request("/api/dependency/application", { application_id: id }),
    });
  };
  const renderedEvents =
    mode === "dependency"
      ? (dependency?.events || [])
          .filter((e) => e.application_id === dependency?.application.id)
          .map((e) => ({
            id: e.seq,
            at: e.at,
            title: e.message,
            subtitle: e.kind,
            important: !["observed", "request"].includes(e.kind),
          }))
      : (security?.events || [])
          .slice()
          .reverse()
          .map((e) => ({
            id: e.sequence,
            at: e.recorded_at,
            title: events[e.kind] || e.kind,
            subtitle: e.scope.environment_id,
            important: e.kind !== "security_observed",
          }));
  const findings =
    mode === "security" && security && chosen
      ? Object.values(security.snapshots)
          .flatMap((s) => s.findings)
          .filter((f) => chosen.detail.includes(f.scope.resource_id))
      : [];
  const comparison = security?.protection_comparison;
  const parityCurrent =
    connected &&
    !staleSubjects &&
    comparison?.basis === "configuration_only" &&
    comparison.execution_authority === false &&
    Number.isFinite(Date.parse(comparison.valid_until || "")) &&
    tick < Date.parse(comparison.valid_until || "");

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a className="brand" href="/">
          <span className="brand-mark">
            <Layers3 size={23} strokeWidth={2.5} />
          </span>
          <strong>
            sova<span>.</span>
          </strong>
        </a>
        <div className="workspace-label">
          <span className="workspace-avatar">S</span>
          <div>
            <b>Local workspace</b>
            <small>운영자 검증 환경</small>
          </div>
          <ChevronDown size={14} />
        </div>
        <p className="nav-caption">WORKSPACE</p>
        <nav aria-label="주요 메뉴">
          <button
            className={migrationOpen ? "active" : ""}
            disabled={security?.interfaces?.migration === false}
            title={
              security?.interfaces?.migration === false
                ? "이번 시연 회차에는 연결하지 않았습니다"
                : undefined
            }
            onClick={() => {
              setMigrationOpen(true);
              window.scrollTo({ top: 0 });
            }}
          >
            <ArrowRight size={18} />
            환경 이전
            <span className="nav-dot" />
          </button>
          <button
            className={!migrationOpen && mode === "dependency" ? "active" : ""}
            onClick={() => {
              setMigrationOpen(false);
              setMode(
                security?.interfaces?.dependency === false
                  ? "security"
                  : "dependency",
              );
              requestAnimationFrame(() =>
                document
                  .querySelector(".topology-card")
                  ?.scrollIntoView({ behavior: "smooth", block: "start" }),
              );
            }}
          >
            <GitBranch size={18} />
            워크로드 지도
            <span className="nav-dot" />
          </button>
          <button
            className={!migrationOpen && mode === "security" ? "active" : ""}
            onClick={() => {
              setMigrationOpen(false);
              setMode("security");
              window.scrollTo({ top: 0 });
            }}
          >
            <ShieldCheck size={18} />
            보안·대응
            <span className="nav-dot" />
          </button>
          <button
            onClick={() =>
              (migrationOpen
                ? document.querySelector(".migration-history")
                : timeline.current
              )?.scrollIntoView({
                behavior: "smooth",
                block: "start",
              })
            }
          >
            <Clock3 size={18} />
            실행 타임라인
          </button>
        </nav>
        <div className="sidebar-help">
          <LockKeyhole size={19} />
          <b>확인한 변화만, 안전하게.</b>
          <p>
            실제 관측과 실행 근거를 연결합니다. 미확인 결과는 성공으로 표시하지
            않습니다.
          </p>
        </div>
        <div className="sidebar-bottom">
          <span className="tiny-dot" />
          로컬 데모 연결<small>PYTHON CONTROL PLANE</small>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace<span>/</span>
            <b>
              {migrationOpen
                ? "환경 이전"
                : mode === "dependency"
                  ? "워크로드 지도"
                  : "보안·대응"}
            </b>
          </div>
          <div className="topbar-right">
            <span className="environment-tag">
              <Terminal size={12} /> LOCAL DEMO
            </span>
            <span className="avatar" title="로컬 운영자">
              OP
            </span>
            <button
              className="icon-button"
              aria-label="로그아웃"
              title="로그아웃"
              disabled={signingOut}
              onClick={() => void logout()}
            >
              <LogOut size={16} />
            </button>
          </div>
        </header>
        <main>
          {migrationOpen ? (
            <MigrationPanel />
          ) : (
            <>
              <section className="page-heading">
                <div>
                  <p className="eyebrow">OBSERVE · CONTAIN · VERIFY</p>
                  <h1>
                    {mode === "dependency"
                      ? "연결을 보고, 영향만 좁혀서."
                      : "근거를 확인하고, 안전하게 대응하세요."}
                  </h1>
                  <p>
                    {mode === "dependency"
                      ? "실제 호출과 의존성을 관측하고, 필요한 구성 요소만 격리·복원합니다."
                      : "보호 설정과 보류를 확인한 뒤, 승인한 범위 안에서 실제 대응을 실행합니다."}
                  </p>
                </div>
                <button
                  className="button secondary refresh"
                  onClick={() => void refresh()}
                  disabled={pending}
                >
                  <RefreshCw
                    size={15}
                    className={connection === "loading" ? "spin" : ""}
                  />
                  관측 새로고침
                </button>
              </section>
              <div className="view-strip">
                <div className="view-tabs" aria-label="실행 경로">
                  <button
                    className={mode === "dependency" ? "selected" : ""}
                    disabled={security?.interfaces?.dependency === false}
                    title={
                      security?.interfaces?.dependency === false
                        ? "별도 프로세스 실험은 이번 회차에 연결하지 않았습니다"
                        : undefined
                    }
                    onClick={() => setMode("dependency")}
                  >
                    <GitBranch size={15} />
                    의존성 실험
                  </button>
                  <button
                    className={mode === "security" ? "selected" : ""}
                    onClick={() => setMode("security")}
                  >
                    <ShieldCheck size={15} />
                    Kubernetes 대응
                  </button>
                </div>
                <span
                  className={`connection-badge ${connected ? "online" : ""}`}
                >
                  <span className="tiny-dot" />
                  {stateText}
                </span>
              </div>
              {(connection === "expired" || connection === "unverified") && (
                <div className="notice error-notice" role="alert">
                  <TriangleAlert size={18} />
                  <div>
                    <b>
                      {connection === "expired"
                        ? "운영자 인증을 확인해 주세요."
                        : "현재 관측을 확인할 수 없습니다."}
                    </b>
                    <span>
                      {error ||
                        "마지막 관측은 현재 성공을 의미하지 않습니다. 변경 동작을 잠시 막았습니다."}
                    </span>
                  </div>
                  {connection === "expired" && (
                    <a href="/" className="text-link">
                      로그인 화면 <ArrowUpRight size={14} />
                    </a>
                  )}
                </div>
              )}
              <div className="scope-note">
                <CircleHelp size={15} />
                <span>
                  {mode === "dependency"
                    ? "로컬 프로세스·HTTP·SQLite 기반 실험입니다. 격리는 선택한 시험 프로세스의 종료이며, Kubernetes·방화벽 격리와 구분합니다."
                    : "같은 로컬 k3s의 두 namespace를 사용합니다. 실제 공격 탐지·클라우드 간 이전·DB 및 세션의 무중단 이전은 포함하지 않습니다."}
                </span>
              </div>
              {mode === "security" && (
                <SecurityScenario
                  state={security}
                  connected={connected}
                  tick={tick}
                />
              )}
              <section className="stats-grid" aria-label="관측 요약">
                <Stat
                  label={
                    mode === "dependency"
                      ? "실행 중 구성 요소"
                      : "보안 설정 위반"
                  }
                  value={
                    connected ? (
                      mode === "dependency" ? (
                        <>
                          {dependency?.nodes.filter(
                            (n) => n.observation.available && !n.stale,
                          ).length || 0}
                          <em> / {dependency?.nodes.length || 0}</em>
                        </>
                      ) : staleSubjects ? (
                        "미확인"
                      ) : (
                        Object.values(security?.snapshots || {})
                          .flatMap((s) => s.findings)
                          .filter((f) => f.result === "fail").length
                      )
                    ) : (
                      "—"
                    )
                  }
                  detail={
                    mode === "dependency"
                      ? "독립 프로세스의 실제 health 관측"
                      : "Pod template의 제한된 설정 검사"
                  }
                  icon={
                    mode === "dependency" ? (
                      <Server size={17} />
                    ) : (
                      <ShieldAlert size={17} />
                    )
                  }
                />
                <Stat
                  label={
                    mode === "dependency"
                      ? "격리된 구성 요소"
                      : "독립 보안 보류"
                  }
                  value={
                    connected
                      ? mode === "dependency"
                        ? dependency?.isolated.length || 0
                        : security?.holds.length || 0
                      : "—"
                  }
                  detail={
                    mode === "dependency"
                      ? "종료 확인된 선택 프로세스"
                      : "일반 배포 승인으로 해제되지 않음"
                  }
                  icon={<LockKeyhole size={17} />}
                  tone="amber-stat"
                />
                <Stat
                  label="현재 업무 경로"
                  value={
                    connected
                      ? mode === "dependency"
                        ? requestVerified
                          ? dependency?.last_request?.degraded
                            ? "영향 있음"
                            : "정상 처리"
                          : "응답 미확인"
                        : active?.toUpperCase() || "미확인"
                      : "미확인"
                  }
                  detail={
                    mode === "dependency"
                      ? "필수·선택 의존성의 실제 호출 결과"
                      : `시험 gateway revision ${security?.route.revision ?? "—"}`
                  }
                  icon={<GitBranch size={17} />}
                />
                <Stat
                  label="최근 응답 지연"
                  value={
                    requestVerified ? (
                      <>
                        {currentRequest?.duration_ms?.toFixed(1) || "0"}
                        <em> ms</em>
                      </>
                    ) : (
                      "—"
                    )
                  }
                  detail="시험 probe의 관측값 · 공개 서비스 SLO 아님"
                  icon={<Activity size={17} />}
                />
              </section>
              <section className="workspace-grid">
                <article className="card topology-card">
                  <div className="card-heading">
                    <div>
                      <p className="eyebrow">LIVE WORKLOAD MAP</p>
                      <h2>
                        {mode === "dependency"
                          ? dependency?.application.name || "워크로드 관측 중"
                          : "원본과 대체 실행 환경"}
                      </h2>
                    </div>
                    {mode === "dependency" ? (
                      <div className="select-wrap">
                        <select
                          aria-label="등록 예제 선택"
                          value={dependency?.application.id || ""}
                          onChange={(e) => selectApplication(e.target.value)}
                          disabled={disabled}
                        >
                          {dependency?.applications.map((a) => (
                            <option key={a.id} value={a.id}>
                              {a.name} · {a.node_count}개 구성
                            </option>
                          ))}
                        </select>
                        <ChevronDown size={14} />
                      </div>
                    ) : (
                      <span className="subtle-tag">
                        <Database size={12} />
                        PostgreSQL 실행 원장
                      </span>
                    )}
                  </div>
                  <div className="map-description">
                    <span className="observed-dot" />
                    {mode === "dependency"
                      ? "실선은 실제 호출 결과 · 선택한 노드는 오른쪽에서 제어합니다."
                      : "선언 관계와 실제 검증한 시험 업무 경로를 구분합니다."}
                  </div>
                  <WorkloadMap
                    topology={topology}
                    selected={selected}
                    onSelect={choose}
                    connected={connected}
                    identity={`${mode}-${dependency?.application.id || "k3s"}`}
                  />
                  <div
                    className={`request-receipt ${requestVerified ? "verified" : ""}`}
                  >
                    <span className="receipt-icon">
                      {requestVerified ? (
                        <Check size={18} />
                      ) : (
                        <Radio size={18} />
                      )}
                    </span>
                    <div>
                      <b>
                        {requestVerified
                          ? mode === "dependency" &&
                            dependency?.last_request?.degraded
                            ? "핵심 업무 응답 확인 · 선택 경로 영향 있음"
                            : "실제 시험 요청의 응답을 확인했습니다"
                          : connected
                            ? "현재 업무 응답을 확인하지 못했습니다"
                            : "새 관측을 기다리고 있습니다"}
                      </b>
                      <small>
                        {requestVerified
                          ? `Request ${currentRequest?.request_id.slice(0, 18)} · ${time(mode === "dependency" ? dependency?.last_request?.at : currentProbe?.observed_at)}`
                          : "연결·관측이 없으면 트래픽을 재생하거나 성공으로 표시하지 않습니다."}
                      </small>
                    </div>
                    <span
                      className={`status-chip ${requestVerified ? "healthy" : "unknown"}`}
                    >
                      {requestVerified ? "VERIFIED" : "UNVERIFIED"}
                    </span>
                  </div>
                </article>
                <aside className="card response-panel">
                  <div className="panel-heading">
                    <span className="panel-symbol">
                      {mode === "dependency" ? (
                        <GitBranch size={19} />
                      ) : (
                        <ShieldCheck size={19} />
                      )}
                    </span>
                    <div>
                      <h2>
                        {mode === "dependency"
                          ? "범위를 정한 제어"
                          : "승인 기반 대응"}
                      </h2>
                      <p>
                        {mode === "dependency"
                          ? "선택한 시험 구성 요소만 변경합니다."
                          : "확인한 계획만 실행합니다."}
                      </p>
                    </div>
                  </div>
                  {mode === "dependency" ? (
                    <DependencyControls
                      dependency={dependency}
                      selected={selected}
                      disabled={disabled}
                      pending={pending}
                      faultTarget={faultTarget}
                      choose={choose}
                      setSelected={setSelected}
                      setFaultTarget={setFaultTarget}
                      processAction={processAction}
                      execute={execute}
                    />
                  ) : (
                    <SecurityControls
                      security={security}
                      connected={connected}
                      staleSubjects={staleSubjects}
                      disabled={disabled}
                      tick={tick}
                      active={active}
                      securityAction={securityAction}
                      formatTime={time}
                    />
                  )}
                  {pending && (
                    <div className="action-message">
                      <LoaderCircle size={15} className="spin" />
                      요청 중 · 완료 여부를 확인합니다
                    </div>
                  )}
                  {actionError && (
                    <p className="action-error" role="alert">
                      {actionError}
                    </p>
                  )}
                  {accepted && !actionError && (
                    <p className="action-accepted" role="status">
                      {accepted}
                    </p>
                  )}
                </aside>
              </section>
              {mode === "security" && (
                <section className="card protection-card">
                  <div className="card-heading">
                    <div>
                      <p className="eyebrow">PROTECTION COMPARISON</p>
                      <h2>출발지와 목적지의 보호 설정</h2>
                    </div>
                    <span
                      className={`status-chip ${parityCurrent && comparison?.accepted ? "healthy" : "unknown"}`}
                    >
                      {parityCurrent
                        ? comparison?.accepted
                          ? "목적지 설정 충족"
                          : "미충족·미확인 포함"
                        : "현재 비교 미확인"}
                    </span>
                  </div>
                  <p className="card-explainer">
                    Pod template의 12개 설정만 비교합니다. 전체 환경의 보호
                    동등성이나 실행 승인을 뜻하지 않습니다.
                  </p>
                  <div className="protection-table">
                    <div className="protection-row table-label">
                      <span>보호 목적</span>
                      <span>SOURCE</span>
                      <span>TARGET</span>
                      <span>비교 결과</span>
                    </div>
                    {(parityCurrent ? comparison?.requirements || [] : []).map(
                      (r) => (
                        <div className="protection-row" key={r.requirement_id}>
                          <b>
                            {controls[r.requirement_id] || r.requirement_id}
                          </b>
                          <span>
                            <i
                              className={`tiny-dot ${r.source.state === "satisfied" ? "green" : "red"}`}
                            />
                            {r.source.state === "satisfied"
                              ? "설정 충족"
                              : r.source.state === "violated"
                                ? "위반"
                                : "미확인"}
                          </span>
                          <span>
                            <i
                              className={`tiny-dot ${r.target.state === "satisfied" ? "green" : "red"}`}
                            />
                            {r.target.state === "satisfied"
                              ? "설정 충족"
                              : r.target.state === "violated"
                                ? "위반"
                                : "미확인"}
                          </span>
                          <span
                            className={
                              r.accepted ? "good-text" : "warning-text"
                            }
                          >
                            {(
                              {
                                maintained: "설정상 유지",
                                improved: "설정 보완",
                                regressed: "설정 저하",
                                unmet: "양쪽 위반",
                                unverified: "미확인",
                              } as Record<string, string>
                            )[r.comparison] || "미확인"}
                          </span>
                        </div>
                      ),
                    )}
                  </div>
                  {!parityCurrent && (
                    <div className="empty-inline">
                      유효한 관측이 있어야 비교 결과를 표시합니다.
                    </div>
                  )}
                </section>
              )}
              <section className="evidence-grid">
                <article className="card evidence-card">
                  <div className="card-heading">
                    <div>
                      <p className="eyebrow">RESOURCE EVIDENCE</p>
                      <h2>{chosen?.label || "자원을 선택해 주세요"}</h2>
                    </div>
                    <span
                      className={`status-chip ${chosen?.health || "unknown"}`}
                    >
                      {chosen ? healthLabels[chosen.health] : "미확인"}
                    </span>
                  </div>
                  {chosen ? (
                    <>
                      <dl className="resource-facts">
                        <div>
                          <dt>실행 경계</dt>
                          <dd>
                            {mode === "dependency"
                              ? "등록된 로컬 시험 프로세스"
                              : chosen.lane
                                ? `${chosen.lane.toUpperCase()} · 로컬 k3s`
                                : "로컬 시험 gateway"}
                          </dd>
                        </div>
                        <div>
                          <dt>실행 근거</dt>
                          <dd>
                            {chosen.pid
                              ? `실제 PID ${chosen.pid}`
                              : mode === "dependency"
                                ? "종료 또는 미확인"
                                : "등록 자원 UID·독립 HTTP probe"}
                          </dd>
                        </div>
                        <div>
                          <dt>최근 관측</dt>
                          <dd>{time(chosen.observation)}</dd>
                        </div>
                      </dl>
                      <div className="resource-description">
                        {chosen.detail}
                      </div>
                      {findings.length > 0 && (
                        <div className="finding-list">
                          {findings.map((f) => (
                            <div key={f.control_id}>
                              <span>
                                {controls[f.control_id] || f.control_id}
                              </span>
                              <b
                                className={
                                  connected && f.result === "pass"
                                    ? "good-text"
                                    : "warning-text"
                                }
                              >
                                {!connected
                                  ? "미확인"
                                  : f.result === "pass"
                                    ? "설정상 충족"
                                    : f.result === "fail"
                                      ? "위반"
                                      : "미확인"}
                              </b>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="empty-inline">
                      실제 관측된 구성 요소를 선택하면 근거를 표시합니다.
                    </div>
                  )}
                </article>
                <section
                  ref={timeline}
                  className="card timeline-card"
                  id="timeline"
                >
                  <div className="card-heading">
                    <div>
                      <p className="eyebrow">EXECUTION TIMELINE</p>
                      <h2>변경과 검증의 기록</h2>
                    </div>
                    <span className="subtle-tag">
                      {renderedEvents.length} records
                    </span>
                  </div>
                  <p className="card-explainer">
                    현재 실행 경로의 기록입니다. 연결이 끊기면 과거 이력으로
                    남습니다.
                  </p>
                  <ol className="timeline">
                    {renderedEvents.slice(0, 12).map((event, i) => (
                      <li key={event.id}>
                        <span
                          className={`timeline-dot ${event.important ? "emphasis" : ""}`}
                        >
                          {i === 0 ? <Activity size={12} /> : <span />}
                        </span>
                        <div>
                          <b>{event.title}</b>
                          <small>
                            #{event.id} · {event.subtitle}
                          </small>
                        </div>
                        <time>{time(event.at)}</time>
                      </li>
                    ))}
                  </ol>
                  {!renderedEvents.length && (
                    <div className="empty-inline">
                      <Clock3 size={20} />
                      실제 관측·실행 기록을 기다립니다.
                    </div>
                  )}
                </section>
              </section>
              <footer>
                <span>
                  <Layers3 size={13} /> SOVA · OPERATIONS WORKSPACE
                </span>
                <span>
                  {receivedAt
                    ? `마지막 수신 ${time(new Date(receivedAt).toISOString())}`
                    : "관측 연결 대기"}
                  <i />
                  {expiry ? `${time(expiry)} 실험 종료` : "운영자 로컬 세션"}
                </span>
                <a
                  href={
                    mode === "dependency" ? "http://127.0.0.1:8791" : "/legacy"
                  }
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  기존 실험 화면 <ExternalLink size={12} />
                </a>
              </footer>
            </>
          )}
        </main>
      </div>
      {confirmation && (
        <div
          className="modal-backdrop"
          onClick={() => !pending && setConfirmation(null)}
        >
          <section
            className="confirm-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="confirm-title"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="modal-close icon-button"
              aria-label="닫기"
              onClick={() => setConfirmation(null)}
            >
              <X size={18} />
            </button>
            <span
              className={`confirm-icon ${confirmation.danger ? "danger" : ""}`}
            >
              <ShieldCheck size={25} />
            </span>
            <h2 id="confirm-title">{confirmation.title}</h2>
            <p>{confirmation.description}</p>
            <ul>
              {confirmation.subjects.map((s, i) => (
                <li key={i}>
                  <Check size={13} />
                  <span>{s}</span>
                </li>
              ))}
            </ul>
            <div className="modal-actions">
              <button
                className="button secondary"
                onClick={() => setConfirmation(null)}
              >
                취소
              </button>
              <button
                className={`button ${confirmation.danger ? "danger" : "primary"}`}
                disabled={disabled}
                onClick={() => void execute(confirmation.execute)}
              >
                확인 후 실행
                <ArrowRight size={15} />
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
