import { ApiError } from "../../api";
import type { Topology } from "../../types";

export interface MigrationWorkflow {
  id: string;
  target: "aws" | "vm";
  status: string;
  steps: {
    id: string;
    label: string;
    status: string;
    started_at?: number;
    completed_at?: number;
  }[];
}
export interface MigrationState {
  profile?: "eks-rke2-stateless-v1";
  recovery_required?: boolean;
  now: number;
  route: "aws" | "vm";
  route_revision: number;
  revision: string;
  expires_at: string;
  scope: string;
  observations: Record<
    string,
    {
      available: boolean;
      stale?: boolean;
      observed_at: number;
      latency_ms?: number;
      pod_uid?: string;
    }
  >;
  workloads: Record<
    string,
    {
      runtime: string;
      database: false;
      namespace?: string;
      deployment_uid?: string;
      pod_uids?: string[];
      image?: string;
    }
  >;
  operation: MigrationWorkflow | null;
  workflows: MigrationWorkflow[];
  events: {
    seq: number;
    at: number;
    kind: string;
    environment: string;
    detail: string;
  }[];
  security: { state: string };
  metrics: {
    sample_count: number;
    success_percent: number | null;
    p95_ms: number | null;
  };
  requests: {
    id: string;
    at: number;
    environment: string;
    ok: boolean;
    latency_ms: number;
    pod_uid?: string;
  }[];
}
export type MigrationEnvelope =
  | { status: "connected"; state: MigrationState }
  | { status: "unavailable"; state: null; reason: string };

const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
export function migrationEnvelope(
  value: unknown,
  now = Date.now(),
): MigrationEnvelope {
  if (!object(value))
    throw new ApiError("이전 관측 형식을 확인할 수 없습니다.");
  if (
    value.status === "unavailable" &&
    value.state === null &&
    typeof value.reason === "string"
  )
    return value as MigrationEnvelope;
  const s = value.state;
  if (
    value.status !== "connected" ||
    !object(s) ||
    (s.profile !== undefined && s.profile !== "eks-rke2-stateless-v1") ||
    !["aws", "vm"].includes(String(s.route)) ||
    !Number.isSafeInteger(s.route_revision) ||
    Number(s.route_revision) < 1 ||
    !/^[a-f0-9]{64}$/.test(String(s.revision)) ||
    typeof s.now !== "number" ||
    !Number.isFinite(s.now) ||
    now - s.now * 1000 > 15000 ||
    s.now * 1000 > now + 5000 ||
    typeof s.expires_at !== "string" ||
    !Number.isFinite(Date.parse(s.expires_at)) ||
    now >= Date.parse(s.expires_at) ||
    !object(s.workloads) ||
    !object(s.observations) ||
    !object(s.metrics) ||
    !object(s.security) ||
    !["aws", "vm"].every(
      (e) =>
        object(s.workloads) &&
        object(s.workloads[e]) &&
        s.workloads[e].database === false,
    ) ||
    !Array.isArray(s.events) ||
    !Array.isArray(s.workflows) ||
    !Array.isArray(s.requests)
  )
    throw new ApiError("최신 AWS·VM 관측을 확인할 수 없습니다.");
  return value as unknown as MigrationEnvelope;
}

export function migrationTopology(
  state: MigrationState | null,
  current: boolean,
  now = Date.now(),
  expanded = false,
): Topology {
  const recent = state?.requests.find(
    (r) => r.at * 1000 <= now + 1000 && now - r.at * 1000 < 8000,
  );
  const healthy = (side: string) => {
    const o = state?.observations[side];
    return (
      current &&
      o &&
      !o.stale &&
      Number.isFinite(o.observed_at) &&
      now - o.observed_at * 1000 < 8000 &&
      o.observed_at * 1000 <= now + 1000
    );
  };
  if (expanded && state?.profile === "eks-rke2-stateless-v1") {
    const graph: Topology = {
      nodes: [
        {
          key: "gateway",
          label: "고정 시험 진입점",
          subtitle: "실제 요청의 Pod UID로 연결 확인",
          kind: "edge",
          health: "unknown",
          detail: "로컬 사설 터널 · 공개 ALB/DNS 아님",
        },
      ],
      edges: [],
    };
    for (const side of ["aws", "vm"] as const) {
      const registered = state.workloads[side];
      const lane = side === "aws" ? "blue" : "green";
      graph.nodes.push({
        key: side,
        label: side === "aws" ? "EKS · Deployment" : "RKE2 · Deployment",
        subtitle: registered.namespace || "등록 정보 없음",
        lane,
        kind: "service",
        health: "unknown",
        detail: "등록된 배치 구성 · 현재 상태는 Pod의 실제 응답과 별도",
      });
      for (const [index, uid] of (registered.pod_uids || []).entries()) {
        const key = side + ":" + uid;
        const observation = state.observations[side];
        const observedPod =
          healthy(side) &&
          observation?.available &&
          observation.pod_uid === uid;
        graph.nodes.push({
          key,
          label: `${side === "aws" ? "EKS" : "RKE2"} Pod ${index + 1}`,
          subtitle: uid.slice(0, 18),
          kind: "service",
          lane,
          health: observedPod ? "healthy" : "unknown",
          detail: observedPod
            ? "등록 UID와 실제 HTTP 응답 일치"
            : "등록된 Pod · 현재 응답 미확인",
        });
        graph.edges.push({
          id: "owns:" + key,
          source: side,
          target: key,
          label: "등록된 배치 관계 · 요청 아님",
          state: "idle",
        });
        if (observedPod) {
          const flowing =
            current &&
            state.route === side &&
            recent?.environment === side &&
            recent.pod_uid === uid;
          graph.edges.push({
            id: "request:" + key,
            source: "gateway",
            target: key,
            label: flowing
              ? "실제 업무 요청 응답"
              : "시험 터널 응답 확인 · 업무 요청 대기",
            state: flowing ? (recent.ok ? "flow" : "error") : "idle",
            requestId: flowing ? recent.id : undefined,
          });
        }
      }
    }
    return graph;
  }
  return {
    nodes: [
      {
        key: "gateway",
        label: "고정 시험 진입점",
        subtitle: "등록된 시험 요청 중계",
        kind: "edge",
        health: "unknown",
        detail: "AWS ALB·DNS 전환이 아닌 시험 게이트웨이",
      },
      ...(["aws", "vm"] as const).map((side) => ({
        key: side,
        label: side === "aws" ? "AWS 앱" : "온프렘 VM 앱",
        lane: side === "aws" ? "blue" : "green",
        subtitle: state?.workloads[side]?.runtime || "실행 상태 미확인",
        kind: "service",
        health: healthy(side)
          ? state!.observations[side].available
            ? ("healthy" as const)
            : ("failed" as const)
          : ("unknown" as const),
        detail: "미리 실행한 무상태 앱 · 업무 DB·세션 이전 없음",
      })),
    ],
    edges: (["aws", "vm"] as const).map((side) => {
      const active = current && state?.route === side;
      const observed = active && recent?.environment === side;
      return {
        id: "entry-" + side,
        source: "gateway",
        target: side,
        label: active
          ? "적용 경로 · " +
            (observed
              ? recent.ok
                ? "요청 응답 확인"
                : "요청 실패"
              : "업무 요청 대기")
          : current
            ? "대기 경로"
            : "미확인",
        state: observed
          ? recent.ok
            ? ("flow" as const)
            : ("error" as const)
          : ("idle" as const),
        requestId: observed ? recent.id : undefined,
      };
    }),
  };
}
