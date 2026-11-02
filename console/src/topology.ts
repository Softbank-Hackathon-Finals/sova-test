import type {
  DependencyState,
  DisplayEdge,
  Health,
  SecurityState,
  Topology,
} from "./types";

export const healthLabels: Record<Health, string> = {
  healthy: "응답 확인",
  impacted: "영향 확인",
  failed: "문제 확인",
  isolated: "격리 확인",
  unknown: "미확인",
};
export function fresh(
  value: string | number | undefined,
  maxAge = 8000,
  now = Date.now(),
): boolean {
  const time =
    typeof value === "number" ? value * 1000 : Date.parse(value || "");
  return Number.isFinite(time) && time <= now + 1000 && now - time < maxAge;
}
export function dependencyTopology(
  state: DependencyState,
  connected: boolean,
): Topology {
  const trace =
    connected && fresh(state.last_request?.at) ? state.last_request : null;
  const byId = new Map(state.nodes.map((n) => [n.id, n]));
  return {
    nodes: state.nodes.map((n) => ({
      key: n.id,
      label: n.name,
      subtitle: n.kind === "storage" ? "SQLite 시험 저장소" : "HTTP 프로세스",
      kind: n.kind,
      health: !connected || n.stale ? "unknown" : n.state,
      detail: n.description,
      pid: n.observation.pid,
      observation: new Date(n.observation.at * 1000).toISOString(),
      potential:
        connected &&
        n.state !== "failed" &&
        n.state !== "isolated" &&
        n.state !== "impacted" &&
        state.edges.some(
          (e) =>
            (e.source === n.id && byId.get(e.target)?.state === "failed") ||
            (e.target === n.id && byId.get(e.source)?.state === "failed"),
        ),
    })),
    edges: state.edges.map((e) => {
      const observed = trace?.edges.find(
        (x) => x.source === e.source && x.target === e.target,
      );
      const cut =
        connected &&
        [e.source, e.target].some((id) => byId.get(id)?.state === "isolated");
      const status = !connected
        ? "idle"
        : cut
          ? "cut"
          : !observed
            ? "idle"
            : !observed.ok || observed.degraded
              ? "error"
              : "flow";
      return {
        id: `${e.source}-${e.target}`,
        source: e.source,
        target: e.target,
        label: `${e.required ? "필수" : "선택"} · ${status === "cut" ? "차단" : status === "flow" ? "응답" : status === "error" ? "영향" : "미관측"}`,
        state: status,
        requestId: observed && !cut ? trace?.request_id : undefined,
      };
    }),
  };
}
export function activeEnvironment(state: SecurityState): string | undefined {
  return Object.entries(state.snapshots).find(([, s]) =>
    s.graph.resources.some(
      (r) => r.scope.environment_id === state.route.environment_id,
    ),
  )?.[0];
}
export function securityTopology(
  state: SecurityState,
  connected: boolean,
): Topology {
  const active = activeEnvironment(state);
  const probe = active ? state.probes[active] : undefined;
  const live = connected && !!probe?.ok && fresh(probe.observed_at);
  const nodes: Topology["nodes"] = [
    {
      key: "gateway",
      label: "시험 진입점",
      subtitle: "로컬 gateway · Pod probe",
      kind: "edge",
      health: live ? "healthy" : "unknown",
      detail:
        "PostgreSQL에 기록된 시험 경로와 독립 Pod의 실제 HTTP 응답을 확인합니다. 공개 ALB가 아닙니다.",
    },
  ];
  const edges: DisplayEdge[] = [];
  for (const [env, snapshot] of Object.entries(state.snapshots)) {
    const p = state.probes[env];
    const current =
      connected && !snapshot.stale && fresh(snapshot.graph.observed_at, 15000);
    const isolated =
      current &&
      env === "blue" &&
      state.isolation_proof?.status === "confirmed_applied" &&
      fresh(state.isolation_proof.observed_at, 12000) &&
      fresh(p?.observed_at) &&
      p?.new_connection_blocked;
    for (const resource of snapshot.graph.resources) {
      const failed = snapshot.findings.filter(
        (f) =>
          f.scope.resource_id === resource.scope.resource_id &&
          f.result === "fail",
      ).length;
      nodes.push({
        key: `${env}:${resource.id}`,
        label: resource.name,
        subtitle: resource.id.startsWith("service:")
          ? "Kubernetes Service"
          : "Kubernetes Deployment",
        kind: resource.kind,
        lane: env,
        health: !current
          ? "unknown"
          : isolated
            ? "isolated"
            : failed
              ? "failed"
              : p?.ok && fresh(p.observed_at)
                ? "healthy"
                : "unknown",
        detail: `${resource.scope.environment_id} · ${resource.scope.resource_id}${failed ? ` · 설정 위반 ${failed}건` : ""}`,
        observation: snapshot.graph.observed_at,
      });
    }
    const subjects = new Set(snapshot.graph.resources.map((r) => r.id));
    for (const relation of snapshot.graph.relations) {
      if (!subjects.has(relation.source) || !subjects.has(relation.target))
        continue;
      edges.push({
        id: `${env}:${relation.source}-${relation.target}`,
        source: `${env}:${relation.source}`,
        target: `${env}:${relation.target}`,
        label: "선언 관계",
        state: isolated ? "cut" : "idle",
      });
    }
    const entry =
      snapshot.graph.resources.find((r) => r.kind === "edge") ||
      snapshot.graph.resources[0];
    if (entry)
      edges.push({
        id: `route-${env}`,
        source: "gateway",
        target: `${env}:${entry.id}`,
        label: isolated
          ? "새 연결 차단"
          : active === env
            ? "현재 업무 경로"
            : "대기 경로",
        state: !current
          ? "idle"
          : isolated
            ? "cut"
            : active === env && live
              ? "flow"
              : "idle",
        requestId: active === env && live ? probe?.request_id : undefined,
      });
  }
  return { nodes, edges };
}

export function layout(
  topology: Topology,
): Record<string, { x: number; y: number }> {
  if (topology.nodes.some((n) => n.lane)) {
    const positions: Record<string, { x: number; y: number }> = {
      gateway: { x: 0, y: 145 },
    };
    for (const lane of ["blue", "green"])
      topology.nodes
        .filter((n) => n.lane === lane)
        .sort((a, b) => Number(b.kind === "edge") - Number(a.kind === "edge"))
        .forEach((n, i) => {
          positions[n.key] = { x: 320 + i * 300, y: lane === "blue" ? 0 : 290 };
        });
    return positions;
  }
  const degree = new Map(topology.nodes.map((n) => [n.key, 0]));
  const ranks = new Map(topology.nodes.map((n) => [n.key, 0]));
  for (const e of topology.edges)
    if (degree.has(e.target) && degree.has(e.source))
      degree.set(e.target, degree.get(e.target)! + 1);
  const queue = [...degree].filter(([, d]) => d === 0).map(([id]) => id);
  const visited = new Set<string>();
  for (let i = 0; i < queue.length; i++) {
    const id = queue[i];
    visited.add(id);
    for (const e of topology.edges.filter(
      (x) => x.source === id && degree.has(x.target),
    )) {
      ranks.set(e.target, Math.max(ranks.get(e.target)!, ranks.get(id)! + 1));
      degree.set(e.target, degree.get(e.target)! - 1);
      if (!degree.get(e.target)) queue.push(e.target);
    }
  }
  // Cycles remain a bounded review group, rather than recursing indefinitely.
  const last = Math.max(0, ...ranks.values()) + 1;
  for (const n of topology.nodes)
    if (!visited.has(n.key)) ranks.set(n.key, last);
  const groups = new Map<number, string[]>();
  for (const [id, rank] of ranks)
    groups.set(rank, [...(groups.get(rank) || []), id]);
  const positions: Record<string, { x: number; y: number }> = {};
  for (const [rank, ids] of groups)
    ids.forEach((id, i) => {
      positions[id] = { x: rank * 270, y: i * 185 - (ids.length - 1) * 92.5 };
    });
  return positions;
}
