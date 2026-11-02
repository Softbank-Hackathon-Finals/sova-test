import type { DependencyState, SecurityState } from "./types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status = 0,
  ) {
    super(message);
  }
}
export function operatorProof(
  storage: Pick<Storage, "getItem"> = localStorage,
  now = Date.now(),
): string {
  try {
    const item = JSON.parse(storage.getItem("sova_operator_proof") || "{}");
    return typeof item.token === "string" && now < Date.parse(item.expires_at)
      ? item.token
      : "";
  } catch {
    return "";
  }
}
export async function request<T>(
  path: string,
  body?: unknown,
  signal?: AbortSignal,
): Promise<T> {
  const proof = operatorProof();
  if (!proof)
    throw new ApiError(
      "운영자 로그인이 만료되었습니다. 새 로컬 로그인 주소가 필요합니다.",
      401,
    );
  let response: Response;
  try {
    response = await fetch(path, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "X-Sova-CSRF": proof,
        ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: signal || AbortSignal.timeout(body === undefined ? 10000 : 20000),
    });
  } catch {
    throw new ApiError(
      body === undefined
        ? "연결을 확인하지 못했습니다."
        : "요청 결과가 불확실합니다. 상태를 확인하세요. 자동 재시도하지 않습니다.",
    );
  }
  if (!response.ok)
    throw new ApiError(
      response.status === 403 ||
        response.status === 401 ||
        response.status === 404
        ? "로그인 또는 실행 경로를 확인할 수 없습니다."
        : "현재 요청을 확인하지 못했습니다. 근거를 확인한 뒤 다시 검토하세요.",
      response.status,
    );
  try {
    return (await response.json()) as T;
  } catch {
    throw new ApiError("서버 상태 형식을 확인할 수 없습니다.");
  }
}
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
export function dependencyState(value: unknown): DependencyState {
  if (
    !object(value) ||
    !object(value.application) ||
    !Array.isArray(value.nodes) ||
    !value.nodes.length ||
    !Array.isArray(value.edges) ||
    !Array.isArray(value.events) ||
    !Array.isArray(value.applications) ||
    typeof value.revision !== "number" ||
    typeof value.now !== "number" ||
    !Number.isFinite(value.now) ||
    typeof value.expires_at !== "string" ||
    !Number.isFinite(Date.parse(value.expires_at)) ||
    Date.now() >= Date.parse(value.expires_at) ||
    Date.now() - Number(value.now) * 1000 > 15000 ||
    Number(value.now) * 1000 > Date.now() + 5000 ||
    !value.nodes.every(
      (n) =>
        object(n) &&
        typeof n.id === "string" &&
        typeof n.name === "string" &&
        ["healthy", "impacted", "failed", "isolated", "unknown"].includes(
          String(n.state),
        ) &&
        object(n.observation),
    )
  ) {
    throw new ApiError("최신 워크로드 관측을 확인할 수 없습니다.");
  }
  return value as unknown as DependencyState;
}
export function securityState(value: unknown): SecurityState {
  if (
    !object(value) ||
    !object(value.snapshots) ||
    !object(value.route) ||
    !object(value.probes) ||
    !Array.isArray(value.holds) ||
    !Array.isArray(value.events) ||
    !Array.isArray(value.steps) ||
    typeof value.at !== "string" ||
    Date.now() - Date.parse(value.at) > 15000 ||
    !Number.isFinite(Date.parse(value.at)) ||
    Date.parse(value.at) > Date.now() + 5000 ||
    typeof value.expires_at !== "string" ||
    !Number.isFinite(Date.parse(value.expires_at)) ||
    Date.now() >= Date.parse(value.expires_at) ||
    !["blue", "green"].every(
      (env) =>
        object((value.snapshots as Record<string, unknown>)[env]) &&
        object(
          (value.snapshots as Record<string, Record<string, unknown>>)[env]
            .graph,
        ) &&
        Array.isArray(
          (
            value.snapshots as Record<
              string,
              { graph: Record<string, unknown> }
            >
          )[env].graph.resources,
        ),
    )
  ) {
    throw new ApiError("최신 보안 관측을 확인할 수 없습니다.");
  }
  return value as unknown as SecurityState;
}

export function mergeSecurityEvents(
  current: SecurityState["events"],
  incoming: SecurityState["events"],
): SecurityState["events"] {
  const values = new Map(current.map((e) => [e.sequence, e]));
  for (const event of incoming) {
    if (!Number.isSafeInteger(event.sequence) || event.sequence < 1)
      throw new ApiError("잘못된 실행 기록 순서입니다.");
    values.set(event.sequence, event);
  }
  return [...values.values()]
    .sort((a, b) => a.sequence - b.sequence)
    .slice(-500);
}
