import { ApiError } from "./api";

export interface ReadinessRequirement {
  id: string;
  objective: string;
  due_gate: number;
  verifier?: string;
  result?: "pass" | "fail" | "unknown" | "not_applicable";
  evidence_id?: string | null;
  reason?: string;
}
export interface ReadinessArea {
  id: string;
  title: string;
  requirements: ReadinessRequirement[];
  fully_verified?: boolean;
}
export interface Readiness {
  status: "connected" | "unavailable";
  catalog: ReadinessArea[];
  report: null | {
    program_digest: string;
    status: "assessment-only";
    execution_authorized: false;
    all_areas_verified: boolean;
    gate_accepted: boolean;
    carry_forward: string[];
    areas: ReadinessArea[];
  };
  observed_at?: string;
  expires_at?: string;
}

const areaIds = [
  "migration",
  "governance",
  "destination",
  "ai_residency",
  "sandbox",
  "cost_observability",
];
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
function areas(value: unknown): value is ReadinessArea[] {
  if (!Array.isArray(value) || value.length !== 6) return false;
  const ids = new Set<string>();
  for (const area of value) {
    if (
      !object(area) ||
      typeof area.id !== "string" ||
      !areaIds.includes(area.id) ||
      ids.has(area.id) ||
      typeof area.title !== "string" ||
      !Array.isArray(area.requirements) ||
      !area.requirements.length ||
      area.requirements.length > 64
    )
      return false;
    ids.add(area.id);
    const obligations = new Set<string>();
    for (const req of area.requirements) {
      if (
        !object(req) ||
        typeof req.id !== "string" ||
        !req.id.startsWith(area.id + ":") ||
        obligations.has(req.id) ||
        typeof req.objective !== "string" ||
        !Number.isInteger(req.due_gate) ||
        Number(req.due_gate) < 0 ||
        Number(req.due_gate) > 8 ||
        (req.result !== undefined &&
          !["pass", "fail", "unknown", "not_applicable"].includes(
            String(req.result),
          ))
      )
        return false;
      obligations.add(req.id);
    }
  }
  return true;
}
export function readiness(value: unknown, now = Date.now()): Readiness {
  if (
    !object(value) ||
    !["connected", "unavailable"].includes(String(value.status)) ||
    !areas(value.catalog)
  )
    throw new ApiError("여섯 영역의 검증 목록을 확인하지 못했습니다.");
  if (value.status === "unavailable" && value.report === null)
    return value as unknown as Readiness;
  const r = value.report;
  if (
    !object(r) ||
    r.status !== "assessment-only" ||
    r.execution_authorized !== false ||
    !/^[a-f0-9]{64}$/.test(String(r.program_digest)) ||
    !areas(r.areas) ||
    typeof value.observed_at !== "string" ||
    typeof value.expires_at !== "string" ||
    !Number.isFinite(Date.parse(value.observed_at)) ||
    Date.parse(value.observed_at) > now + 1000 ||
    now - Date.parse(value.observed_at) > 12000 ||
    !Number.isFinite(Date.parse(value.expires_at)) ||
    now >= Date.parse(value.expires_at)
  )
    throw new ApiError("현재 이전 계획의 근거를 확인하지 못했습니다.");
  const expected = new Map(
    value.catalog.flatMap((a) =>
      a.requirements.map((r) => [r.id, r.due_gate] as const),
    ),
  );
  const actual = r.areas.flatMap((a) => a.requirements);
  if (
    actual.length !== expected.size ||
    actual.some(
      (req) =>
        expected.get(req.id) !== req.due_gate ||
        !["pass", "fail", "unknown", "not_applicable"].includes(
          String(req.result),
        ) ||
        ((req.result === "pass" || req.result === "not_applicable") &&
          (typeof req.evidence_id !== "string" || !req.evidence_id)),
    )
  )
    throw new ApiError("계획 요구사항과 검증 결과의 연결이 다릅니다.");
  return value as unknown as Readiness;
}
