export type Mode = "dependency" | "security";
export type Health = "healthy" | "impacted" | "failed" | "isolated" | "unknown";
export type Connection = "loading" | "connected" | "unverified" | "expired";

export interface DependencyNode {
  id: string;
  name: string;
  kind: string;
  description: string;
  state: Health;
  stale: boolean;
  called: boolean;
  dependencies: { target: string; required: boolean }[];
  observation: {
    pid?: number | null;
    at: number;
    available: boolean;
    rows?: number;
    fault?: boolean;
  };
}
export interface RequestTrace {
  request_id: string;
  at: number;
  ok: boolean;
  degraded: boolean;
  duration_ms: number;
  edges: { source: string; target: string; ok: boolean; degraded?: boolean }[];
  spans: { node: string; [key: string]: unknown }[];
  failures: { node: string }[];
}
export interface DependencyState {
  now: number;
  revision: number;
  expires_at: string;
  application: {
    id: string;
    name: string;
    description: string;
    entry: string;
    fault_default: string;
    isolation_default: string[];
  };
  applications: { id: string; name: string; node_count: number }[];
  nodes: DependencyNode[];
  edges: { source: string; target: string; required: boolean }[];
  last_request: RequestTrace | null;
  events: {
    seq: number;
    at: number;
    message: string;
    kind: string;
    nodes: string[];
    application_id: string;
  }[];
  isolated: string[];
  requests: number;
  successes: number;
  scope: string;
}
export interface Scope {
  tenant_id: string;
  application_id: string;
  environment_id: string;
  resource_id: string;
}
export interface Resource {
  id: string;
  node_id?: string;
  name: string;
  kind: string;
  scope: Scope;
}
export interface Finding {
  control_id: string;
  family: string;
  result: string;
  basis: string;
  scope: Scope;
  observed_at: string;
  valid_until: string;
  resource_revision: string;
}
export interface SecurityState {
  interfaces?: { dependency: boolean; migration: boolean };
  at: string;
  expires_at: string;
  application_id: string;
  snapshots: Record<
    string,
    {
      digest: string;
      stale: boolean;
      graph: {
        observed_at: string;
        resources: Resource[];
        relations: { source: string; target: string; [key: string]: unknown }[];
      };
      findings: Finding[];
    }
  >;
  holds: { hold_id: string; scope: Scope; reason: string; raised_at: string }[];
  route: { environment_id: string; revision: number };
  probes: Record<
    string,
    {
      ok: boolean;
      target: string;
      request_id: string;
      observed_at: string;
      duration_ms?: number;
      new_connection_blocked?: boolean;
    }
  >;
  phase: string;
  busy: boolean;
  error: string | null;
  steps: {
    action: string;
    status: string;
    at: string;
    effect_digest: string;
    historical?: boolean;
  }[];
  operation: {
    status: string;
    operation_id: string;
    completion_digest?: string;
    read_only_recovered?: boolean;
  } | null;
  prepared: {
    plan_digest: string;
    expires_at: string;
    actions: string[];
  } | null;
  isolation_proof: { status: string; observed_at: string } | null;
  protection_comparison: {
    basis: string;
    execution_authority: boolean;
    accepted: boolean;
    valid_until?: string;
    requirements?: {
      requirement_id: string;
      comparison: string;
      accepted: boolean;
      source: { state: string };
      target: { state: string };
    }[];
  };
  events: {
    sequence: number;
    kind: string;
    recorded_at: string;
    scope: Scope;
    details: Record<string, unknown>;
  }[];
  csrf?: string;
}
export interface DisplayNode {
  key: string;
  label: string;
  subtitle: string;
  kind: string;
  health: Health;
  lane?: string;
  detail: string;
  pid?: number | null;
  observation?: string;
  potential?: boolean;
  selected?: boolean;
}
export interface DisplayEdge {
  id: string;
  source: string;
  target: string;
  label: string;
  state: "flow" | "error" | "cut" | "idle";
  requestId?: string;
}
export interface Topology {
  nodes: DisplayNode[];
  edges: DisplayEdge[];
}
