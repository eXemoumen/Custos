import {
  AuditEventItem,
  GuardrailRule,
  GuardrailTestResult,
  HealthStatus,
  PolicyRuleItem,
  PromptItem,
  SensitiveAsset,
  ThreatPattern,
} from "./types";

const BASE_URL = process.env.NEXT_PUBLIC_CUSTOS_API || "http://localhost:8000";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const url = `${BASE_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
  });

  if (!res.ok) {
    let errorMsg = `API Error ${res.status}: ${res.statusText}`;
    try {
      const body = await res.json();
      if (body.detail) errorMsg = body.detail;
    } catch {
      // fallback
    }
    throw new Error(errorMsg);
  }

  return res.json();
}

export const api = {
  // Health
  getHealth: () => request<HealthStatus>("/api/v1/health"),

  // Prompts (Human-in-the-Loop)
  getPrompts: () => request<PromptItem[]>("/api/v1/prompts"),
  respondPrompt: (requestId: string, choice: string, approver = "control_plane_admin") =>
    request<{ status: string; choice: string }>(`/api/v1/prompts/${requestId}/respond`, {
      method: "POST",
      body: JSON.stringify({ choice, approver }),
    }),

  // Knowledge Base - Assets
  getAssets: () => request<SensitiveAsset[]>("/api/v1/knowledge/assets"),
  createAsset: (asset: Omit<SensitiveAsset, "id">) =>
    request<SensitiveAsset>("/api/v1/knowledge/assets", {
      method: "POST",
      body: JSON.stringify(asset),
    }),
  deleteAsset: (id: string) =>
    request<{ status: string }>(`/api/v1/knowledge/assets/${id}`, { method: "DELETE" }),

  // Knowledge Base - Rules
  getRules: () => request<GuardrailRule[]>("/api/v1/knowledge/rules"),
  createRule: (rule: Omit<GuardrailRule, "id">) =>
    request<GuardrailRule>("/api/v1/knowledge/rules", {
      method: "POST",
      body: JSON.stringify(rule),
    }),
  deleteRule: (id: string) =>
    request<{ status: string }>(`/api/v1/knowledge/rules/${id}`, { method: "DELETE" }),

  // Knowledge Base - Threats
  getThreats: () => request<ThreatPattern[]>("/api/v1/knowledge/threats"),
  createThreat: (threat: Omit<ThreatPattern, "id">) =>
    request<ThreatPattern>("/api/v1/knowledge/threats", {
      method: "POST",
      body: JSON.stringify(threat),
    }),
  deleteThreat: (id: string) =>
    request<{ status: string }>(`/api/v1/knowledge/threats/${id}`, { method: "DELETE" }),

  // Recompile & Test
  recompileKB: () =>
    request<{ status: string; message: string }>("/api/v1/knowledge/compile", {
      method: "POST",
    }),
  testGuardrail: (tool: string, args: Record<string, unknown>, user_message?: string) =>
    request<GuardrailTestResult>("/api/v1/knowledge/test", {
      method: "POST",
      body: JSON.stringify({ tool, args, user_message }),
    }),

  // Policies
  getPolicies: () =>
    request<{ default: string; total_rules: number; rules: PolicyRuleItem[] }>("/api/v1/policies"),

  // Audit
  getAuditEvents: (limit = 50, offset = 0) =>
    request<{ total: number; limit: number; offset: number; events: AuditEventItem[] }>(
      `/api/v1/audit?limit=${limit}&offset=${offset}`
    ),
  verifyAudit: () =>
    request<{ verified: boolean; event_count: number; message: string; errors?: string[] }>(
      "/api/v1/audit/verify",
      { method: "POST" }
    ),

  // Agents
  getAgents: () => request<import("./types").AgentRecord[]>("/api/v1/agents"),
  quarantineAgent: (agentId: string) =>
    request<{ status: string; agent_id: string; success: boolean }>(
      `/api/v1/agents/${agentId}/quarantine`,
      { method: "POST" }
    ),
  releaseAgent: (agentId: string) =>
    request<{ status: string; agent_id: string; success: boolean }>(
      `/api/v1/agents/${agentId}/release`,
      { method: "POST" }
    ),

  // Invocations (Real Gateway Tool Execution)
  decideInvocation: (payload: import("./types").DecideRequest) =>
    request<import("./types").DecideResponse>("/api/v1/invocations/decide", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
};
