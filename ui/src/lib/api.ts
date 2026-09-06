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

const BASE_URL = process.env.NEXT_PUBLIC_CUSTOS_API ?? "";

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
      if (body.detail) {
        if (typeof body.detail === "string") {
          errorMsg = body.detail;
        } else if (Array.isArray(body.detail)) {
          errorMsg = body.detail
            .map((item: any) => {
              if (typeof item === "string") return item;
              if (item && typeof item === "object") {
                const loc = Array.isArray(item.loc) ? item.loc.slice(1).join(".") : "";
                const msg = item.msg || JSON.stringify(item);
                return loc ? `${loc}: ${msg}` : msg;
              }
              return String(item);
            })
            .join("; ");
        } else if (typeof body.detail === "object" && body.detail !== null) {
          errorMsg = JSON.stringify(body.detail);
        } else {
          errorMsg = String(body.detail);
        }
      }
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
  getPrompt: (requestId: string) => request<PromptItem>(`/api/v1/prompts/${requestId}`),
  respondPrompt: (requestId: string, choice: string, approver = "control_plane_admin") =>
    request<{ status: string; choice: string }>(`/api/v1/prompts/${requestId}/respond`, {
      method: "POST",
      body: JSON.stringify({ choice, approver }),
    }),
  cancelPrompt: (requestId: string, reason?: string) =>
    request<{ status: string; request_id: string }>(`/api/v1/prompts/${requestId}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  batchRespondPrompts: (resolutions: Array<{ request_id: string; choice: string; approver?: string }>) =>
    request<{ results: Array<{ request_id: string; success: boolean }>; total: number }>("/api/v1/prompts/batch-respond", {
      method: "POST",
      body: JSON.stringify({ resolutions }),
    }),

  // Knowledge Base - Assets
  getAssets: () => request<SensitiveAsset[]>("/api/v1/knowledge/assets"),
  getAsset: (id: string) => request<SensitiveAsset>(`/api/v1/knowledge/assets/${id}`),
  createAsset: (asset: Omit<SensitiveAsset, "id">) =>
    request<SensitiveAsset>("/api/v1/knowledge/assets", {
      method: "POST",
      body: JSON.stringify(asset),
    }),
  toggleAsset: (id: string) =>
    request<SensitiveAsset>(`/api/v1/knowledge/assets/${id}/toggle`, { method: "POST" }),
  deleteAsset: (id: string) =>
    request<{ status: string }>(`/api/v1/knowledge/assets/${id}`, { method: "DELETE" }),

  // Knowledge Base - Rules
  getRules: () => request<GuardrailRule[]>("/api/v1/knowledge/rules"),
  getRule: (id: string) => request<GuardrailRule>(`/api/v1/knowledge/rules/${id}`),
  createRule: (rule: Omit<GuardrailRule, "id">) =>
    request<GuardrailRule>("/api/v1/knowledge/rules", {
      method: "POST",
      body: JSON.stringify(rule),
    }),
  toggleRule: (id: string) =>
    request<GuardrailRule>(`/api/v1/knowledge/rules/${id}/toggle`, { method: "POST" }),
  deleteRule: (id: string) =>
    request<{ status: string }>(`/api/v1/knowledge/rules/${id}`, { method: "DELETE" }),

  // Knowledge Base - Threats
  getThreats: () => request<ThreatPattern[]>("/api/v1/knowledge/threats"),
  getThreat: (id: string) => request<ThreatPattern>(`/api/v1/knowledge/threats/${id}`),
  createThreat: (threat: Omit<ThreatPattern, "id">) =>
    request<ThreatPattern>("/api/v1/knowledge/threats", {
      method: "POST",
      body: JSON.stringify(threat),
    }),
  updateThreat: (id: string, threat: Partial<ThreatPattern>) =>
    request<ThreatPattern>(`/api/v1/knowledge/threats/${id}`, {
      method: "PUT",
      body: JSON.stringify(threat),
    }),
  toggleThreat: (id: string) =>
    request<ThreatPattern>(`/api/v1/knowledge/threats/${id}/toggle`, { method: "POST" }),
  deleteThreat: (id: string) =>
    request<{ status: string }>(`/api/v1/knowledge/threats/${id}`, { method: "DELETE" }),

  // Knowledge Base - Import & Export
  exportKnowledge: () => request<Record<string, unknown>>("/api/v1/knowledge/export"),
  importKnowledge: (data: Record<string, unknown>, overwrite = false) =>
    request<{
      status: string;
      message: string;
      asset_count: number;
      rule_count: number;
      threat_count: number;
    }>("/api/v1/knowledge/import", {
      method: "POST",
      body: JSON.stringify({ data, overwrite }),
    }),

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
  reloadPolicy: () =>
    request<{ status: string; message: string; default: string; total_rules: number }>(
      "/api/v1/policies/reload",
      { method: "POST" }
    ),
  validatePolicy: (payload: { policy?: Record<string, unknown>; yaml_content?: string }) =>
    request<{
      valid: boolean;
      rule_count?: number;
      default?: string;
      message?: string;
      error?: string;
    }>("/api/v1/policies/validate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getPolicyOverlays: () =>
    request<{ total_overlays: number; overlays: Array<{ id: string; rule_count: number }> }>(
      "/api/v1/policies/overlays"
    ),

  // Audit
  getAuditEvents: (limit = 50, offset = 0, userId?: string) => {
    const url = `/api/v1/audit?limit=${limit}&offset=${offset}${userId ? `&user_id=${encodeURIComponent(userId)}` : ""}`;
    return request<{ total: number; limit: number; offset: number; events: AuditEventItem[] }>(url);
  },
  getAuditStats: () =>
    request<{
      total_events: number;
      decision_counts: Record<string, number>;
      top_tools: Array<[string, number]>;
      high_risk_events_count: number;
    }>("/api/v1/audit/stats"),
  verifyAudit: () =>
    request<{ verified: boolean; event_count: number; message: string; errors?: string[] }>(
      "/api/v1/audit/verify",
      { method: "POST" }
    ),

  // Agents
  getAgents: () => request<import("./types").AgentRecord[]>("/api/v1/agents"),
  getAgent: (agentId: string) => request<import("./types").AgentRecord>(`/api/v1/agents/${agentId}`),
  registerAgent: (agent: {
    id: string;
    name?: string;
    framework?: string;
    policy_profile?: string;
    description?: string;
  }) =>
    request<import("./types").AgentRecord>("/api/v1/agents", {
      method: "POST",
      body: JSON.stringify(agent),
    }),
  updateAgent: (
    agentId: string,
    updates: {
      name?: string;
      framework?: string;
      policy_profile?: string;
      description?: string;
    }
  ) =>
    request<import("./types").AgentRecord>(`/api/v1/agents/${agentId}`, {
      method: "PUT",
      body: JSON.stringify(updates),
    }),
  deleteAgent: (agentId: string) =>
    request<{ status: string; agent_id: string; success: boolean }>(`/api/v1/agents/${agentId}`, {
      method: "DELETE",
    }),
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
  decideBatch: (invocations: Array<import("./types").DecideRequest>) =>
    request<{ total: number; results: Array<import("./types").DecideResponse> }>(
      "/api/v1/invocations/decide-batch",
      {
        method: "POST",
        body: JSON.stringify({ invocations }),
      }
    ),

  // Settings
  getSettings: () =>
    request<{
      default_action: string;
      ollama_url: string;
      ollama_model: string;
      hmac_key_configured: boolean;
      hmac_key_masked: string;
    }>("/api/v1/settings"),
  updateSettings: (payload: {
    default_action?: string;
    ollama_url?: string;
    ollama_model?: string;
    hmac_key?: string;
  }) =>
    request<{ status: string; message: string }>("/api/v1/settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  testOllama: (ollamaUrl?: string) =>
    request<{
      reachable: boolean;
      url: string;
      models?: string[];
      message?: string;
      error?: string;
    }>("/api/v1/settings/test-ollama", {
      method: "POST",
      body: JSON.stringify({ ollama_url: ollamaUrl }),
    }),
};
