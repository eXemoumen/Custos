export type Decision =
  | "allow"
  | "allow_once"
  | "allow_and_persist"
  | "deny"
  | "prompt"
  | "defer"
  | "quarantine";

export type AssetType =
  | "file_path"
  | "ip_network"
  | "domain"
  | "db_table"
  | "env_var"
  | "regex"
  | "keyword";

export type Severity = "critical" | "high" | "medium" | "low";

export interface SensitiveAsset {
  id: string;
  name: string;
  asset_type: AssetType;
  pattern: string;
  action: Decision;
  severity: Severity;
  description?: string;
  enabled: boolean;
  created_at?: number;
}

export interface GuardrailRule {
  id: string;
  name: string;
  natural_language_rule: string;
  category: string;
  action: Decision;
  severity: Severity;
  target_tools: string[];
  keywords: string[];
  enabled: boolean;
  created_at?: number;
}

export interface ThreatPattern {
  id: string;
  name: string;
  pattern: string;
  is_regex: boolean;
  severity: Severity;
  description?: string;
  action: Decision;
  enabled: boolean;
  created_at?: number;
}

export interface PromptItem {
  request_id: string;
  tool: string;
  args: Record<string, unknown>;
  risk: number;
  reasoning: string;
  options: Decision[];
  created_at?: number;
  timeout_seconds?: number;
  deadline_ms?: number;
}

export interface AuditEventItem {
  ts?: number;
  ts_unix_ms?: number;
  tool?: string;
  decision: Decision;
  risk_score?: number;
  risk?: number;
  reasoning?: string;
  assistant_reasoning?: string;
  policy_rule_id?: string;
  policy_match?: string;
  assistant?: string;
  latency_ms?: number;
  hash?: string;
  prev_hash?: string;
  raw?: Record<string, unknown>;
}

export interface HealthStatus {
  status: string;
  version: string;
  uptime_seconds: number;
  gateway: {
    active_rules: number;
    pending_prompts: number;
    kb_assets: number;
    kb_rules: number;
    kb_threats: number;
  };
  metrics?: {
    total_calls: number;
    total_allowed: number;
    total_blocked: number;
    total_prompted: number;
    active_agents_count: number;
    quarantined_agents_count: number;
  };
}

export interface AgentRecord {
  id: string;
  name: string;
  framework: string;
  status: "active" | "quarantined" | "idle";
  policy_profile: string;
  calls: number;
  last_seen_ts: number;
  last_tool?: string;
}

export interface PolicyRuleItem {
  action: string;
  overlay_id?: string;
  match: Record<string, unknown>;
  description?: string;
}

export interface GuardrailTestResult {
  allowed: boolean;
  action?: Decision;
  risk_score: number;
  reasoning: string;
  violated_rule?: GuardrailRule;
  violated_asset?: SensitiveAsset;
  violated_threat?: ThreatPattern;
}

export interface DecideRequest {
  tool: string;
  args?: Record<string, unknown>;
  user_id?: string;
  goal_id?: string;
  task_id?: string;
  risk_tier?: number;
  extra?: Record<string, unknown>;
}

export interface DecideResponse {
  decision: string;
  allowed: boolean;
  risk?: number;
  reasoning?: string;
  audit_event: AuditEventItem;
}
