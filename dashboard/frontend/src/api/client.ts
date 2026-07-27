const BASE = '/api/v1'

let _authToken: string | null = null

export function setAuthToken(token: string | null) {
  _authToken = token
}

function authHeaders(): HeadersInit {
  return _authToken ? { Authorization: `Bearer ${_authToken}` } : {}
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() })
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  return res.json()
}

// Fleet Overview
export interface FleetStats {
  total_agents: number
  active_agents: number
  total_events: number
  denied_events: number
  total_alerts: number
  critical_alerts: number
}

export interface AgentSummary {
  agent_id: string
  display_name: string | null
  status: string
  policy_version: string | null
  last_seen_at: string
  event_count: number
  alert_count: number
}

export interface DecisionBreakdown {
  hour: string
  allowed: number
  denied: number
  warned: number
}

export interface RedactedEvent {
  event_id: string
  timestamp_ms: number
  session_id: string
  agent_id: string
  tool_name: string
  decision: string
  dlp_findings: { category: string; pattern_name: string; count: number }[]
  injection_findings: { pattern_name: string; count: number }[]
  semantic_findings: { anomaly_score: number; finding_type: string }[]
}

export interface RedactedAlert {
  alert_id: string
  severity: string
  event: RedactedEvent
}

// Identity Governance
export interface CredentialMeta {
  credential_id: string
  agent_id: string
  scope: string[]
  ttl_seconds: number
  created_at_ms: number
  expires_at_ms: number
  last_rotated_at_ms: number | null
  rotation_history: { rotated_at_ms: number; reason: string }[]
}

export const api = {
  getFleetOverview: () => get<FleetStats>('/fleet/overview'),
  listAgents: (limit = 50, offset = 0) =>
    get<AgentSummary[]>(`/fleet/agents?limit=${limit}&offset=${offset}`),
  getHeatmap: (hours = 24) =>
    get<DecisionBreakdown[]>(`/fleet/heatmap?hours=${hours}`),
  listEvents: (limit = 100) =>
    get<RedactedEvent[]>(`/fleet/events?limit=${limit}`),
  listRecentAlerts: (limit = 50) =>
    get<RedactedAlert[]>(`/alerts/recent?limit=${limit}`),
  listCredentials: (agentId?: string) =>
    get<CredentialMeta[]>(
      `/identity/credentials${agentId ? `?agent_id=${agentId}` : ''}`
    ),
  getPolicyStatus: () => get<PolicyStatus>('/policy/status'),
  getPolicySuggestions: () => post<PolicySuggestion[]>('/policy/suggestions'),
  getThreatSummary: (hours = 24) =>
    get<ThreatSummary>(`/threats/summary?hours=${hours}`),
  getThreatTimeline: (hours = 24) =>
    get<ThreatTimelinePoint[]>(`/threats/timeline?hours=${hours}`),
  getTopThreatPatterns: (hours = 24, limit = 20) =>
    get<ThreatPattern[]>(`/threats/top-patterns?hours=${hours}&limit=${limit}`),
  triggerRotation: (agentId: string, drainSeconds = 300) =>
    postJSON<RotationResult>('/identity/rotate', { agent_id: agentId, drain_seconds: drainSeconds }),
  
  // Policy Management
  getActivePolicy: () => get<Policy>('/policies/active'),
  savePolicy: (policy: Partial<Policy>) => postJSON<Policy>('/policies', policy),
}

async function post<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers: authHeaders() })
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  return res.json()
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  return res.json()
}

// Policy Insights (self-healing)
export interface ToolStatus {
  name: string
  confidence_decay: number
  last_seen: number
  stale: boolean
}

export interface PolicyStatus {
  enabled: boolean
  decay_window_days: number
  tools: ToolStatus[]
  pending_suggestions: PolicySuggestion[]
}

export interface PolicySuggestion {
  tool: string
  field: string
  old_value: string
  new_value: string
  anomaly_score: number
  timestamp_ns: number
  suggested_action: string
}

export interface Policy {
  id: string
  version: string
  content: string
  is_active: boolean
  created_at: string
  updated_at: string
}

// Threat Intelligence
export interface ThreatSummary {
  dlp_total: number
  injection_total: number
  semantic_total: number
  events_with_dlp: number
  events_with_injection: number
  events_with_semantic: number
}

export interface ThreatTimelinePoint {
  hour: string
  dlp: number
  injection: number
  semantic: number
}

export interface ThreatPattern {
  type: string
  pattern_name: string
  category?: string
  total_count: number
  event_count: number
}

// Credential Rotation
export interface RotationResult {
  new_credential_id: string
  agent_id: string
  expires_at: string
  drain_seconds: number
}

// SSE stream for real-time alerts (AC-23.2).
export function subscribeAlerts(
  onAlert: (alert: RedactedAlert) => void,
  onError?: (err: Event) => void
): () => void {
  const es = new EventSource(`${BASE}/alerts/stream`)
  es.onmessage = (e) => {
    try {
      onAlert(JSON.parse(e.data))
    } catch { /* ignore malformed */ }
  }
  es.onerror = (e) => onError?.(e)
  return () => es.close()
}
