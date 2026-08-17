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


// Spend Caps & Group Policy
export interface SpendBudget {
  scope_type: string
  scope_key: string
  cap_cents: number
  period: string
  updated_at: string
}

export interface SpendSnapshot {
  snapshot_id: string
  agent_id: string
  period_start: string
  spent_cents: number
  cap_cents: number | null
  is_estimated: boolean
}

export interface IncreaseRequest {
  request_id: string
  agent_id: string
  current_cap: number
  new_cap?: number
  reason?: string
  status: string
  submitted_at: string
}

export interface GroupPolicy {
  id: string
  group_id: string
  version: number
  claims: any
  tools: any
  active: boolean
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

export interface GatewayInfo {
  id: string
  last_seen_at: string
  version: string
  mode: string
  policy_version: number
  connected: boolean
}

export interface LicenseStatus {
  org_id: string
  tier: string
  max_seats: number
  seats_used: number
  seats_remaining: number
  features: string[]
  expires_at?: string
}

export interface BudgetWindowV2 {
  window_id: string
  organization_id: string
  policy_version_id: string
  scope_type: string
  scope_id: string
  window_start: string
  window_end: string
  limit_microcents: number
  reserved_microcents: number
  settled_microcents: number
  available_microcents: number
  version: number
}

export interface SpendPolicyV2 {
  policy_id: string
  organization_id: string
  scope_type: string
  scope_id: string
  currency: string
  period_type: string
  limit_microcents: number
  action: string
  effective_from: string
  status: string
  created_at: string
  updated_at: string
}

export interface SpendEventV2 {
  event_id: string
  organization_id: string
  reservation_id: string
  request_id: string
  event_type: string
  amount_microcents: number
  currency: string
  usage_json: string
  provider_request_id?: string
  actor: string
  reason_code: string
  occurred_at: string
}

export interface IncreaseRequestV2 {
  request_id: string
  organization_id: string
  project_id: string
  requested_limit_microcents: number
  current_limit_microcents: number
  reason: string
  status: string
  created_by: string
  decided_by?: string
  decision_reason?: string
  resulting_policy_version_id?: string
  created_at: string
  decided_at?: string
}

export const api = {
  // Spend V2 (Authoritative PostgreSQL Ledger)
  getEffectiveSpendV2: async () => {
    const res = await fetch('/api/v2/spend/effective', { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; windows: BudgetWindowV2[] }>
  },
  listSpendEventsV2: async (limit = 100) => {
    const res = await fetch(`/api/v2/spend/events?limit=${limit}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; events: SpendEventV2[] }>
  },
  listSpendPoliciesV2: async () => {
    const res = await fetch('/api/v2/spend/policies', { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ policies: SpendPolicyV2[] }>
  },
  createSpendPolicyV2: async (data: { scope_type: string; scope_id: string; period_type: string; limit_usd: number; action?: string }) => {
    const res = await fetch('/api/v2/spend/policies', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json()
  },
  listIncreaseRequestsV2: async () => {
    const res = await fetch('/api/v2/spend/increase-requests', { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ requests: IncreaseRequestV2[] }>
  },
  createIncreaseRequestV2: async (data: { project_id: string; requested_limit_usd: number; current_limit_microcents: number; reason: string }) => {
    const res = await fetch('/api/v2/spend/increase-requests', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json()
  },
  decideIncreaseRequestV2: async (id: string, decision: 'APPROVED' | 'REJECTED', reason: string) => {
    const res = await fetch(`/api/v2/spend/increase-requests/${id}/decide`, {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ decision, reason })
    })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json()
  },

  // License
  getLicenseStatus: () => get<LicenseStatus>('/license/status'),

  // Gateways
  listGateways: () => get<{ gateways: GatewayInfo[] }>('/gateways'),
  rotateProviderKey: (provider: string, newKey: string) =>
    postJSON<{ provider: string; rotation_version: number; credential_id: string }>('/credentials/rotate', { provider, new_key: newKey }),

  // Spend Caps
  listBudgets: () => get<SpendBudget[]>('/spend/budgets'),
  createBudget: (data: any) => postJSON('/spend/budgets', data),
  listSnapshots: () => get<SpendSnapshot[]>('/spend/snapshots'),
  listIncreaseRequests: () => get<IncreaseRequest[]>('/spend/requests'),
  submitIncreaseRequest: (data: any) => postJSON('/spend/requests', data),
  resolveIncreaseRequest: (id: string, data: any) => postJSON(`/spend/requests/${id}/resolve`, data),

  // Group Policy
  listGroupPolicies: () => get<GroupPolicy[]>('/group-policies'),
  getGroupPolicy: (groupId: string) => get<GroupPolicy>(`/group-policies/${groupId}`),
  publishGroupPolicy: (data: any) => postJSON('/group-policies', data),

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
  listPolicies: () => get<Policy[]>('/policies'),
  getActivePolicy: () => get<Policy>('/policies/active?raw=true'),
  savePolicy: (policy: Partial<Policy>) => postJSON<Policy>('/policies', policy),
  
  // Policy Marketplace Templates
  listTemplates: () => get<PolicyTemplate[]>('/policies/templates'),
  getTemplate: (id: string) => get<PolicyTemplate>(`/policies/templates/${id}`),
  createCustomTemplate: (tpl: Partial<PolicyTemplate>) => postJSON<PolicyTemplate>('/policies/templates', tpl),
  deleteCustomTemplate: (id: string) => fetch(`${BASE}/policies/templates/${id}`, { method: 'DELETE', headers: authHeaders() }),

  // Sentry Device Governance & Tamper Log
  listSentryDevices: (complianceStatus = '', limit = 50) => {
    const query = complianceStatus ? `?compliance_status=${complianceStatus}&limit=${limit}` : `?limit=${limit}`
    return get<ListSentryDevicesResponse>(`/devices${query}`)
  },
  listSentryTamperEvents: (limit = 50) =>
    get<ListSentryTamperEventsResponse>(`/devices/tamper-log?limit=${limit}`),
}

async function post<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { method: 'POST', headers: authHeaders() })
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  const text = await res.text()
  return text ? JSON.parse(text) : ({} as T)
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
  const text = await res.text()
  return text ? JSON.parse(text) : ({} as T)
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

export interface PolicyTemplate {
  id: string
  name: string
  category: string
  description: string
  tags: string[]
  icon: string
  content: string
  is_custom: boolean
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

// Central Device Governance
export interface Device {
  device_id: string
  hostname: string
  os_arch: string
  os_family: string
  public_key: string
  agentcontrol_version: string
  compliance_status: 'COMPLIANT' | 'UNREACHABLE' | 'NON_COMPLIANT'
  mcp_servers_total: number
  mcp_servers_wrapped: number
  ide_checksums: Record<string, string>
  first_enrolled_at: string
  last_heartbeat_at: string
  is_revoked: boolean
  revoked_at?: string
  updated_at: string
}

export interface EnrollmentToken {
  token_id: string
  token_hash: string
  created_by: string
  max_uses: number
  current_uses: number
  expires_at: string
  created_at: string
}

export interface EnrollmentTokenV2 {
  id: string
  token: string
  token_hint: string
  expires_at: string
  max_uses: number
  status: string
}

export async function createEnrollmentTokenV2(reason: string, deviceLabel = '', targetOwner = '', ttlHours = 24): Promise<EnrollmentTokenV2> {
  const res = await fetch('/api/v2/admin/enrollment-tokens', {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({
      schema_version: '2.0',
      expires_in_minutes: ttlHours * 60,
      device_label: deviceLabel,
      target_owner_subject: targetOwner,
      reason: reason,
    }),
  })
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  return res.json()
}

export async function revokeDeviceV2(deviceId: string, reason = 'Operator manual revocation'): Promise<{ device_id: string; status: string }> {
  const res = await fetch(`/api/v2/admin/devices/${deviceId}/revoke`, {
    method: 'POST',
    headers: { ...authHeaders(), 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  })
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`)
  }
  return res.json()
}

export async function listDevices(osFamily = '', status = ''): Promise<{ devices: Device[]; total: number }> {
  return get<{ devices: Device[]; total: number }>(`/admin/devices?os_family=${osFamily}&status=${status}`)
}

export async function revokeDevice(deviceId: string): Promise<{ device_id: string; status: string }> {
  return revokeDeviceV2(deviceId)
}

export async function createEnrollmentToken(rawToken: string, maxUses = 10, ttlHours = 24): Promise<EnrollmentToken> {
  return postJSON<EnrollmentToken>(`/admin/enrollment-tokens`, {
    raw_token: rawToken,
    max_uses: maxUses,
    ttl_hours: ttlHours,
  })
}

// ── Device Governance & Sentry Compliance Types & API ────────────────────────

export interface SentryDeviceSummary {
  device_id: string
  hostname: string
  user_identifier: string
  os: string
  os_version: string
  overall_compliance: 'COMPLIANT' | 'NON_COMPLIANT' | 'OFFLINE'
  active_ides: string[]
  tamper_count_24h: number
  last_heartbeat_at?: string
  enrollment_status: string
}

export interface ListSentryDevicesResponse {
  devices: SentryDeviceSummary[]
  total_count: number
  compliant_count: number
  non_compliant_count: number
  offline_count: number
}

export interface SentryTamperEvent {
  event_id: string
  device_id: string
  hostname: string
  user_identifier: string
  ide_name: string
  event_type: string
  tamper_details: string
  healed_successfully: boolean
  occurred_at: string
}

export interface ListSentryTamperEventsResponse {
  events: SentryTamperEvent[]
  total_count: number
}

export async function listSentryDevices(complianceStatus = '', limit = 50): Promise<ListSentryDevicesResponse> {
  const query = complianceStatus ? `?compliance_status=${complianceStatus}&limit=${limit}` : `?limit=${limit}`
  return get<ListSentryDevicesResponse>(`/devices${query}`)
}

export async function listSentryTamperEvents(limit = 50): Promise<ListSentryTamperEventsResponse> {
  return get<ListSentryTamperEventsResponse>(`/devices/tamper-log?limit=${limit}`)
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
