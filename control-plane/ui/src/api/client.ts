const BASE = '/api/v1'

let _authToken: string | null = null

export function setAuthToken(token: string | null) {
  _authToken = token
}

function authHeaders(): HeadersInit {
  return _authToken ? { Authorization: `Bearer ${_authToken}` } : {}
}

export function extractErrorMessage(text: string, status?: number): string {
  try {
    const json = JSON.parse(text)
    if (json.message && typeof json.message === 'string') return json.message
    if (json.error && typeof json.error === 'string') return json.error
  } catch {}
  return text || (status ? `Request failed with status ${status}` : 'Unknown error')
}

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${BASE}${path}`, { headers: authHeaders() })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
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

export interface SpendAnalytics {
  summary: {
    total_reserved_microcents: number
    total_settled_microcents: number
    total_released_microcents: number
    request_count: number
    denied_count: number
  }
  time_series: Array<{
    hour: string
    reserved_microcents: number
    settled_microcents: number
    released_microcents: number
    request_count: number
  }>
  top_entities: Array<{
    entity_id: string
    entity_name?: string
    settled_microcents: number
    request_count: number
  }>
}

export interface RunSummary {
  run_id: string
  request_id: string
  device_id: string
  project_id: string
  provider: string
  model: string
  state: string
  reserved_microcents: number
  settled_microcents: number
  started_at: string
  settled_at?: string
  duration_ms: number
  ttft_ms?: number
  input_tokens?: number
  output_tokens?: number
  cached_tokens?: number
  total_tokens?: number
  virtual_key_id?: string
  virtual_key_hash?: string
  virtual_key_prefix?: string
  virtual_key_alias?: string
  session_id?: string
  internal_user_id?: string
  end_user_id?: string
  tags?: Record<string, any>
  request_type?: string
  status_code?: number
}

export interface AuditLogItem {
  id: string
  tenant_id: string
  timestamp: string
  table_name: string
  action: string
  changed_by: string
  actor_role?: string
  affected_item_id: string
  before_value?: Record<string, any>
  updated_value?: Record<string, any>
  ip_address?: string
  outcome?: string
}

export interface DeletedVirtualKey {
  id: string
  tenant_id: string
  key_prefix: string
  name: string
  team_id: string
  created_by: string
  created_at: string
  deleted_at?: string
  deleted_by?: string
  deleted_reason?: string
  monthly_budget_microcents: number
  spent_microcents: number
  allowed_models: string[]
  status: string
}


export interface RunDossier {
  run_id: string
  request_id: string
  identity: {
    device_id: string
    device_hostname?: string
    device_compliance?: string
    project_id: string
  }
  policy: {
    snapshot: any
    price_book_version_id: string
  }
  dispatch: {
    provider: string
    model: string
  }
  economics: {
    reserved_microcents: number
    settled_microcents: number
    released_microcents: number
    currency: string
    events: SpendEventV2[]
  }
  outcome: {
    state: string
    started_at: string
    settled_at?: string
    released_at?: string
    release_reason?: string
    duration_ms?: number
  }
  provenance: {
    data_freshness: string
    evidence_source: string
    confidence: string
  }
}

export interface EffectivePolicyResponse {
  queried_at: string
  query_params: Record<string, string>
  provenance_ladder: Array<{
    level: string
    source: string
    policy?: any
    policies?: any[]
    scope?: any
    state?: any
    confidence: string
  }>
  effective: {
    spend_limit_microcents: number
    action: string
    allowed_models: string[]
    allowed_routes: string[]
    policy_version_ids: string[]
  }
  confidence: string
  provenance?: {
    data_freshness: string
    evidence_source: string
    confidence: string
  }
}

export interface VirtualKey {
  id: string
  tenant_id: string
  key_prefix: string
  previous_key_expires_at?: string
  name: string
  team_id: string
  created_by: string
  created_at: string
  expires_at?: string
  allowed_ips: string[]
  max_rpm: number
  max_tpm: number
  max_concurrent_requests: number
  monthly_budget_microcents: number
  spent_microcents: number
  allowed_models: string[]
  allowed_routes: string[]
  status: 'active' | 'rotating' | 'revoked'
  tags?: Record<string, string>
  owner_type?: 'user' | 'service_account' | 'agent' | string
  budget_period?: 'monthly' | 'weekly' | 'daily' | string
}

export interface CreateVirtualKeyRequest {
  name: string
  team_id?: string
  expires_at?: string
  allowed_ips?: string[]
  max_rpm?: number
  max_tpm?: number
  max_concurrent_requests?: number
  monthly_budget_microcents?: number
  allowed_models?: string[]
  allowed_routes?: string[]
  tags?: Record<string, string>
  owner_type?: string
  budget_period?: string
}

export interface CreateVirtualKeyResponse {
  virtual_key: VirtualKey
  raw_secret: string
}

export interface RotateVirtualKeyRequest {
  grace_period_seconds?: number
}

export const api = {
  // Virtual Keys (Pillar 1)
  listVirtualKeys: async () => {
    const res = await fetch('/api/v1/virtual-keys', { headers: authHeaders() })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
    }
    return res.json() as Promise<{ virtual_keys: VirtualKey[] }>
  },
  createVirtualKey: async (data: CreateVirtualKeyRequest) => {
    const res = await fetch('/api/v1/virtual-keys', {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
    }
    return res.json() as Promise<CreateVirtualKeyResponse>
  },
  deleteVirtualKey: async (id: string) => {
    const res = await fetch(`/api/v1/virtual-keys/${id}`, {
      method: 'DELETE',
      headers: authHeaders()
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
    }
    return res.json() as Promise<{ status: string; id: string }>
  },
  rotateVirtualKey: async (id: string, gracePeriodSeconds = 3600) => {
    const res = await fetch(`/api/v1/virtual-keys/${id}/rotate`, {
      method: 'POST',
      headers: { ...authHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ grace_period_seconds: gracePeriodSeconds })
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
    }
    return res.json() as Promise<CreateVirtualKeyResponse>
  },
  resetVirtualKeySpend: async (id: string) => {
    const res = await fetch(`/api/v1/virtual-keys/${id}/reset-spend`, {
      method: 'POST',
      headers: authHeaders()
    })
    if (!res.ok) {
      const text = await res.text()
      throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
    }
    return res.json() as Promise<{ status: string; id: string }>
  },
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

  // Spend V2 Analytics
  getSpendAnalytics: async (hours = 24, groupBy = 'provider') => {
    const res = await fetch(`/api/v2/spend/analytics?hours=${hours}&group_by=${groupBy}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; analytics: SpendAnalytics; generated_at: string }>
  },

  // Observability & Request Logs (LiteLLM-grade)
  listRequestLogs: async (params?: {
    limit?: number
    offset?: number
    hours?: number
    provider?: string
    model?: string
    status?: string
    request_id?: string
    session_id?: string
    key_hash?: string
    virtual_key_id?: string
    user?: string
    search?: string
  }) => {
    const qs = new URLSearchParams()
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.offset) qs.set('offset', String(params.offset))
    if (params?.hours) qs.set('hours', String(params.hours))
    if (params?.provider) qs.set('provider', params.provider)
    if (params?.model) qs.set('model', params.model)
    if (params?.status) qs.set('status', params.status)
    if (params?.request_id) qs.set('request_id', params.request_id)
    if (params?.session_id) qs.set('session_id', params.session_id)
    if (params?.key_hash) qs.set('key_hash', params.key_hash)
    if (params?.virtual_key_id) qs.set('virtual_key_id', params.virtual_key_id)
    if (params?.user) qs.set('user', params.user)
    if (params?.search) qs.set('search', params.search)
    const res = await fetch(`/api/v1/observability/request-logs?${qs.toString()}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; request_logs: RunSummary[]; total: number; data_freshness: string; confidence: string }>
  },

  listAuditLogs: async (params?: { limit?: number; offset?: number; object_id?: string; table_name?: string; action?: string; changed_by?: string }) => {
    const qs = new URLSearchParams()
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.offset) qs.set('offset', String(params.offset))
    if (params?.object_id) qs.set('object_id', params.object_id)
    if (params?.table_name) qs.set('table_name', params.table_name)
    if (params?.action) qs.set('action', params.action)
    if (params?.changed_by) qs.set('changed_by', params.changed_by)
    const res = await fetch(`/api/v1/observability/audit-logs?${qs.toString()}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; audit_logs: AuditLogItem[]; total: number; page: number; limit: number }>
  },

  listDeletedVirtualKeys: async (params?: { limit?: number; offset?: number }) => {
    const qs = new URLSearchParams()
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.offset) qs.set('offset', String(params.offset))
    const res = await fetch(`/api/v1/observability/deleted-keys?${qs.toString()}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; deleted_virtual_keys: DeletedVirtualKey[]; total: number }>
  },

  listDeletedTeams: async () => {
    const res = await fetch('/api/v1/observability/deleted-teams', { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; deleted_teams: any[]; total: number }>
  },

  deleteVirtualKeyWithReason: async (id: string, reason?: string) => {
    const qs = reason ? `?reason=${encodeURIComponent(reason)}` : ''
    const res = await fetch(`/api/v1/virtual-keys/${id}${qs}`, { method: 'DELETE', headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ status: string; id: string }>
  },

  // Run Explorer
  listRuns: async (params?: { limit?: number; hours?: number; device_id?: string; provider?: string; model?: string; state?: string }) => {
    const qs = new URLSearchParams()
    if (params?.limit) qs.set('limit', String(params.limit))
    if (params?.hours) qs.set('hours', String(params.hours))
    if (params?.device_id) qs.set('device_id', params.device_id)
    if (params?.provider) qs.set('provider', params.provider)
    if (params?.model) qs.set('model', params.model)
    if (params?.state) qs.set('state', params.state)
    const res = await fetch(`/api/v1/runs?${qs.toString()}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<{ organization_id: string; runs: RunSummary[]; data_freshness: string; confidence: string }>
  },
  getRunDossier: async (runId: string) => {
    const res = await fetch(`/api/v1/runs/${runId}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<RunDossier>
  },


  // Effective Policy Explorer
  getEffectivePolicy: async (params: Record<string, string>) => {
    const qs = new URLSearchParams(params)
    const res = await fetch(`/api/v1/policy/effective-explorer?${qs.toString()}`, { headers: authHeaders() })
    if (!res.ok) throw new Error(`API ${res.status}: ${await res.text()}`)
    return res.json() as Promise<EffectivePolicyResponse>
  },

  getFleetOverview: (hours = 24) => get<FleetStats>(`/fleet/overview?hours=${hours}`),
  listAgents: (limit = 50, offset = 0, hours = 24) =>
    get<AgentSummary[]>(`/fleet/agents?limit=${limit}&offset=${offset}&hours=${hours}`),
  getHeatmap: (hours = 24) =>
    get<DecisionBreakdown[]>(`/fleet/heatmap?hours=${hours}`),
  listEvents: (limit = 100) =>
    get<RedactedEvent[]>(`/fleet/events?limit=${limit}`),
  listRecentAlerts: (limit = 50, hours = 24) =>
    get<RedactedAlert[]>(`/alerts/recent?limit=${limit}&hours=${hours}`),
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
    const text = await res.text()
    throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
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
    const text = await res.text()
    throw new Error(`API ${res.status}: ${extractErrorMessage(text, res.status)}`)
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
  categories?: string[]
  complexity?: 'Low Complexity' | 'Medium Complexity' | 'High Complexity' | string
  description: string
  tags: string[]
  guardrails?: string[]
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

export interface IdeTargetDetail {
  name: string
  installed: boolean
  config_path?: string
  proxy_configured: boolean
  configured_base_url?: string
  mcp_wrapped: boolean
  compliance_state: string
  last_healed_at?: string
}

export interface SentryDeviceDetail {
  device_id: string
  organization_id: string
  hostname: string
  user_identifier: string
  os: string
  os_version: string
  public_key: string
  daemon_version: string
  enrollment_status: string
  last_heartbeat_at?: string
  created_at: string
  updated_at: string
  overall_compliance: 'COMPLIANT' | 'NON_COMPLIANT' | 'OFFLINE'
  tamper_count_24h: number
  ide_statuses: IdeTargetDetail[]
  recent_tamper_events: SentryTamperEvent[]
  report_payload?: string
}

export async function listSentryDevices(complianceStatus = '', limit = 50): Promise<ListSentryDevicesResponse> {
  const query = complianceStatus ? `?compliance_status=${complianceStatus}&limit=${limit}` : `?limit=${limit}`
  return get<ListSentryDevicesResponse>(`/devices${query}`)
}

export async function getSentryDeviceDetail(deviceId: string): Promise<SentryDeviceDetail> {
  return get<SentryDeviceDetail>(`/devices/${deviceId}`)
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
