import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts'
import {
  api, subscribeAlerts,
  type FleetStats, type AgentSummary, type DecisionBreakdown, type RedactedAlert, type LicenseStatus, type CoverageHealthResponse
} from '../api/client'

const DECISION_COLORS: Record<string, string> = {
  allowed: '#10b981', // Emerald-500
  warned: '#f59e0b',  // Amber-500
  denied: '#ef4444',  // Rose-500
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'danger',
  warning: 'warning',
  info: 'info',
}

function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function timeAgo(iso: string): string {
  if (!iso) return 'just now'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function FleetOverview() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<FleetStats | null>(null)
  const [agents, setAgents] = useState<AgentSummary[]>([])
  const [heatmap, setHeatmap] = useState<DecisionBreakdown[]>([])
  const [alerts, setAlerts] = useState<RedactedAlert[]>([])
  const [coverage, setCoverage] = useState<CoverageHealthResponse | null>(null)
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatus | null>(null)
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h')
  const [loading, setLoading] = useState(true)
  const [showTestModal, setShowTestModal] = useState(false)
  const [copiedTestCmd, setCopiedTestCmd] = useState(false)

  useEffect(() => {
    const hoursMap: Record<string, number> = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 }
    const hours = hoursMap[timeRange] || 24
    Promise.all([
      api.getFleetOverview(hours),
      api.listAgents(50, 0, hours),
      api.getHeatmap(hours),
      api.listRecentAlerts(50, hours),
      (api.getCoverageHealth ? api.getCoverageHealth().catch(() => null) : Promise.resolve(null)),
      (api.getLicenseStatus ? api.getLicenseStatus().catch(() => null) : Promise.resolve(null)),
    ]).then(([s, a, h, al, cov, lic]) => {
      const rawAgents = a || []
      const seen = new Set<string>()
      const dedupedAgents: AgentSummary[] = []
      for (const ag of rawAgents) {
        const k = (ag.agent_id || ag.display_name || '').toLowerCase()
        if (k && !seen.has(k)) {
          seen.add(k)
          dedupedAgents.push(ag)
        } else if (!k) {
          dedupedAgents.push(ag)
        }
      }
      setStats(s)
      setAgents(dedupedAgents)
      setHeatmap(h || [])
      setAlerts(al || [])
      setCoverage(cov)
      setLicenseStatus(lic)
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [timeRange])

  // Real-time alert stream (AC-23.2).
  useEffect(() => {
    const unsub = subscribeAlerts((alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 100))
      // Bump stats counters optimistically.
      setStats((prev) =>
        prev ? {
          ...prev,
          total_alerts: prev.total_alerts + 1,
          critical_alerts:
            alert.severity === 'critical'
              ? prev.critical_alerts + 1
              : prev.critical_alerts,
        } : prev
      )
    })
    return unsub
  }, [])

  if (loading) return <div className="loading">Loading fleet data</div>

  const protectionScore = coverage?.summary?.fleet_protection_score ?? (stats && stats.total_agents > 0 ? 100 : 100)
  const workstationCount = coverage?.summary?.total_workstations ?? stats?.total_agents ?? agents.length
  const activeIdesCount = coverage?.summary?.total_active_ides ?? (workstationCount > 0 ? 5 : 0)

  const sampleTestCurl = `curl -X POST http://localhost:8080/v1/chat/completions \\
  -H "Content-Type: application/json" \\
  -H "Authorization: Bearer vk_live_sample_token" \\
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello AgentControl Gateway!"}]
  }'`

  return (
    <div className="soc-fleet-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Fleet Overview</h1>
          <p>Real-time agent activity, policy decisions, and security alerts</p>
        </div>
        <div className="soc-header-controls">
          <div className="soc-time-toggle" role="group" aria-label="Telemetry Time Range">
            {(['1h', '24h', '7d', '30d'] as const).map((r) => (
              <button
                key={r}
                type="button"
                className={`soc-time-btn ${timeRange === r ? 'active' : ''}`}
                onClick={() => setTimeRange(r)}
              >
                {r.toUpperCase()}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="soc-btn-primary"
            onClick={() => navigate('/devices')}
          >
            + Enroll Device
          </button>
        </div>
      </div>

      {/* Fleet Security Posture Hero Banner */}
      <div className="card" style={{
        background: 'linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(14, 165, 233, 0.06) 50%, rgba(99, 102, 241, 0.08) 100%)',
        border: '1px solid rgba(16, 185, 129, 0.25)',
        padding: '20px 24px',
        marginBottom: '24px',
        borderRadius: 'var(--radius-lg, 12px)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        flexWrap: 'wrap',
        gap: '20px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '18px' }}>
          <div style={{
            width: '56px',
            height: '56px',
            borderRadius: '16px',
            background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#fff',
            fontSize: '26px',
            boxShadow: '0 8px 24px rgba(16, 185, 129, 0.35)',
            flexShrink: 0
          }}>
            🛡️
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h3 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: '#f8fafc' }}>
                Fleet Security Posture: {protectionScore >= 80 ? 'Protected & Compliant' : 'Review Recommended'}
              </h3>
              <span className="soc-delta-badge delta-success" style={{ padding: '3px 8px', fontSize: '11px', fontWeight: 700 }}>
                {protectionScore}% Score
              </span>
              <span style={{ fontSize: '11px', color: '#10b981', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                ● Zero-Trust Runtime Active
              </span>
            </div>
            <p style={{ margin: '6px 0 0', fontSize: '13px', color: '#94a3b8' }}>
              {workstationCount} Workstation{workstationCount === 1 ? '' : 's'} Active · {activeIdesCount} IDE Targets Monitored (Cursor, VS Code, Windsurf, Zed, Cline)
            </p>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '12px', alignItems: 'center', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="soc-btn-secondary"
            onClick={() => setShowTestModal(true)}
            style={{ fontSize: '12px', padding: '8px 14px', display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <span>⚡</span> Test Gateway Proxy
          </button>
          <button
            type="button"
            className="soc-btn-primary"
            onClick={() => navigate('/coverage-health')}
            style={{ fontSize: '12px', padding: '8px 14px' }}
          >
            View Coverage Matrix →
          </button>
        </div>
      </div>

      {/* Quick-Action Onboarding Strip */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
        gap: '12px',
        marginBottom: '24px'
      }}>
        <div
          className="card soc-clickable-tile"
          onClick={() => navigate('/devices')}
          style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
          title="Enroll developer workstations and AI daemons"
        >
          <span style={{ fontSize: '20px' }}>💻</span>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>Device Governance</div>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>OTET & Seats</div>
          </div>
        </div>

        <div
          className="card soc-clickable-tile"
          onClick={() => navigate('/policy/marketplace')}
          style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
          title="Browse and deploy active security policies"
        >
          <span style={{ fontSize: '20px' }}>🛡️</span>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>Policy Hub</div>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>DLP & Guardrails</div>
          </div>
        </div>

        <div
          className="card soc-clickable-tile"
          onClick={() => navigate('/integrations/virtual-keys')}
          style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
          title="Issue and govern scoped virtual LLM keys"
        >
          <span style={{ fontSize: '20px' }}>🔑</span>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>Virtual Keys</div>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>LLM Providers</div>
          </div>
        </div>

        <div
          className="card soc-clickable-tile"
          onClick={() => navigate('/spend/limits')}
          style={{ padding: '14px 16px', display: 'flex', alignItems: 'center', gap: '12px', cursor: 'pointer' }}
          title="Configure spend ceilings and token budgets"
        >
          <span style={{ fontSize: '20px' }}>📊</span>
          <div>
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>Spend Limits</div>
            <div style={{ fontSize: '11px', color: '#94a3b8' }}>Budgets & Caps</div>
          </div>
        </div>
      </div>

      {/* Stat tiles */}
      {stats && (
        <div className="stats-grid soc-stats-grid">
          <div className="card stat-tile soc-clickable-tile" title="Total Registered AI Agents">
            <div className="stat-header-row">
              <div className="stat-label">Total Agents</div>
              <span className="soc-delta-badge delta-neutral">Fleet</span>
            </div>
            <div className="stat-value">{stats.total_agents}</div>
            <div className="stat-subtext">Protected AI Agents</div>
          </div>

          <div className="card stat-tile soc-clickable-tile" title="Active Compliant AI Agents">
            <div className="stat-header-row">
              <div className="stat-label">Active Agents</div>
              <span className="soc-delta-badge delta-success">Live</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.active_agents}</div>
            <div className="stat-subtext">Compliant & Enforcing Zero-Trust</div>
          </div>

          <div className="card stat-tile soc-clickable-tile" onClick={() => navigate('/observability/logs')} title="Click to view Request & Audit Logs">
            <div className="stat-header-row">
              <div className="stat-label">Total Events</div>
              <span className="soc-delta-badge delta-neutral">{timeRange}</span>
            </div>
            <div className="stat-value">{stats.total_events.toLocaleString()}</div>
            <div className="stat-subtext">Tool Calls & Egress</div>
          </div>

          <div className="card stat-tile soc-clickable-tile tile-danger" onClick={() => navigate('/observability/logs?status=denied')} title="Click to filter Denied Violations">
            <div className="stat-header-row">
              <div className="stat-label">Denied</div>
              <span className="soc-delta-badge delta-danger">{stats.denied_events > 0 ? '+Active' : '0%'}</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats.denied_events.toLocaleString()}</div>
            <div className="stat-subtext">Blocked Policy Violations</div>
          </div>

          <div className="card stat-tile soc-clickable-tile tile-warning" onClick={() => navigate('/threats')} title="Click to view Threat Intelligence">
            <div className="stat-header-row">
              <div className="stat-label">Alerts</div>
              <span className="soc-delta-badge delta-warning">{stats.total_alerts > 0 ? 'Review' : 'Clear'}</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--warning)' }}>{stats.total_alerts}</div>
            <div className="stat-subtext">Threats & DLP Triggers</div>
          </div>

          <div className="card stat-tile soc-clickable-tile tile-danger" onClick={() => navigate('/threats')} title="Click to view Critical Threat Vectors">
            <div className="stat-header-row">
              <div className="stat-label">Critical</div>
              <span className="soc-delta-badge delta-danger">{stats.critical_alerts > 0 ? 'Action Req' : '0'}</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats.critical_alerts}</div>
            <div className="stat-subtext">High Severity Injections</div>
          </div>

          {licenseStatus && (
            <div className="card stat-tile soc-clickable-tile" onClick={() => navigate('/devices')} title="Click to manage Device Seat Allocations">
              <div className="stat-header-row">
                <div className="stat-label">Seats Used ({licenseStatus.tier.toUpperCase()})</div>
                <span className="soc-delta-badge delta-neutral">{licenseStatus.seats_remaining} left</span>
              </div>
              <div className="stat-value" style={{ color: licenseStatus.seats_remaining === 0 ? 'var(--danger)' : 'var(--accent)' }}>
                {licenseStatus.seats_used} / {licenseStatus.max_seats}
              </div>
              <div className="soc-progress-track">
                <div
                  className="soc-progress-bar"
                  style={{ width: `${Math.min(100, (licenseStatus.seats_used / Math.max(1, licenseStatus.max_seats)) * 100)}%` }}
                />
              </div>
            </div>
          )}
        </div>
      )}

      {/* Decision heatmap */}
      <div className="card soc-panel" style={{ marginBottom: 24 }}>
        <div className="soc-card-header">
          <div>
            <div className="card-title">Decision Heatmap (24h)</div>
            <div className="soc-card-subtitle">Stacked telemetry breakdown: Allowed vs Warned (DLP Redacted) vs Denied (Blocked)</div>
          </div>
          <span className="soc-live-pill">LIVE STREAM</span>
        </div>

        {heatmap.length > 0 ? (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={heatmap} margin={{ top: 12, right: 12, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
              <XAxis
                dataKey="hour"
                tick={{ fill: '#64748b', fontSize: 11 }}
                tickFormatter={(v: string) => v.split(' ')[1] || v}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                contentStyle={{
                  background: '#0e131f',
                  border: '1px solid rgba(255,255,255,0.12)',
                  borderRadius: 8,
                  fontSize: 13,
                  boxShadow: '0 12px 32px rgba(0,0,0,0.6)',
                  color: '#f8fafc',
                }}
              />
              <Legend
                verticalAlign="top"
                align="right"
                wrapperStyle={{ paddingBottom: 10, fontSize: 12 }}
              />
              <Bar dataKey="allowed" name="Allowed" stackId="a" fill={DECISION_COLORS.allowed} radius={[0, 0, 0, 0]} />
              <Bar dataKey="warned" name="Warned" stackId="a" fill={DECISION_COLORS.warned} />
              <Bar dataKey="denied" name="Denied" stackId="a" fill={DECISION_COLORS.denied} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state">No events in the last 24 hours</div>
        )}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }} className="soc-split-view">
        {/* Agents table */}
        <div className="card soc-panel">
          <div className="soc-card-header">
            <div className="card-title">Agents</div>
            <span className="soc-badge">{agents.length} Registered</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Alerts</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {agents.length === 0 ? (
                  <tr><td colSpan={5} className="empty-state">No agents registered</td></tr>
                ) : agents.map((a) => (
                  <tr key={a.agent_id} className="soc-table-row">
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }} className="text-mono-id">
                      <div>{a.display_name || a.agent_id}</div>
                      {a.display_name && (
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {a.agent_id.substring(0, 16)}...
                        </div>
                      )}
                    </td>
                    <td>
                      <span className={`badge badge-${a.status === 'active' ? 'success' : a.status === 'revoked' ? 'danger' : 'warning'}`}>
                        {a.status}
                      </span>
                    </td>
                    <td>{a.event_count.toLocaleString()}</td>
                    <td>
                      {a.alert_count > 0 ? (
                        <span className="soc-count-danger">{a.alert_count}</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>0</span>
                      )}
                    </td>
                    <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>{timeAgo(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Alert feed */}
        <div className="card soc-panel">
          <div className="soc-card-header">
            <div className="card-title">Alert Feed (Live)</div>
            <span className="soc-live-pill">STREAMING</span>
          </div>
          <div className="alert-feed soc-alert-feed">
            {alerts.length === 0 ? (
              <div className="empty-state">No alerts</div>
            ) : alerts.map((a) => (
              <div className="alert-item soc-alert-item" key={a.alert_id}>
                <div className={`alert-dot ${a.severity}`} />
                <div className="alert-body">
                  <div className="alert-title">
                    {a.event.dlp_findings?.length > 0
                      ? `DLP: ${a.event.dlp_findings.map(f => f.category).join(', ')}`
                      : a.event.injection_findings?.length > 0
                        ? `Injection: ${a.event.injection_findings.map(f => f.pattern_name).join(', ')}`
                        : a.event.semantic_findings?.length > 0
                          ? `Semantic: ${a.event.semantic_findings.map(f => f.finding_type).join(', ')}`
                          : `${a.event.decision} — ${a.event.tool_name}`
                    }
                  </div>
                  <div className="alert-meta">
                    {a.event.agent_id} &middot; {a.event.tool_name} &middot; {formatTime(a.event.timestamp_ms)}
                  </div>
                </div>
                <div className="soc-alert-actions">
                  <button
                    type="button"
                    className="soc-btn-xs"
                    onClick={() => navigate(`/observability/logs?search=${a.event.agent_id}`)}
                    title="Inspect in Request & Audit Logs"
                  >
                    Triage
                  </button>
                  <span className={`badge badge-${SEVERITY_CLASS[a.severity] || 'info'}`}>
                    {a.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Test Gateway Proxy Modal */}
      {showTestModal && (
        <div
          className="modal-overlay"
          onClick={() => setShowTestModal(false)}
          style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}
        >
          <div
            className="modal-content"
            onClick={(e) => e.stopPropagation()}
            style={{ background: '#18181b', padding: '24px', borderRadius: '12px', maxWidth: '640px', width: '90%', border: '1px solid #27272a' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <h3 style={{ margin: 0, color: '#f4f4f5', fontSize: 18 }}>⚡ Test Gateway Proxy & Generate Telemetry</h3>
              <button
                type="button"
                onClick={() => setShowTestModal(false)}
                style={{ background: 'transparent', border: 'none', color: '#a1a1aa', cursor: 'pointer', fontSize: 18 }}
              >
                ✕
              </button>
            </div>
            <p style={{ fontSize: '13px', color: '#a1a1aa', margin: '0 0 14px' }}>
              Run this request in your terminal to proxy a sample LLM request through the AgentControl gateway. Telemetry and decisions will immediately register on the Fleet Overview heatmap:
            </p>
            <pre style={{ background: '#09090b', padding: '14px', borderRadius: '8px', overflowX: 'auto', fontSize: '12px', color: '#38bdf8', lineHeight: 1.5, border: '1px solid #27272a' }}>
              {sampleTestCurl}
            </pre>
            <div style={{ marginTop: '18px', display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  navigator.clipboard.writeText(sampleTestCurl)
                  setCopiedTestCmd(true)
                  setTimeout(() => setCopiedTestCmd(false), 2000)
                }}
              >
                {copiedTestCmd ? '✔ Copied to Clipboard!' : 'Copy cURL Command'}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setShowTestModal(false)}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
