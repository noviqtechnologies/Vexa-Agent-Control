import { useEffect, useState } from 'react'
import {
  api,
  type PolicyStatus, type PolicySuggestion,
} from '../api/client'

function confidenceLabel(decay: number): { label: string; cls: string } {
  if (decay >= 0.8) return { label: 'High', cls: 'success' }
  if (decay >= 0.4) return { label: 'Medium', cls: 'warning' }
  return { label: 'Low', cls: 'danger' }
}

function formatScore(score: number): string {
  return (score * 100).toFixed(1) + '%'
}

function timeAgoFromNs(ns: number): string {
  const diff = Date.now() - ns / 1_000_000
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function PolicyInsights() {
  const [status, setStatus] = useState<PolicyStatus | null>(null)
  const [suggestions, setSuggestions] = useState<PolicySuggestion[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [refreshing, setRefreshing] = useState(false)

  useEffect(() => {
    Promise.all([
      api.getPolicyStatus(),
      api.getPolicySuggestions(),
    ]).then(([s, sug]) => {
      setStatus(s)
      setSuggestions(sug || [])
    }).catch((e) => {
      setError(e.message)
    }).finally(() => setLoading(false))
  }, [])

  function handleRefresh() {
    setRefreshing(true)
    Promise.all([
      api.getPolicyStatus(),
      api.getPolicySuggestions(),
    ]).then(([s, sug]) => {
      setStatus(s)
      setSuggestions(sug || [])
      setError(null)
    }).catch((e) => {
      setError(e.message)
    }).finally(() => setRefreshing(false))
  }

  if (loading) return <div className="loading">Loading policy data</div>

  if (error) {
    const isGatewayDown = error.includes('502') || error.includes('gateway') || error.includes('fetch')
    return (
      <>
        <div className="page-header">
          <h1>Policy Insights</h1>
          <p>Self-healing engine status and policy suggestions</p>
        </div>
        <div className="card empty-state" style={{ textAlign: 'left', padding: '32px 28px' }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>⚠️</div>
          {isGatewayDown ? (
            <>
              <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 8 }}>
                Agent Control Gateway is not reachable
              </div>
              <div style={{ color: 'var(--text-secondary)', marginBottom: 16, lineHeight: 1.6 }}>
                The Policy Insights page requires the Agent Control gateway to be running.
                When using <code>run-demo.ps1</code> the gateway starts automatically as part of the stack.
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 13, background: 'var(--surface-2)', padding: '10px 14px', borderRadius: 6 }}>
                docker compose -f control-plane/docker-compose.yml up --build
              </div>
            </>
          ) : (
            <>
              <div style={{ fontWeight: 600, fontSize: 16, marginBottom: 8 }}>
                Unable to reach the gateway
              </div>
              <div style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                {error}
              </div>
            </>
          )}
        </div>
      </>
    )
  }

  const staleTools = status?.tools?.filter(t => t.stale) ?? []
  const activeTools = status?.tools?.filter(t => !t.stale) ?? []
  const highAnomalySuggestions = suggestions?.filter(s => s.anomaly_score >= 0.95) ?? []

  return (
    <>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Policy Insights</h1>
          <p>Self-healing engine status, tool confidence decay, and policy suggestions</p>
        </div>
        <button className="refresh-btn" onClick={handleRefresh} disabled={refreshing}>
          {refreshing ? 'Refreshing...' : 'Refresh'}
        </button>
      </div>

      {/* Stat tiles */}
      {status && (
        <div className="stats-grid">
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: status.enabled ? 'var(--success)' : 'var(--danger)' }}>
              {status.enabled ? 'Active' : 'Disabled'}
            </div>
            <div className="stat-label">Engine Status</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value">{status.tools?.length || 0}</div>
            <div className="stat-label">Monitored Tools</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{staleTools.length}</div>
            <div className="stat-label">Stale Tools</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: 'var(--warning)' }}>{suggestions?.length ?? 0}</div>
            <div className="stat-label">Pending Suggestions</div>
          </div>
        </div>
      )}

      {/* High anomaly alert */}
      {highAnomalySuggestions.length > 0 && (
        <div className="card" style={{ marginBottom: 24, borderColor: 'var(--danger)', background: 'var(--danger-dim)' }}>
          <div className="card-title" style={{ color: 'var(--danger)' }}>High Anomaly Alerts</div>
          <div style={{ fontSize: 14, color: 'var(--text-secondary)' }}>
            {highAnomalySuggestions.length} suggestion{highAnomalySuggestions.length > 1 ? 's' : ''} with anomaly score above 95% detected.
            These may indicate policy baseline deviations requiring immediate review.
          </div>
        </div>
      )}

      {/* Engine Architecture & How It Works Banner */}
      <div className="card" style={{ padding: '16px 20px', marginBottom: 24, backgroundColor: '#18181b', borderColor: '#27272a' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>
          🧠 How the Self-Healing Engine Works
        </h4>
        <div style={{ fontSize: '13px', color: '#a1a1aa', lineHeight: '1.5' }}>
          The Self-Healing Engine monitors MCP tools invoked by AI agents through the proxy.
          As agents invoke tools, confidence decay values update over a 30-day window. If anomalous tool arguments or unexpected egress behavior are detected, automated policy suggestions appear below for administrator approval.
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 24 }}>
        {/* Tool confidence */}
        <div className="card">
          <div className="card-title">Tool Confidence Decay</div>
          {status && status.tools?.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Tool</th>
                    <th>Confidence</th>
                    <th>Decay</th>
                    <th>Last Seen</th>
                  </tr>
                </thead>
                <tbody>
                  {[...activeTools, ...staleTools].map((tool) => {
                    const conf = confidenceLabel(tool.confidence_decay)
                    return (
                      <tr key={tool.name}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{tool.name}</td>
                        <td><span className={`badge badge-${conf.cls}`}>{conf.label}</span></td>
                        <td>
                          <div className="decay-bar-container">
                            <div
                              className="decay-bar-fill"
                              style={{
                                width: `${(tool.confidence_decay * 100).toFixed(0)}%`,
                                background: conf.cls === 'success' ? 'var(--success)' : conf.cls === 'warning' ? 'var(--warning)' : 'var(--danger)',
                              }}
                            />
                          </div>
                        </td>
                        <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>
                          {timeAgoFromNs(tool.last_seen)}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="empty-state">No tools monitored</div>
          )}
        </div>

        {/* Engine config */}
        <div className="card">
          <div className="card-title">Engine Configuration</div>
          {status && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="cred-detail">
                <span>Self-Healing</span>
                <span className={`badge badge-${status.enabled ? 'success' : 'danger'}`}>
                  {status.enabled ? 'Enabled' : 'Disabled'}
                </span>
              </div>
              <div className="cred-detail">
                <span>Decay Window</span>
                <span>{status.decay_window_days} days</span>
              </div>
              <div className="cred-detail">
                <span>Active Tools</span>
                <span>{activeTools.length}</span>
              </div>
              <div className="cred-detail">
                <span>Stale Tools</span>
                <span style={{ color: staleTools.length > 0 ? 'var(--danger)' : undefined }}>
                  {staleTools.length}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Suggestions table */}
      <div className="card">
        <div className="card-title">Policy Suggestions</div>
        {suggestions && suggestions.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Tool</th>
                  <th>Field</th>
                  <th>Value</th>
                  <th>Anomaly</th>
                  <th>Action</th>
                  <th>When</th>
                </tr>
              </thead>
              <tbody>
                {suggestions.map((s, i) => {
                  const scoreClass = s.anomaly_score >= 0.95 ? 'danger' : s.anomaly_score >= 0.8 ? 'warning' : 'info'
                  return (
                    <tr key={`${s.tool}-${s.field}-${i}`}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{s.tool}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{s.field}</td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {s.new_value}
                      </td>
                      <td><span className={`badge badge-${scoreClass}`}>{formatScore(s.anomaly_score)}</span></td>
                      <td style={{ fontSize: 13 }}>{s.suggested_action}</td>
                      <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>{timeAgoFromNs(s.timestamp_ns)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">No policy suggestions — baseline is clean</div>
        )}
      </div>

      {/* OWASP Agentic Top 10 (ASI 2026) Compliance Scorecard */}
      <div className="card" style={{ marginTop: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div>
            <div className="card-title" style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}>
              🛡️ OWASP Agentic Top 10 (ASI 2026) Security Readiness
            </div>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginTop: 4 }}>
              Architectural alignment against the OWASP Agentic System Security Standard.
            </p>
          </div>
          <span className="badge badge-success" style={{ fontSize: 12, padding: '4px 10px' }}>
            8/10 Full · 1/10 Partial · 1/10 Scoped
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
          {[
            { id: 'ASI01', name: 'Agent Goal Hijacking', status: 'Protected', coverage: 'Full', desc: '9 active prompt injection scanners & Safe Mode' },
            { id: 'ASI02', name: 'Tool Misuse & Exploitation', status: 'Enforcing', coverage: 'Full', desc: 'Default-deny AST policy engine & parameter regex' },
            { id: 'ASI03', name: 'Identity & Privilege Abuse', status: 'Enforcing', coverage: 'Full', desc: 'OIDC JWT validation & scoped credential binding' },
            { id: 'ASI04', name: 'Supply Chain & Schema Drift', status: 'Monitored', coverage: 'Full', desc: 'Cross-session tool catalog SHA-256 baseline hashing' },
            { id: 'ASI05', name: 'Unexpected Execution (RCE)', status: 'Enforcing', coverage: 'Full', desc: 'Safe-mode pipe-to-shell block & OS Sentry daemon' },
            { id: 'ASI06', name: 'Memory & Context Poisoning', status: 'Monitored', coverage: 'Partial', desc: 'Tamper-evident audit trail & response DLP scanner' },
            { id: 'ASI07', name: 'Inter-Agent Communication', status: 'Disclosed', coverage: 'Scoped', desc: 'Org-local OIDC claims (Cross-tenant requires IdP federation)' },
            { id: 'ASI08', name: 'Cascading Failures / Loops', status: 'Enforcing', coverage: 'Full', desc: 'Sliding-window cycle detection & spend caps' },
            { id: 'ASI09', name: 'Human Trust Exploitation', status: 'Enforcing', coverage: 'Full', desc: 'HMAC-signed Human-in-the-Loop approval webhooks' },
            { id: 'ASI10', name: 'Rogue Egress / Shadow Traffic', status: 'Enforcing', coverage: 'Full', desc: 'Hardware-bound PKI daemon & persistent watch loops' },
          ].map(item => (
            <div key={item.id} style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: 8, padding: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>{item.id}</span>
                <span className={`badge badge-${item.coverage === 'Full' ? 'success' : item.coverage === 'Partial' ? 'warning' : 'info'}`} style={{ fontSize: 10 }}>
                  {item.coverage}
                </span>
              </div>
              <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{item.name}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>{item.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </>
  )
}
