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
      setSuggestions(sug)
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
      setSuggestions(sug)
      setError(null)
    }).catch((e) => {
      setError(e.message)
    }).finally(() => setRefreshing(false))
  }

  if (loading) return <div className="loading">Loading policy data</div>

  if (error) {
    return (
      <>
        <div className="page-header">
          <h1>Policy Insights</h1>
          <p>Self-healing engine status and policy suggestions</p>
        </div>
        <div className="card empty-state">
          Unable to reach the gateway: {error}
        </div>
      </>
    )
  }

  const staleTools = status?.tools.filter(t => t.stale) ?? []
  const activeTools = status?.tools.filter(t => !t.stale) ?? []
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
            <div className="stat-value">{status.tools.length}</div>
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

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 24 }}>
        {/* Tool confidence */}
        <div className="card">
          <div className="card-title">Tool Confidence Decay</div>
          {status && status.tools.length > 0 ? (
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
    </>
  )
}
