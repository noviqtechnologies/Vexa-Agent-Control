import { useEffect, useState } from 'react'
import { api, type CoverageHealthResponse } from '../api/client'

export default function CoverageControlHealth() {
  const [data, setData] = useState<CoverageHealthResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<'all' | 'protected' | 'action_needed' | 'stale'>('all')
  const [search, setSearch] = useState('')

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.getCoverageHealth()
      setData(res)
    } catch (err: any) {
      setError(err.message || 'Failed to load coverage health telemetry')
    } finally {
      setLoading(false)
    }
  }

  const rawWorkstations = data?.workstations || []
  const seenHostKeys = new Set<string>()
  const deduplicatedWorkstations = rawWorkstations.filter((w) => {
    const hostKey = (w.hostname || w.device_id || '').toLowerCase().trim()
    if (hostKey && seenHostKeys.has(hostKey)) {
      return false
    }
    if (hostKey) {
      seenHostKeys.add(hostKey)
    }
    return true
  })

  const protectedCount = deduplicatedWorkstations.filter(w => w.health_state === 'PROTECTED').length
  const exposedCount = deduplicatedWorkstations.filter(w => w.health_state === 'EXPOSED').length
  const staleCount = deduplicatedWorkstations.filter(w => w.health_state === 'STALE').length
  const totalCount = deduplicatedWorkstations.length

  const summary = data?.summary
  const score = totalCount > 0
    ? Math.round((protectedCount / totalCount) * 1000) / 10
    : (summary?.fleet_protection_score ?? 0.0)

  const filteredWorkstations = deduplicatedWorkstations.filter((w) => {
    if (search) {
      const q = search.toLowerCase()
      const matchHost = (w.hostname || '').toLowerCase().includes(q)
      const matchUser = (w.user_identifier || '').toLowerCase().includes(q)
      const matchDevice = (w.device_id || '').toLowerCase().includes(q)
      if (!matchHost && !matchUser && !matchDevice) return false
    }

    if (filter === 'all') return true
    if (filter === 'protected') return w.health_state === 'PROTECTED'
    if (filter === 'action_needed') return w.health_state === 'EXPOSED' || w.health_state === 'STALE'
    if (filter === 'stale') return w.health_state === 'STALE'
    return true
  })

  return (
    <div className="soc-coverage-page">
      {/* Header */}
      <div className="page-header soc-page-header">
        <div>
          <h1>Coverage & Control Health</h1>
          <p>Live boundary inspection: which workstations, developer environments, and AI coding tools are actively wrapped, enforced, stale, or bypassing proxy controls.</p>
        </div>
        <div className="soc-header-controls">
          <button
            type="button"
            className="soc-btn-secondary"
            onClick={loadData}
          >
            🔄 Refresh Boundary Map
          </button>
        </div>
      </div>

      {/* Top KPI Banner */}
      <div className="stats-grid soc-stats-grid">
        <div className="card stat-tile soc-clickable-tile" onClick={() => setFilter('all')}>
          <div className="stat-header-row">
            <div className="stat-label">FLEET PROTECTION SCORE</div>
            <span className={`soc-delta-badge ${score >= 90 ? 'delta-success' : score >= 70 ? 'delta-warning' : 'delta-danger'}`}>
              Health
            </span>
          </div>
          <div
            className="stat-value"
            style={{
              color: score >= 90 ? '#10b981' : score >= 70 ? '#f59e0b' : '#ef4444',
            }}
          >
            {score.toFixed(1)}%
          </div>
          <div className="stat-subtext">Active control enclosed</div>
        </div>

        <div className="card stat-tile soc-clickable-tile" onClick={() => setFilter('protected')}>
          <div className="stat-header-row">
            <div className="stat-label">PROTECTED WORKSTATIONS</div>
            <span className="soc-delta-badge delta-success">Live</span>
          </div>
          <div className="stat-value" style={{ color: '#10b981' }}>
            {protectedCount}
          </div>
          <div className="stat-subtext">Heartbeat live & enforced</div>
        </div>

        <div className="card stat-tile soc-clickable-tile tile-danger" onClick={() => setFilter('action_needed')}>
          <div className="stat-header-row">
            <div className="stat-label">EXPOSED / UNWRAPPED</div>
            <span className="soc-delta-badge delta-danger">{exposedCount > 0 ? 'Urgent' : '0'}</span>
          </div>
          <div className="stat-value" style={{ color: exposedCount > 0 ? '#ef4444' : 'var(--text-muted)' }}>
            {exposedCount}
          </div>
          <div className="stat-subtext">Action required immediately</div>
        </div>

        <div className="card stat-tile soc-clickable-tile tile-warning" onClick={() => setFilter('stale')}>
          <div className="stat-header-row">
            <div className="stat-label">STALE HEARTBEATS</div>
            <span className="soc-delta-badge delta-warning">{staleCount > 0 ? 'Review' : '0'}</span>
          </div>
          <div className="stat-value" style={{ color: staleCount > 0 ? '#f59e0b' : 'var(--text-muted)' }}>
            {staleCount}
          </div>
          <div className="stat-subtext">No ping in &gt; 24h</div>
        </div>

        <div className="card stat-tile soc-clickable-tile tile-danger">
          <div className="stat-header-row">
            <div className="stat-label">TAMPER DETECTIONS (24H)</div>
            <span className="soc-delta-badge delta-danger">24H</span>
          </div>
          <div className="stat-value" style={{ color: (summary?.tamper_alerts_24h ?? 0) > 0 ? '#ef4444' : 'var(--text-muted)' }}>
            {summary?.tamper_alerts_24h ?? 0}
          </div>
          <div className="stat-subtext">Config reversion / bypass</div>
        </div>
      </div>

      {/* Coverage Matrix Table Panel */}
      <div className="card soc-panel">
        <div className="soc-card-header" style={{ marginBottom: 20 }}>
          <div>
            <div className="card-title">Workstation Boundary Health Matrix</div>
            <div className="soc-card-subtitle">{filteredWorkstations.length} of {totalCount} workstations monitored</div>
          </div>
          <div className="soc-filter-bar">
            <div className="soc-time-toggle" role="group" aria-label="Health Filter">
              <button
                type="button"
                className={`soc-time-btn ${filter === 'all' ? 'active' : ''}`}
                onClick={() => setFilter('all')}
              >
                All ({totalCount})
              </button>
              <button
                type="button"
                className={`soc-time-btn ${filter === 'protected' ? 'active' : ''}`}
                onClick={() => setFilter('protected')}
              >
                🛡️ Protected ({protectedCount})
              </button>
              <button
                type="button"
                className={`soc-time-btn ${filter === 'action_needed' ? 'active' : ''}`}
                onClick={() => setFilter('action_needed')}
              >
                ⚠️ Action Needed ({exposedCount + staleCount})
              </button>
              <button
                type="button"
                className={`soc-time-btn ${filter === 'stale' ? 'active' : ''}`}
                onClick={() => setFilter('stale')}
              >
                🕒 Stale ({staleCount})
              </button>
            </div>
            <div className="soc-filter-search-box">
              <span className="search-icon">🔍</span>
              <input
                type="text"
                className="soc-filter-input"
                placeholder="Filter by hostname, user or ID..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                style={{ width: 240 }}
              />
            </div>
          </div>
        </div>

        {error && (
          <div className="card" style={{ padding: 16, borderColor: 'var(--danger)', color: 'var(--danger)', marginBottom: 16 }}>
            {error}
          </div>
        )}

        {loading ? (
          <div className="loading" style={{ height: 220 }}>Inspecting workstation boundary health...</div>
        ) : filteredWorkstations.length === 0 ? (
          <div className="empty-state">
            <p style={{ fontSize: 15, fontWeight: 500 }}>No developer workstations found matching the criteria.</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>Deploy the Agent Control daemon (`agentcontrol enroll`) to observe developer coverage.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Workstation</th>
                  <th>Developer</th>
                  <th>Platform / Daemon</th>
                  <th>Heartbeat Freshness</th>
                  <th>Boundary Health</th>
                  <th>IDE Protection Matrix</th>
                </tr>
              </thead>
              <tbody>
                {filteredWorkstations.map((w) => {
                  const isProtected = w.health_state === 'PROTECTED'
                  const isStale = w.health_state === 'STALE'
                  const isExposed = w.health_state === 'EXPOSED'

                  const badgeClass = isProtected
                    ? 'green'
                    : isExposed
                    ? 'red'
                    : isStale
                    ? 'amber'
                    : 'red'

                  return (
                    <tr key={w.device_id} className="runs-table-row">
                      <td>
                        <strong style={{ fontSize: 13 }}>{w.hostname}</strong>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {w.device_id.slice(0, 10)}...
                        </div>
                      </td>
                      <td style={{ fontSize: 13 }}>
                        {w.user_identifier}
                      </td>
                      <td style={{ fontSize: 12 }}>
                        <span style={{ textTransform: 'capitalize' }}>{w.os}</span>
                        <span style={{ color: 'var(--text-muted)', marginLeft: 6 }}>v{w.os_version}</span>
                      </td>
                      <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        {w.last_heartbeat_at ? (
                          new Date(w.last_heartbeat_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
                        ) : (
                          'Never'
                        )}
                      </td>
                      <td>
                        <span className={`badge ${badgeClass}`}>
                          {w.health_state}
                        </span>
                        {w.tamper_count_24h > 0 && (
                          <span className="badge red" style={{ marginLeft: 6 }} title="Tamper events detected in last 24h">
                            🚨 {w.tamper_count_24h} Tamper
                          </span>
                        )}
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                          {w.ide_coverage.map((ide) => {
                            const isEnforced = ide.status === 'ENFORCED'
                            return (
                              <span
                                key={ide.id}
                                className={`badge ${isEnforced ? 'green' : 'gray'}`}
                                style={{
                                  fontSize: 11,
                                  opacity: isEnforced ? 1 : 0.45,
                                  border: isEnforced ? '1px solid rgba(16, 185, 129, 0.4)' : '1px dashed var(--border)',
                                }}
                                title={`${ide.name}: ${ide.status}`}
                              >
                                {isEnforced ? '🛡️' : '○'} {ide.name}
                              </span>
                            )
                          })}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Provenance Footer */}
        <div style={{ padding: '12px 20px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span style={{ color: '#10b981' }}>●</span>
            <span>Integrity: <strong style={{ color: '#10b981' }}>Continuous</strong> · System of Record: <strong>Workstation Compliance & Telemetry Store</strong></span>
          </span>
          <span>Last audit generation: {data?.generated_at ? new Date(data.generated_at).toLocaleTimeString() : 'N/A'}</span>
        </div>
      </div>
    </div>
  )
}
