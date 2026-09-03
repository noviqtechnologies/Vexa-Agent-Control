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
    : (summary?.fleet_protection_score ?? 100.0)

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
    <div className="soc-spend-analytics-page">
      {/* Header */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Coverage & Control Health</h1>
          <p>Live boundary inspection: which workstations, developer environments, and AI coding tools are actively wrapped, enforced, stale, or bypassing proxy controls.</p>
        </div>
        <div>
          <button
            type="button"
            className="soc-btn-secondary"
            onClick={loadData}
            style={{ fontSize: 13 }}
          >
            🔄 Refresh Boundary Map
          </button>
        </div>
      </div>

      {/* Top KPI Banner */}
      <div className="card" style={{ padding: 24, marginBottom: 24, display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 16 }}>
        <div>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>
            FLEET PROTECTION SCORE
          </p>
          <div
            style={{
              fontSize: 32,
              fontWeight: 700,
              color: score >= 90 ? '#10b981' : score >= 70 ? '#f59e0b' : '#ef4444',
            }}
          >
            {score.toFixed(1)}%
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Active control enclosed
          </span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>
            PROTECTED WORKSTATIONS
          </p>
          <div style={{ fontSize: 32, fontWeight: 700, color: '#10b981' }}>
            {protectedCount}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            Heartbeat live & enforced
          </span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>
            EXPOSED / UNWRAPPED
          </p>
          <div style={{ fontSize: 32, fontWeight: 700, color: exposedCount > 0 ? '#ef4444' : 'var(--text-muted)' }}>
            {exposedCount}
          </div>
          <span style={{ fontSize: 12, color: exposedCount > 0 ? '#ef4444' : 'var(--text-muted)' }}>
            Action required immediately
          </span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>
            STALE HEARTBEATS
          </p>
          <div style={{ fontSize: 32, fontWeight: 700, color: staleCount > 0 ? '#f59e0b' : 'var(--text-muted)' }}>
            {staleCount}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
            No ping in &gt; 24h
          </span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 16 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>
            TAMPER DETECTIONS
          </p>
          <div style={{ fontSize: 32, fontWeight: 700, color: (summary?.tamper_alerts_24h ?? 0) > 0 ? '#ef4444' : 'var(--text-muted)' }}>
            {summary?.tamper_alerts_24h ?? 0}
          </div>
          <span style={{ fontSize: 12, color: (summary?.tamper_alerts_24h ?? 0) > 0 ? '#ef4444' : 'var(--text-muted)' }}>
            Config reversion / bypass
          </span>
        </div>
      </div>

      {/* Filter and Search Toolbar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, gap: 16 }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <button
            type="button"
            className={`soc-time-btn ${filter === 'all' ? 'active' : ''}`}
            onClick={() => setFilter('all')}
          >
            All Workstations ({totalCount})
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

        <input
          type="text"
          className="run-filter-input"
          placeholder="Filter by hostname, user or ID..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{ width: 280 }}
        />
      </div>

      {error && (
        <div className="card" style={{ padding: 16, borderColor: 'var(--danger)', color: 'var(--danger)', marginBottom: 16 }}>
          {error}
        </div>
      )}

      {/* Coverage Matrix Table */}
      <div className="runs-table-card card">
        {loading ? (
          <div className="loading" style={{ height: 220 }}>Inspecting workstation boundary health...</div>
        ) : filteredWorkstations.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: 15, fontWeight: 500 }}>No developer workstations found matching the criteria.</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>Deploy the Agent Control daemon (`agentcontrol enroll`) to observe developer coverage.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
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
        <div style={{ padding: '12px 20px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)' }}>
          <span>Confidence: <strong style={{ color: '#10b981' }}>observed</strong> · Evidence source: <strong>devices + device_compliance_reports</strong></span>
          <span>Last audit generation: {data?.generated_at ? new Date(data.generated_at).toLocaleTimeString() : 'N/A'}</span>
        </div>
      </div>
    </div>
  )
}
