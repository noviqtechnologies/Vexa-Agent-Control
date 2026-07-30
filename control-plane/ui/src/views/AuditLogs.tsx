import { useEffect, useState, useRef } from 'react'
import { api, type RedactedEvent } from '../api/client'

const DECISION_CLASS: Record<string, string> = {
  allowed: 'badge-success',
  denied: 'badge-danger',
  warned: 'badge-warning',
}

function formatTs(ms: number): string {
  return new Date(ms).toLocaleString([], {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

const LIMIT = 200

export default function AuditLogs() {
  const [events, setEvents] = useState<RedactedEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [filterDecision, setFilterDecision] = useState<string>('all')
  const [filterAgent, setFilterAgent] = useState('')
  const [filterTool, setFilterTool] = useState('')
  const [downloading, setDownloading] = useState(false)
  const tableRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    api.listEvents(LIMIT)
      .then(data => setEvents(data ?? []))
      .catch(() => setEvents([]))
      .finally(() => setLoading(false))
  }, [])

  function refresh() {
    setLoading(true)
    api.listEvents(LIMIT)
      .then(data => setEvents(data ?? []))
      .catch(() => setEvents([]))
      .finally(() => setLoading(false))
  }

  const filtered = events.filter(e => {
    if (filterDecision !== 'all' && e.decision !== filterDecision) return false
    if (filterAgent && !e.agent_id.toLowerCase().includes(filterAgent.toLowerCase())) return false
    if (filterTool && !e.tool_name.toLowerCase().includes(filterTool.toLowerCase())) return false
    return true
  })

  function downloadCSV() {
    setDownloading(true)
    const headers = ['Event ID', 'Timestamp', 'Agent ID', 'Tool', 'Decision', 'DLP Findings', 'Injection Findings']
    const rows = filtered.map(e => [
      e.event_id,
      new Date(e.timestamp_ms).toISOString(),
      e.agent_id,
      e.tool_name,
      e.decision,
      e.dlp_findings?.map(f => f.category).join('; ') ?? '',
      e.injection_findings?.map(f => f.pattern_name).join('; ') ?? '',
    ])
    const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `agentwall-audit-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
    setDownloading(false)
  }

  return (
    <>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Audit Logs</h1>
          <p>HMAC-tamper-evident event log of all agent tool calls, decisions, and findings.</p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="refresh-btn" onClick={refresh} disabled={loading}>
            {loading ? 'Loading…' : 'Refresh'}
          </button>
          <button className="refresh-btn" onClick={downloadCSV} disabled={downloading || filtered.length === 0}>
            {downloading ? 'Exporting…' : '↓ Export CSV'}
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card" style={{ marginBottom: 20, padding: '16px 20px' }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: '1 1 160px' }}>
            <label style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Decision
            </label>
            <select
              className="refresh-btn"
              style={{ width: '100%', background: 'rgba(255,255,255,0.05)' }}
              value={filterDecision}
              onChange={e => setFilterDecision(e.target.value)}
            >
              <option value="all">All Decisions</option>
              <option value="allowed">Allowed</option>
              <option value="denied">Denied</option>
              <option value="warned">Warned</option>
            </select>
          </div>
          <div style={{ flex: '1 1 160px' }}>
            <label style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Budget Exhausted
            </label>
            <select
              className="refresh-btn"
              style={{ width: '100%', background: 'rgba(255,255,255,0.05)' }}
              value={filterDecision}
              onChange={e => setFilterDecision(e.target.value)}
            >
              <option value="all">All</option>
              <option value="budget_exhausted">Budget Exhausted Only</option>
            </select>
          </div>
          <div style={{ flex: '2 1 200px' }}>
            <label style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Agent ID
            </label>
            <input
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', color: 'var(--text-primary)', fontSize: 13, width: '100%', outline: 'none', fontFamily: 'var(--font-mono)' }}
              placeholder="Filter by agent ID…"
              value={filterAgent}
              onChange={e => setFilterAgent(e.target.value)}
            />
          </div>
          <div style={{ flex: '2 1 200px' }}>
            <label style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Tool Name
            </label>
            <input
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', color: 'var(--text-primary)', fontSize: 13, width: '100%', outline: 'none', fontFamily: 'var(--font-mono)' }}
              placeholder="Filter by tool name…"
              value={filterTool}
              onChange={e => setFilterTool(e.target.value)}
            />
          </div>
          <div style={{ alignSelf: 'flex-end', whiteSpace: 'nowrap', fontSize: 13, color: 'var(--text-muted)' }}>
            {filtered.length} / {events.length} events
          </div>
        </div>
      </div>

      <div className="card" ref={tableRef}>
        {loading ? (
          <div className="loading">Loading audit events</div>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 580, overflowY: 'auto' }}>
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Agent ID</th>
                  <th>Group ID</th>
                  <th>Tool</th>
                  <th>Decision</th>
                  <th>DLP Findings</th>
                  <th>Injection</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="empty-state">No events match the current filters.</td>
                  </tr>
                ) : filtered.map(e => (
                  <tr key={e.event_id}>
                    <td style={{ fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                      {formatTs(e.timestamp_ms)}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {e.agent_id}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 500, color: 'var(--text-primary)' }}>
                      {e.tool_name}
                    </td>
                    <td>
                      <span className={`badge ${DECISION_CLASS[e.decision] ?? 'badge-info'}`}>
                        {e.decision}
                      </span>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {e.dlp_findings?.length > 0 ? (
                        <span className="badge badge-warning" title={e.dlp_findings.map(f => f.pattern_name).join(', ')}>
                          {e.dlp_findings.length} finding{e.dlp_findings.length > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
                      )}
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {e.injection_findings?.length > 0 ? (
                        <span className="badge badge-danger" title={e.injection_findings.map(f => f.pattern_name).join(', ')}>
                          {e.injection_findings.length} pattern{e.injection_findings.length > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </>
  )
}
