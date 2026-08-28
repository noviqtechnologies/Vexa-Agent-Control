import { useEffect, useState, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, type RedactedEvent } from '../api/client'

const DECISION_CLASS: Record<string, string> = {
  allowed: 'badge-success',
  denied: 'badge-danger',
  warned: 'badge-warning',
  drift: 'badge-warning',
}

function formatTs(ms: number): string {
  return new Date(ms).toLocaleString([], {
    month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

const LIMIT = 200

export default function AuditLogs() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [events, setEvents] = useState<RedactedEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [filterDecision, setFilterDecision] = useState<string>(searchParams.get('decision') || 'all')
  const [filterAgent, setFilterAgent] = useState(searchParams.get('agent') || '')
  const [filterTool, setFilterTool] = useState(searchParams.get('tool') || '')
  const [filterQuick, setFilterQuick] = useState<'all' | 'allowed' | 'violations' | 'security' | 'unlisted'>('all')
  const [selectedEvent, setSelectedEvent] = useState<RedactedEvent | null>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [downloading, setDownloading] = useState(false)
  const tableRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (searchParams.get('decision')) {
      setFilterDecision(searchParams.get('decision')!)
    }
    if (searchParams.get('agent')) {
      setFilterAgent(searchParams.get('agent')!)
    }
    if (searchParams.get('tool')) {
      setFilterTool(searchParams.get('tool')!)
    }
  }, [searchParams])

  useEffect(() => {
    fetchEvents()
  }, [])

  function fetchEvents() {
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

    if (filterQuick === 'allowed' && e.decision !== 'allowed') return false
    if (filterQuick === 'violations' && e.decision !== 'denied' && e.decision !== 'warned') return false
    if (filterQuick === 'security' && (!e.dlp_findings?.length && !e.injection_findings?.length)) return false
    if (filterQuick === 'unlisted' && !e.tool_name.includes('<unlisted_tool>')) return false

    return true
  })

  // Quick stats computed from current events
  const totalCount = events.length
  const allowedCount = events.filter(e => e.decision === 'allowed').length
  const violationCount = events.filter(e => e.decision === 'denied' || e.decision === 'warned').length
  const securityCount = events.filter(e => (e.dlp_findings?.length || 0) > 0 || (e.injection_findings?.length || 0) > 0).length

  function copyToClipboard(text: string, key: string) {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  function downloadCSV() {
    setDownloading(true)
    const headers = [
      'Event ID',
      'Timestamp (ISO)',
      'Timestamp (Local)',
      'Agent ID',
      'Tool Name',
      'Decision',
      'DLP Findings Count',
      'DLP Categories',
      'Injection Findings Count',
      'Injection Patterns',
      'Session ID',
    ]
    const rows = filtered.map(e => [
      e.event_id,
      new Date(e.timestamp_ms).toISOString(),
      formatTs(e.timestamp_ms),
      e.agent_id,
      e.tool_name,
      e.decision,
      e.dlp_findings?.length ?? 0,
      e.dlp_findings?.map(f => f.category || f.pattern_name).join('; ') ?? '',
      e.injection_findings?.length ?? 0,
      e.injection_findings?.map(f => f.pattern_name).join('; ') ?? '',
      e.session_id ?? '',
    ])
    const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `agentcontrol-audit-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
    setDownloading(false)
  }

  function clearAllFilters() {
    setFilterDecision('all')
    setFilterAgent('')
    setFilterTool('')
    setFilterQuick('all')
    setSearchParams({})
  }

  return (
    <>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 4 }}>Audit Logs</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
            HMAC tamper-evident cryptographic event log of all agent tool calls, decisions, DLP triggers, and injection defenses.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="refresh-btn" onClick={fetchEvents} disabled={loading} style={{ cursor: 'pointer' }}>
            {loading ? 'Loading…' : '↻ Refresh'}
          </button>
          <button
            className="refresh-btn"
            onClick={downloadCSV}
            disabled={downloading || filtered.length === 0}
            style={{ cursor: 'pointer', background: 'rgba(99, 102, 241, 0.15)', borderColor: 'var(--accent)' }}
          >
            {downloading ? 'Exporting…' : '↓ Export CSV'}
          </button>
        </div>
      </div>

      {/* KPI Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14, marginBottom: 20 }}>
        <div className="card" style={{ padding: '14px 18px', background: 'rgba(255, 255, 255, 0.03)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Total Invocations</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>{totalCount}</div>
        </div>
        <div className="card" style={{ padding: '14px 18px', background: 'rgba(16, 185, 129, 0.05)', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--success)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Allowed</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--success)', marginTop: 4 }}>{allowedCount}</div>
        </div>
        <div className="card" style={{ padding: '14px 18px', background: violationCount > 0 ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 255, 255, 0.03)', border: violationCount > 0 ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid var(--border)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: violationCount > 0 ? 'var(--danger)' : 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Violations (Denied/Warned)</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: violationCount > 0 ? 'var(--danger)' : 'var(--text-primary)', marginTop: 4 }}>{violationCount}</div>
        </div>
        <div className="card" style={{ padding: '14px 18px', background: securityCount > 0 ? 'rgba(245, 158, 11, 0.08)' : 'rgba(255, 255, 255, 0.03)', border: securityCount > 0 ? '1px solid rgba(245, 158, 11, 0.3)' : '1px solid var(--border)' }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: securityCount > 0 ? 'var(--warning)' : 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Security Alerts (DLP / Inj)</div>
          <div style={{ fontSize: 24, fontWeight: 700, color: securityCount > 0 ? 'var(--warning)' : 'var(--text-primary)', marginTop: 4 }}>{securityCount}</div>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="card" style={{ marginBottom: 20, padding: '16px 20px', background: 'rgba(20, 27, 45, 0.65)' }}>
        {/* Quick Filter Chips */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 14, alignItems: 'center' }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', marginRight: 4 }}>Quick Filter:</span>
          <button
            onClick={() => setFilterQuick('all')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'all' ? 'var(--accent)' : 'var(--border)',
              background: filterQuick === 'all' ? 'var(--accent)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'all' ? '#fff' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            All Events
          </button>
          <button
            onClick={() => setFilterQuick('allowed')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'allowed' ? 'var(--success)' : 'var(--border)',
              background: filterQuick === 'allowed' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'allowed' ? 'var(--success)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            Allowed Only
          </button>
          <button
            onClick={() => setFilterQuick('violations')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'violations' ? 'var(--danger)' : 'var(--border)',
              background: filterQuick === 'violations' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'violations' ? 'var(--danger)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            Denied / Warned
          </button>
          <button
            onClick={() => setFilterQuick('security')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'security' ? 'var(--warning)' : 'var(--border)',
              background: filterQuick === 'security' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'security' ? 'var(--warning)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            DLP / Injection Flags
          </button>
          <button
            onClick={() => setFilterQuick('unlisted')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'unlisted' ? 'var(--accent)' : 'var(--border)',
              background: filterQuick === 'unlisted' ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'unlisted' ? 'var(--accent)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            Privacy Redacted (&lt;unlisted_tool&gt;)
          </button>

          {(filterDecision !== 'all' || filterAgent || filterTool || filterQuick !== 'all') && (
            <button
              onClick={clearAllFilters}
              style={{
                marginLeft: 'auto', padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)',
                background: 'transparent', border: '1px dashed var(--border)', color: 'var(--text-muted)', cursor: 'pointer',
              }}
            >
              ✕ Reset Filters
            </button>
          )}
        </div>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: '1 1 150px' }}>
            <label style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Decision
            </label>
            <select
              className="refresh-btn"
              style={{ width: '100%', background: 'rgba(255,255,255,0.05)', cursor: 'pointer' }}
              value={filterDecision}
              onChange={e => setFilterDecision(e.target.value)}
            >
              <option value="all">All Decisions</option>
              <option value="allowed">Allowed</option>
              <option value="denied">Denied</option>
              <option value="warned">Warned</option>
              <option value="drift">Schema Drift Detected</option>
            </select>
          </div>
          <div style={{ flex: '2 1 200px' }}>
            <label style={{ fontSize: 11, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
              Agent ID / Subject
            </label>
            <input
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', color: 'var(--text-primary)', fontSize: 13, width: '100%', outline: 'none', fontFamily: 'var(--font-mono)' }}
              placeholder="Search by agent ID or subject…"
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
              placeholder="Search by tool name…"
              value={filterTool}
              onChange={e => setFilterTool(e.target.value)}
            />
          </div>
          <div style={{ alignSelf: 'flex-end', whiteSpace: 'nowrap', fontSize: 13, color: 'var(--text-muted)', paddingBottom: 6 }}>
            Showing <strong>{filtered.length}</strong> of <strong>{events.length}</strong> events
          </div>
        </div>
      </div>

      {/* Main Table */}
      <div className="card" ref={tableRef} style={{ background: 'rgba(20, 27, 45, 0.65)', overflow: 'hidden' }}>
        {loading ? (
          <div className="loading" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            Loading audit events…
          </div>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 600, overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: 'rgba(255,255,255,0.02)' }}>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Timestamp</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Agent ID / Subject</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Tool Name</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Decision</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>DLP Findings</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Injection</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-state" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                      No events match the current filter criteria.
                    </td>
                  </tr>
                ) : filtered.map(e => {
                  const isUnlisted = e.tool_name === '<unlisted_tool>'
                  const hasDlp = (e.dlp_findings?.length || 0) > 0
                  const hasInj = (e.injection_findings?.length || 0) > 0

                  return (
                    <tr
                      key={e.event_id}
                      onClick={() => setSelectedEvent(e)}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        transition: 'background 0.15s ease',
                      }}
                      onMouseEnter={ev => (ev.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
                      onMouseLeave={ev => (ev.currentTarget.style.background = 'transparent')}
                    >
                      <td style={{ padding: '12px 16px', fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }} title={new Date(e.timestamp_ms).toISOString()}>
                        {formatTs(e.timestamp_ms)}
                      </td>
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: 12, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)' }} />
                          {e.agent_id}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 500 }}>
                        {isUnlisted ? (
                          <span style={{ color: 'var(--text-muted)', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>
                            &lt;unlisted_tool&gt;
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-primary)', background: 'rgba(99, 102, 241, 0.1)', padding: '2px 8px', borderRadius: 4, border: '1px solid rgba(99, 102, 241, 0.2)' }}>
                            {e.tool_name}
                          </span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge ${DECISION_CLASS[e.decision] ?? 'badge-info'}`}>
                          {e.decision}
                        </span>
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: 12 }}>
                        {hasDlp ? (
                          <span className="badge badge-warning" title={e.dlp_findings.map(f => f.category || f.pattern_name).join(', ')}>
                            {e.dlp_findings.length} finding{e.dlp_findings.length > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', fontSize: 12 }}>
                        {hasInj ? (
                          <span className="badge badge-danger" title={e.injection_findings.map(f => f.pattern_name).join(', ')}>
                            {e.injection_findings.length} pattern{e.injection_findings.length > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: '12px 16px', textAlign: 'right' }}>
                        <button
                          onClick={(ev) => {
                            ev.stopPropagation()
                            setSelectedEvent(e)
                          }}
                          style={{
                            background: 'rgba(255,255,255,0.06)',
                            border: '1px solid var(--border)',
                            color: 'var(--text-primary)',
                            padding: '4px 10px',
                            fontSize: 11,
                            borderRadius: 'var(--radius-sm)',
                            cursor: 'pointer',
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Event Details Modal / Drawer */}
      {selectedEvent && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: 20,
          }}
          onClick={() => setSelectedEvent(null)}
        >
          <div
            className="card"
            style={{
              maxWidth: 680,
              width: '100%',
              background: '#0e131f',
              border: '1px solid var(--border-default)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.5)',
              borderRadius: 'var(--radius)',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              overflow: 'hidden',
            }}
            onClick={e => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h2 style={{ fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 10 }}>
                  Event Inspection
                  <span className={`badge ${DECISION_CLASS[selectedEvent.decision] ?? 'badge-info'}`}>
                    {selectedEvent.decision.toUpperCase()}
                  </span>
                </h2>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 4 }}>
                  ID: {selectedEvent.event_id}
                </div>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{
                  background: 'rgba(255,255,255,0.06)',
                  border: '1px solid var(--border)',
                  color: 'var(--text-muted)',
                  fontSize: 16,
                  cursor: 'pointer',
                  width: 32,
                  height: 32,
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                ✕
              </button>
            </div>

            {/* Modal Body */}
            <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 18 }}>
              {/* Key Attributes Grid */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Timestamp</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', marginTop: 4, color: 'var(--text-primary)' }}>
                    {formatTs(selectedEvent.timestamp_ms)}
                  </div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                    {new Date(selectedEvent.timestamp_ms).toISOString()}
                  </div>
                </div>

                <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Agent / Identity</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', marginTop: 4, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {selectedEvent.agent_id}
                  </div>
                </div>

                <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Tool Name</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', marginTop: 4, color: selectedEvent.tool_name === '<unlisted_tool>' ? 'var(--text-muted)' : 'var(--accent)' }}>
                    {selectedEvent.tool_name}
                  </div>
                  {selectedEvent.tool_name === '<unlisted_tool>' && (
                    <div style={{ fontSize: 11, color: 'var(--warning)', marginTop: 2 }}>
                      🔒 Zero-Knowledge Redacted (not in policy allowlist)
                    </div>
                  )}
                </div>

                <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)' }}>
                  <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Session ID</div>
                  <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', marginTop: 4, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                    {selectedEvent.session_id || '—'}
                  </div>
                </div>
              </div>

              {/* Security Findings Section */}
              <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                  Security & DLP Findings
                </div>
                {(!selectedEvent.dlp_findings?.length && !selectedEvent.injection_findings?.length && !selectedEvent.semantic_findings?.length) ? (
                  <div style={{ fontSize: 13, color: 'var(--success)', display: 'flex', alignItems: 'center', gap: 6 }}>
                    ✓ Clean — No data leaks or prompt injections detected in this event.
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {selectedEvent.dlp_findings?.map((f, idx) => (
                      <div key={idx} style={{ background: 'rgba(245,158,11,0.1)', border: '1px solid rgba(245,158,11,0.25)', padding: '8px 12px', borderRadius: 4, fontSize: 13 }}>
                        <strong style={{ color: 'var(--warning)' }}>DLP Flag:</strong> {f.category} ({f.pattern_name}) — count: {f.count}
                      </div>
                    ))}
                    {selectedEvent.injection_findings?.map((f, idx) => (
                      <div key={idx} style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.25)', padding: '8px 12px', borderRadius: 4, fontSize: 13 }}>
                        <strong style={{ color: 'var(--danger)' }}>Prompt Injection:</strong> {f.pattern_name} — count: {f.count}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Raw JSON viewer */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                    Raw Event Telemetry JSON
                  </span>
                  <button
                    onClick={() => copyToClipboard(JSON.stringify(selectedEvent, null, 2), 'json')}
                    style={{
                      background: 'rgba(255,255,255,0.06)',
                      border: '1px solid var(--border)',
                      color: 'var(--text-primary)',
                      padding: '3px 8px',
                      fontSize: 11,
                      borderRadius: 4,
                      cursor: 'pointer',
                    }}
                  >
                    {copiedKey === 'json' ? '✓ Copied!' : 'Copy JSON'}
                  </button>
                </div>
                <pre
                  style={{
                    background: '#07090e',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    padding: 12,
                    fontSize: 12,
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--text-secondary)',
                    maxHeight: 180,
                    overflowY: 'auto',
                  }}
                >
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>

            {/* Modal Footer / Actions */}
            <div style={{ padding: '14px 24px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', background: 'rgba(0,0,0,0.2)' }}>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  onClick={() => {
                    setFilterAgent(selectedEvent.agent_id)
                    setSelectedEvent(null)
                  }}
                  style={{
                    background: 'rgba(255,255,255,0.06)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-primary)',
                    padding: '6px 12px',
                    fontSize: 12,
                    borderRadius: 'var(--radius-sm)',
                    cursor: 'pointer',
                  }}
                >
                  Filter by this Agent
                </button>
                {selectedEvent.tool_name !== '<unlisted_tool>' && (
                  <button
                    onClick={() => {
                      setFilterTool(selectedEvent.tool_name)
                      setSelectedEvent(null)
                    }}
                    style={{
                      background: 'rgba(255,255,255,0.06)',
                      border: '1px solid var(--border)',
                      color: 'var(--text-primary)',
                      padding: '6px 12px',
                      fontSize: 12,
                      borderRadius: 'var(--radius-sm)',
                      cursor: 'pointer',
                    }}
                  >
                    Filter by this Tool
                  </button>
                )}
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                style={{
                  background: 'var(--accent)',
                  border: 'none',
                  color: '#fff',
                  padding: '6px 16px',
                  fontSize: 12,
                  fontWeight: 600,
                  borderRadius: 'var(--radius-sm)',
                  cursor: 'pointer',
                }}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
