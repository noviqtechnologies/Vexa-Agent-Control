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
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function formatRelativeTime(ms: number): string {
  const diff = Date.now() - ms
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return `${Math.max(1, secs)}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function getOperationMeta(toolName: string) {
  if (toolName.startsWith('llm:')) {
    const model = toolName.slice(4)
    return {
      type: 'llm' as const,
      label: 'LLM Inference',
      badge: '⚡ LLM Call',
      target: model,
      icon: '🧠',
      isUnlisted: false,
    }
  }
  if (toolName === '<unlisted_tool>') {
    return {
      type: 'unlisted' as const,
      label: 'Privacy Redacted',
      badge: '🔒 Redacted Tool',
      target: '<unlisted_tool>',
      icon: '🔒',
      isUnlisted: true,
    }
  }
  return {
    type: 'tool' as const,
    label: 'Tool Invocation',
    badge: '🛠️ Tool Call',
    target: toolName,
    icon: '🛠️',
    isUnlisted: false,
  }
}

const LIMIT = 200

export default function AuditLogs() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [events, setEvents] = useState<RedactedEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [filterDecision, setFilterDecision] = useState<string>(searchParams.get('decision') || 'all')
  const [filterAgent, setFilterAgent] = useState(searchParams.get('agent') || '')
  const [filterTool, setFilterTool] = useState(searchParams.get('tool') || '')
  const [filterQuick, setFilterQuick] = useState<
    'all' | 'allowed' | 'violations' | 'dlp' | 'injection' | 'llm' | 'tools' | 'unlisted'
  >('all')
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
    if (filterQuick === 'dlp' && (!e.dlp_findings || e.dlp_findings.length === 0)) return false
    if (filterQuick === 'injection' && (!e.injection_findings || e.injection_findings.length === 0)) return false
    if (filterQuick === 'llm' && !e.tool_name.startsWith('llm:')) return false
    if (filterQuick === 'tools' && (e.tool_name.startsWith('llm:') || e.tool_name === '<unlisted_tool>')) return false
    if (filterQuick === 'unlisted' && e.tool_name !== '<unlisted_tool>') return false

    return true
  })

  // Quick stats computed from current events
  const totalCount = events.length
  const allowedCount = events.filter(e => e.decision === 'allowed').length
  const violationCount = events.filter(e => e.decision === 'denied' || e.decision === 'warned').length
  const dlpCount = events.filter(e => (e.dlp_findings?.length || 0) > 0).length
  const injectionCount = events.filter(e => (e.injection_findings?.length || 0) > 0).length

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
      'Channel Type',
      'Operation / Target',
      'Decision',
      'DLP Findings Count',
      'DLP Categories & Patterns',
      'Injection Findings Count',
      'Injection Patterns',
      'Session ID',
    ]
    const rows = filtered.map(e => {
      const op = getOperationMeta(e.tool_name)
      return [
        e.event_id,
        new Date(e.timestamp_ms).toISOString(),
        formatTs(e.timestamp_ms),
        e.agent_id,
        op.label,
        op.target,
        e.decision,
        e.dlp_findings?.length ?? 0,
        e.dlp_findings?.map(f => `${f.category}: ${f.pattern_name}`).join('; ') ?? '',
        e.injection_findings?.length ?? 0,
        e.injection_findings?.map(f => f.pattern_name).join('; ') ?? '',
        e.session_id ?? '',
      ]
    })
    const csv = [headers, ...rows].map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `agentcontrol-security-dlp-${Date.now()}.csv`
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
          <h1 style={{ fontSize: 24, fontWeight: 700, letterSpacing: '-0.02em', marginBottom: 4 }}>Security & DLP Logs</h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 14 }}>
            Cryptographic event telemetry stream of agent tool calls, LLM inference guardrails, real-time DLP redactions, and prompt injection defenses.
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
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 14, marginBottom: 20 }}>
        <div
          className="card"
          onClick={() => setFilterQuick('all')}
          style={{
            padding: '14px 18px',
            background: filterQuick === 'all' ? 'rgba(99, 102, 241, 0.12)' : 'rgba(255, 255, 255, 0.03)',
            border: filterQuick === 'all' ? '1px solid var(--accent)' : '1px solid var(--border)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Total Invocations
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>{totalCount}</div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>All evaluated events</div>
        </div>

        <div
          className="card"
          onClick={() => setFilterQuick('allowed')}
          style={{
            padding: '14px 18px',
            background: filterQuick === 'allowed' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(16, 185, 129, 0.05)',
            border: filterQuick === 'allowed' ? '1px solid var(--success)' : '1px solid rgba(16, 185, 129, 0.2)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--success)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Allowed
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: 'var(--success)', marginTop: 4 }}>{allowedCount}</div>
          <div style={{ fontSize: 11, color: 'rgba(16, 185, 129, 0.8)', marginTop: 2 }}>Zero-trust policy pass</div>
        </div>

        <div
          className="card"
          onClick={() => setFilterQuick('violations')}
          style={{
            padding: '14px 18px',
            background: filterQuick === 'violations' ? 'rgba(239, 68, 68, 0.15)' : violationCount > 0 ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 255, 255, 0.03)',
            border: filterQuick === 'violations' ? '1px solid var(--danger)' : violationCount > 0 ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid var(--border)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 600, color: violationCount > 0 ? 'var(--danger)' : 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Violations (Denied/Warned)
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: violationCount > 0 ? 'var(--danger)' : 'var(--text-primary)', marginTop: 4 }}>{violationCount}</div>
          <div style={{ fontSize: 11, color: violationCount > 0 ? 'rgba(239, 68, 68, 0.8)' : 'var(--text-secondary)', marginTop: 2 }}>Policy blocks & warnings</div>
        </div>

        <div
          className="card"
          onClick={() => setFilterQuick('dlp')}
          style={{
            padding: '14px 18px',
            background: filterQuick === 'dlp' ? 'rgba(245, 158, 11, 0.15)' : dlpCount > 0 ? 'rgba(245, 158, 11, 0.08)' : 'rgba(255, 255, 255, 0.03)',
            border: filterQuick === 'dlp' ? '1px solid var(--warning)' : dlpCount > 0 ? '1px solid rgba(245, 158, 11, 0.3)' : '1px solid var(--border)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 600, color: dlpCount > 0 ? 'var(--warning)' : 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            DLP Secrets Intercepted
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: dlpCount > 0 ? 'var(--warning)' : 'var(--text-primary)', marginTop: 4 }}>{dlpCount}</div>
          <div style={{ fontSize: 11, color: dlpCount > 0 ? 'rgba(245, 158, 11, 0.8)' : 'var(--text-secondary)', marginTop: 2 }}>Keys, PII & credentials</div>
        </div>

        <div
          className="card"
          onClick={() => setFilterQuick('injection')}
          style={{
            padding: '14px 18px',
            background: filterQuick === 'injection' ? 'rgba(239, 68, 68, 0.15)' : injectionCount > 0 ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255, 255, 255, 0.03)',
            border: filterQuick === 'injection' ? '1px solid var(--danger)' : injectionCount > 0 ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid var(--border)',
            cursor: 'pointer',
            transition: 'all 0.15s ease',
          }}
        >
          <div style={{ fontSize: 11, fontWeight: 600, color: injectionCount > 0 ? 'var(--danger)' : 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
            Prompt Injections
          </div>
          <div style={{ fontSize: 24, fontWeight: 700, color: injectionCount > 0 ? 'var(--danger)' : 'var(--text-primary)', marginTop: 4 }}>{injectionCount}</div>
          <div style={{ fontSize: 11, color: injectionCount > 0 ? 'rgba(239, 68, 68, 0.8)' : 'var(--text-secondary)', marginTop: 2 }}>Neutralized jailbreaks</div>
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
            onClick={() => setFilterQuick('dlp')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'dlp' ? 'var(--warning)' : 'var(--border)',
              background: filterQuick === 'dlp' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'dlp' ? 'var(--warning)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            🛡️ DLP Detections
          </button>

          <button
            onClick={() => setFilterQuick('injection')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'injection' ? 'var(--danger)' : 'var(--border)',
              background: filterQuick === 'injection' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'injection' ? 'var(--danger)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            🚨 Prompt Injections
          </button>

          <button
            onClick={() => setFilterQuick('llm')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'llm' ? 'var(--primary, #38bdf8)' : 'var(--border)',
              background: filterQuick === 'llm' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'llm' ? '#38bdf8' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            ⚡ LLM Inferences
          </button>

          <button
            onClick={() => setFilterQuick('tools')}
            style={{
              padding: '4px 10px', fontSize: 12, borderRadius: 'var(--radius-sm)', border: '1px solid',
              borderColor: filterQuick === 'tools' ? 'var(--accent)' : 'var(--border)',
              background: filterQuick === 'tools' ? 'rgba(99, 102, 241, 0.2)' : 'rgba(255,255,255,0.04)',
              color: filterQuick === 'tools' ? 'var(--accent)' : 'var(--text-secondary)', cursor: 'pointer',
            }}
          >
            🛠️ Tool Calls
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
            🔒 Privacy Redacted
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
              Operation / Model / Tool
            </label>
            <input
              style={{ background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '8px 12px', color: 'var(--text-primary)', fontSize: 13, width: '100%', outline: 'none', fontFamily: 'var(--font-mono)' }}
              placeholder="Search by model, tool, or target…"
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
            Loading Security & DLP events…
          </div>
        ) : (
          <div className="table-wrap" style={{ maxHeight: 600, overflowY: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', background: 'rgba(255,255,255,0.02)' }}>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Timestamp</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Agent ID / Subject</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Operation & Target</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Decision</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>DLP Findings</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Injection Defense</th>
                  <th style={{ padding: '12px 16px', fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', textAlign: 'right' }}>Action</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="empty-state" style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                      No security events match the current filter criteria.
                    </td>
                  </tr>
                ) : filtered.map(e => {
                  const op = getOperationMeta(e.tool_name)
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
                      {/* Timestamp */}
                      <td style={{ padding: '12px 16px', fontSize: 12, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', whiteSpace: 'nowrap' }} title={new Date(e.timestamp_ms).toISOString()}>
                        <div>{formatTs(e.timestamp_ms)}</div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', opacity: 0.8 }}>{formatRelativeTime(e.timestamp_ms)}</div>
                      </td>

                      {/* Agent / Subject */}
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: 12, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-primary)' }}>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                          <span style={{ width: 7, height: 7, borderRadius: '50%', background: e.decision === 'allowed' ? 'var(--accent)' : 'var(--danger)' }} />
                          {e.agent_id}
                        </span>
                      </td>

                      {/* Operation & Target */}
                      <td style={{ padding: '12px 16px', fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                        {op.type === 'llm' ? (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 3, background: 'rgba(56, 189, 248, 0.15)', color: '#38bdf8', fontWeight: 600, textTransform: 'uppercase' }}>
                              LLM
                            </span>
                            <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                              {op.target}
                            </span>
                          </div>
                        ) : op.type === 'unlisted' ? (
                          <span style={{ color: 'var(--text-muted)', background: 'rgba(255,255,255,0.05)', padding: '2px 8px', borderRadius: 4, fontSize: 12 }}>
                            🔒 &lt;unlisted_tool&gt;
                          </span>
                        ) : (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                            <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 3, background: 'rgba(99, 102, 241, 0.15)', color: 'var(--accent)', fontWeight: 600, textTransform: 'uppercase' }}>
                              TOOL
                            </span>
                            <span style={{ color: 'var(--text-primary)', fontWeight: 500 }}>
                              {op.target}
                            </span>
                          </div>
                        )}
                      </td>

                      {/* Decision */}
                      <td style={{ padding: '12px 16px' }}>
                        <span className={`badge ${DECISION_CLASS[e.decision] ?? 'badge-info'}`}>
                          {e.decision === 'allowed' ? '✓ allowed' : e.decision === 'denied' ? '⛔ denied' : e.decision}
                        </span>
                      </td>

                      {/* DLP Findings */}
                      <td style={{ padding: '12px 16px', fontSize: 12 }}>
                        {hasDlp ? (
                          <span className="badge badge-warning" title={e.dlp_findings.map(f => `${f.category}: ${f.pattern_name}`).join(', ')}>
                            {e.dlp_findings.length} finding{e.dlp_findings.length > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--success)', fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            ✓ Clean
                          </span>
                        )}
                      </td>

                      {/* Injection Defense */}
                      <td style={{ padding: '12px 16px', fontSize: 12 }}>
                        {hasInj ? (
                          <span className="badge badge-danger" title={e.injection_findings.map(f => f.pattern_name).join(', ')}>
                            {e.injection_findings.length} pattern{e.injection_findings.length > 1 ? 's' : ''}
                          </span>
                        ) : (
                          <span style={{ color: 'var(--success)', fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            ✓ Clean
                          </span>
                        )}
                      </td>

                      {/* Action */}
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
                            padding: '4px 12px',
                            fontSize: 12,
                            fontWeight: 500,
                            borderRadius: 'var(--radius-sm)',
                            cursor: 'pointer',
                            transition: 'all 0.15s ease',
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
      {selectedEvent && (() => {
        const op = getOperationMeta(selectedEvent.tool_name)
        const hasDlp = (selectedEvent.dlp_findings?.length || 0) > 0
        const hasInj = (selectedEvent.injection_findings?.length || 0) > 0
        const hasSem = (selectedEvent.semantic_findings?.length || 0) > 0

        return (
          <div
            style={{
              position: 'fixed',
              inset: 0,
              background: 'rgba(0, 0, 0, 0.75)',
              backdropFilter: 'blur(5px)',
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
                maxWidth: 760,
                width: '100%',
                background: '#0e131f',
                border: '1px solid var(--border-default)',
                boxShadow: '0 25px 50px rgba(0,0,0,0.6)',
                borderRadius: 'var(--radius)',
                maxHeight: '92vh',
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
              }}
              onClick={e => e.stopPropagation()}
            >
              {/* Modal Header */}
              <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'rgba(255,255,255,0.02)' }}>
                <div>
                  <h2 style={{ fontSize: 18, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 10, margin: 0 }}>
                    Security Event Inspection
                    <span className={`badge ${DECISION_CLASS[selectedEvent.decision] ?? 'badge-info'}`} style={{ fontSize: 12, padding: '3px 10px' }}>
                      {selectedEvent.decision.toUpperCase()}
                    </span>
                  </h2>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span>ID: {selectedEvent.event_id}</span>
                    <button
                      onClick={() => copyToClipboard(selectedEvent.event_id, 'event_id')}
                      style={{ background: 'transparent', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 11, padding: 0 }}
                    >
                      {copiedKey === 'event_id' ? '✓ Copied' : 'Copy'}
                    </button>
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
              <div style={{ padding: '20px 24px', overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* Key Attributes Grid */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
                  {/* Timestamp & Timing */}
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)', border: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Timestamp & Timing
                    </div>
                    <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', marginTop: 4, color: 'var(--text-primary)', fontWeight: 600 }}>
                      {formatTs(selectedEvent.timestamp_ms)}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                      {new Date(selectedEvent.timestamp_ms).toISOString()} ({formatRelativeTime(selectedEvent.timestamp_ms)})
                    </div>
                  </div>

                  {/* Agent Identity */}
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)', border: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Identity / Principal
                    </div>
                    <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', marginTop: 4, color: 'var(--text-primary)', wordBreak: 'break-all', fontWeight: 600 }}>
                      {selectedEvent.agent_id}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--success)', marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                      ✓ Authenticated Agent Identity
                    </div>
                  </div>

                  {/* Operation & Target */}
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)', border: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Channel & Operation Target
                    </div>
                    <div style={{ fontSize: 13, fontFamily: 'var(--font-mono)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 11, padding: '1px 6px', borderRadius: 3, background: op.type === 'llm' ? 'rgba(56, 189, 248, 0.2)' : 'rgba(99, 102, 241, 0.2)', color: op.type === 'llm' ? '#38bdf8' : 'var(--accent)', fontWeight: 600 }}>
                        {op.label}
                      </span>
                      <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                        {op.target}
                      </span>
                    </div>
                    {op.isUnlisted && (
                      <div style={{ fontSize: 11, color: 'var(--warning)', marginTop: 3 }}>
                        🔒 Zero-Knowledge Redacted (not in policy allowlist)
                      </div>
                    )}
                  </div>

                  {/* Session Context */}
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: 12, borderRadius: 'var(--radius-sm)', border: '1px solid rgba(255,255,255,0.04)' }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                      Session & Cryptographic Proof
                    </div>
                    <div style={{ fontSize: 12, fontFamily: 'var(--font-mono)', marginTop: 4, color: 'var(--text-primary)', wordBreak: 'break-all', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>{selectedEvent.session_id || '—'}</span>
                      {selectedEvent.session_id && (
                        <button
                          onClick={() => copyToClipboard(selectedEvent.session_id, 'session_id')}
                          style={{ background: 'transparent', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: 11, padding: 0 }}
                        >
                          {copiedKey === 'session_id' ? '✓' : 'Copy'}
                        </button>
                      )}
                    </div>
                    <div style={{ fontSize: 11, color: '#38bdf8', marginTop: 2 }}>
                      🔒 HMAC-SHA256 Tamper-Evident Ledger
                    </div>
                  </div>
                </div>

                {/* Guardrails Deep-Dive Section */}
                <div style={{ background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 16 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 12 }}>
                    Active Guardrails & Security Findings
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 12 }}>
                    {/* DLP Findings Card */}
                    <div style={{ background: hasDlp ? 'rgba(245, 158, 11, 0.08)' : 'rgba(16, 185, 129, 0.04)', border: hasDlp ? '1px solid rgba(245, 158, 11, 0.3)' : '1px solid rgba(16, 185, 129, 0.15)', borderRadius: 6, padding: 12 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: hasDlp ? 'var(--warning)' : 'var(--success)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                        {hasDlp ? '⚠️ Data Loss Prevention (DLP) Triggered' : '✓ Data Loss Prevention (DLP)'}
                      </div>
                      {!hasDlp ? (
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                          Passed — Zero secret keys, credentials, or PII tokens detected in payload.
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
                          {selectedEvent.dlp_findings.map((f, idx) => (
                            <div key={idx} style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: 4, fontSize: 12 }}>
                              <div style={{ fontWeight: 600, color: 'var(--warning)' }}>
                                {f.category} — {f.pattern_name}
                              </div>
                              <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>
                                Count: {f.count} • Action: Redacted in-flight / Blocked
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Prompt Injection Findings Card */}
                    <div style={{ background: hasInj ? 'rgba(239, 68, 68, 0.08)' : 'rgba(16, 185, 129, 0.04)', border: hasInj ? '1px solid rgba(239, 68, 68, 0.3)' : '1px solid rgba(16, 185, 129, 0.15)', borderRadius: 6, padding: 12 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: hasInj ? 'var(--danger)' : 'var(--success)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                        {hasInj ? '🚨 Prompt Injection Detected' : '✓ Prompt Injection Defense'}
                      </div>
                      {!hasInj ? (
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                          Passed — No adversarial prompt overrides, jailbreaks, or delimiter hijacks detected.
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
                          {selectedEvent.injection_findings.map((f, idx) => (
                            <div key={idx} style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: 4, fontSize: 12 }}>
                              <div style={{ fontWeight: 600, color: 'var(--danger)' }}>
                                {f.pattern_name}
                              </div>
                              <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>
                                Count: {f.count} • Action: Blocked & Neutralized
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Semantic & Anomaly Findings Card */}
                    <div style={{ background: hasSem ? 'rgba(245, 158, 11, 0.08)' : 'rgba(16, 185, 129, 0.04)', border: hasSem ? '1px solid rgba(245, 158, 11, 0.3)' : '1px solid rgba(16, 185, 129, 0.15)', borderRadius: 6, padding: 12 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: hasSem ? 'var(--warning)' : 'var(--success)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                        {hasSem ? '⚠️ Semantic Anomaly / Drift' : '✓ Semantic Baseline & Schema'}
                      </div>
                      {!hasSem ? (
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                          Passed — Operation conforms to expected semantic baseline (Anomaly Score: 0.00).
                        </div>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 4 }}>
                          {selectedEvent.semantic_findings.map((f, idx) => (
                            <div key={idx} style={{ background: 'rgba(0,0,0,0.3)', padding: '6px 10px', borderRadius: 4, fontSize: 12 }}>
                              <div style={{ fontWeight: 600, color: 'var(--warning)' }}>
                                {f.finding_type}
                              </div>
                              <div style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 2 }}>
                                Anomaly Score: {f.anomaly_score.toFixed(2)}
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>

                    {/* Policy Verdict Explanation */}
                    <div style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border)', borderRadius: 6, padding: 12 }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                        ⚖️ Policy Enforcement Verdict
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {selectedEvent.decision === 'allowed'
                          ? 'Operation permitted: Session claims authorized this action and no active DLP/injection guardrails were violated.'
                          : selectedEvent.decision === 'denied'
                          ? 'Operation denied: Blocked by active policy or security guardrail rule.'
                          : 'Operation flagged with warning or detected schema drift.'}
                      </div>
                    </div>
                  </div>
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
                      color: '#a5b4fc',
                      maxHeight: 180,
                      overflowY: 'auto',
                      lineHeight: 1.4,
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
                      Filter by this Target ({op.target})
                    </button>
                  )}
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  style={{
                    background: 'var(--accent)',
                    border: 'none',
                    color: '#fff',
                    padding: '6px 18px',
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
        )
      })()}
    </>
  )
}
