import { useEffect, useState } from 'react'
import { api, type SessionTraceResponse } from '../../api/client'

interface Props {
  sessionId: string
  onClose: () => void
  onOpenRunDossier?: (runId: string) => void
}

function microcentsToUSD(m: number): number {
  return m / 100_000_000
}

export default function SessionTraceDrawer({ sessionId, onClose, onOpenRunDossier }: Props) {
  const [data, setData] = useState<SessionTraceResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState<'all' | 'llm' | 'tools' | 'interventions'>('all')

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    api.getSessionTrace(sessionId)
      .then((res) => {
        if (!cancelled) setData(res)
      })
      .catch((err) => {
        if (!cancelled) setError(err.message || 'Failed to load session trajectory')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [sessionId])

  const filteredTimeline = (data?.timeline || []).filter((item) => {
    if (filter === 'all') return true
    if (filter === 'llm') return item.type === 'llm_completion'
    if (filter === 'tools') return item.type === 'tool_call'
    if (filter === 'interventions') {
      if (item.type === 'llm_completion') {
        const s = item.llm_run?.state?.toUpperCase()
        return s === 'DENIED' || s === 'BLOCKED'
      }
      if (item.type === 'tool_call') {
        const d = item.tool_event?.decision?.toLowerCase()
        return d === 'deny' || d === 'denied' || d === 'warn' || d === 'redact' ||
          (item.tool_event?.dlp_findings && Object.keys(item.tool_event.dlp_findings).length > 0) ||
          (item.tool_event?.injection_findings && Object.keys(item.tool_event.injection_findings).length > 0)
      }
    }
    return true
  })

  const summary = data?.summary

  return (
    <div className="dossier-overlay" onClick={onClose}>
      <div
        className="dossier-drawer"
        style={{ width: 'min(780px, 94vw)' }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label={`Session Forensics: ${sessionId}`}
      >
        {/* Header */}
        <div className="dossier-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 18 }}>🧭</span>
              <h2 style={{ fontSize: 16, margin: 0, fontWeight: 600 }}>Multi-Turn Session Forensics</h2>
              <span className="badge blue" style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                {sessionId.slice(0, 14)}...
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
              Chronological trajectory of reasoning prompts, completions, and intercepted MCP tool calls.
            </div>
          </div>
          <button
            type="button"
            className="soc-btn-secondary"
            style={{ fontSize: 16, padding: '4px 8px' }}
            onClick={onClose}
            aria-label="Close Session Drawer"
          >
            ✕
          </button>
        </div>

        {loading ? (
          <div className="loading" style={{ height: 300, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            Reconstructing agent trajectory...
          </div>
        ) : error ? (
          <div style={{ padding: 24, color: 'var(--danger)' }}>
            <strong>Failed to load session trace:</strong> {error}
          </div>
        ) : (
          <div className="drawer-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* 4-KPI Session Rollup */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
              <div style={{ padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>LLM TURNS</div>
                <div style={{ fontSize: 18, color: '#38bdf8', fontWeight: 700, marginTop: 4 }}>
                  {summary?.total_llm_calls || 0}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  {((summary?.total_tokens || 0)).toLocaleString()} tokens
                </div>
              </div>

              <div style={{ padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>MCP TOOLS CALLED</div>
                <div style={{ fontSize: 18, color: '#a78bfa', fontWeight: 700, marginTop: 4 }}>
                  {summary?.total_tool_calls || 0}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  Across active servers
                </div>
              </div>

              <div style={{ padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>BILLED SPEND</div>
                <div style={{ fontSize: 18, color: '#10b981', fontWeight: 700, marginTop: 4 }}>
                  ${microcentsToUSD(summary?.total_settled_microcents || 0).toFixed(4)}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  {summary?.total_cached_tokens ? `${summary.total_cached_tokens.toLocaleString()} cached` : '0 cached tokens'}
                </div>
              </div>

              <div style={{ padding: 12, background: (summary?.policy_interventions_count || 0) > 0 ? 'rgba(239, 68, 68, 0.08)' : 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid ' + ((summary?.policy_interventions_count || 0) > 0 ? 'rgba(239, 68, 68, 0.3)' : 'var(--border)') }}>
                <div style={{ fontSize: 10, color: (summary?.policy_interventions_count || 0) > 0 ? '#ef4444' : 'var(--text-muted)', fontWeight: 600 }}>
                  INTERVENTIONS
                </div>
                <div style={{ fontSize: 18, color: (summary?.policy_interventions_count || 0) > 0 ? '#ef4444' : 'var(--text-muted)', fontWeight: 700, marginTop: 4 }}>
                  {summary?.policy_interventions_count || 0}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                  {((summary?.duration_ms || 0) / 1000).toFixed(1)}s wall clock
                </div>
              </div>
            </div>

            {/* Filter Chips */}
            <div style={{ display: 'flex', gap: 8, borderBottom: '1px solid var(--border)', paddingBottom: 10 }}>
              <button
                type="button"
                className={`soc-time-btn ${filter === 'all' ? 'active' : ''}`}
                onClick={() => setFilter('all')}
              >
                All Steps ({data?.timeline.length || 0})
              </button>
              <button
                type="button"
                className={`soc-time-btn ${filter === 'llm' ? 'active' : ''}`}
                onClick={() => setFilter('llm')}
              >
                🤖 LLM Completions ({summary?.total_llm_calls || 0})
              </button>
              <button
                type="button"
                className={`soc-time-btn ${filter === 'tools' ? 'active' : ''}`}
                onClick={() => setFilter('tools')}
              >
                🛡️ MCP Tools ({summary?.total_tool_calls || 0})
              </button>
              <button
                type="button"
                className={`soc-time-btn ${filter === 'interventions' ? 'active' : ''}`}
                onClick={() => setFilter('interventions')}
              >
                🚨 Interventions ({summary?.policy_interventions_count || 0})
              </button>
            </div>

            {/* Timeline Stream */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12, paddingBottom: 24 }}>
              {filteredTimeline.length === 0 ? (
                <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
                  No session events matching this filter.
                </div>
              ) : (
                filteredTimeline.map((item, idx) => {
                  const isLLM = item.type === 'llm_completion'
                  return (
                    <div
                      key={idx}
                      style={{
                        padding: 12,
                        borderRadius: 6,
                        background: isLLM ? 'rgba(56, 189, 248, 0.03)' : 'rgba(167, 139, 250, 0.03)',
                        border: '1px solid ' + (isLLM ? 'rgba(56, 189, 248, 0.2)' : 'rgba(167, 139, 250, 0.2)'),
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 8,
                      }}
                    >
                      {/* Step Header */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontSize: 14 }}>{isLLM ? '🤖' : '🛡️'}</span>
                          <strong style={{ fontSize: 13, color: isLLM ? '#38bdf8' : '#a78bfa' }}>
                            {isLLM ? `LLM Request (${item.llm_run?.provider?.toUpperCase()} / ${item.llm_run?.model})` : `MCP Tool Call: ${item.tool_event?.tool_name}`}
                          </strong>
                          {isLLM ? (
                            <span className={`badge-state state-${item.llm_run?.state?.toLowerCase()}`}>
                              {item.llm_run?.state}
                            </span>
                          ) : (
                            <span className={`badge ${item.tool_event?.decision === 'deny' ? 'red' : item.tool_event?.decision === 'warn' ? 'amber' : 'green'}`}>
                              {item.tool_event?.decision?.toUpperCase() || 'ALLOWED'}
                            </span>
                          )}
                        </div>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          {new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </span>
                      </div>

                      {/* Step Details */}
                      {isLLM && item.llm_run ? (
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, fontSize: 12, color: 'var(--text-muted)' }}>
                          <span>Cost: <strong style={{ color: '#10b981' }}>${microcentsToUSD(item.llm_run.settled_microcents).toFixed(4)}</strong></span>
                          <span>Tokens: <strong>{item.llm_run.input_tokens || 0} in / {item.llm_run.output_tokens || 0} out</strong></span>
                          {item.llm_run.cached_tokens ? (
                            <span style={{ color: '#38bdf8' }}>Cached: {item.llm_run.cached_tokens}</span>
                          ) : null}
                          <span>Latency: <strong>{item.llm_run.duration_ms} ms</strong></span>
                          {item.llm_run.ttft_ms ? <span>TTFT: {item.llm_run.ttft_ms} ms</span> : null}
                          {onOpenRunDossier && (
                            <button
                              type="button"
                              className="soc-btn-secondary"
                              style={{ fontSize: 11, padding: '2px 8px', marginLeft: 'auto' }}
                              onClick={() => onOpenRunDossier(item.llm_run!.run_id)}
                            >
                              Inspect Dossier →
                            </button>
                          )}
                        </div>
                      ) : item.tool_event ? (
                        <div style={{ fontSize: 12 }}>
                          <div style={{ color: 'var(--text-muted)', marginBottom: 4 }}>
                            Agent: <code style={{ color: 'var(--accent)' }}>{item.tool_event.agent_id}</code> · Event ID: <code>{item.tool_event.event_id}</code>
                          </div>
                          {(item.tool_event.dlp_findings || item.tool_event.injection_findings) && (
                            <div style={{ padding: '6px 10px', background: 'rgba(239,68,68,0.1)', borderRadius: 4, color: '#fca5a5', marginTop: 4 }}>
                              🚨 Policy finding intercepted on arguments
                            </div>
                          )}
                        </div>
                      ) : null}
                    </div>
                  )
                })
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
