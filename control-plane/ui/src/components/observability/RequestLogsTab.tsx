import { useState, useEffect, useRef } from 'react'
import { api, type RunSummary, type RunDossier } from '../../api/client'
import RunDossierDrawer from '../../views/RunDossierDrawer'
import SessionTraceDrawer from './SessionTraceDrawer'

function microcentsToUSD(microcents?: number): string {
  if (microcents === undefined || microcents === null || microcents === 0) return '$0.00'
  const dollars = microcents / 100_000_000
  if (dollars < 0.0001) return `<$0.0001`
  return `$${dollars.toFixed(4)}`
}

function formatTokens(input = 0, output = 0): string {
  const total = input + output
  if (total === 0) return '0 (0+0)'
  return `${total.toLocaleString()} (${input.toLocaleString()}+${output.toLocaleString()})`
}

function formatDuration(ms?: number): string {
  if (!ms || ms <= 0) return '0.00s'
  return `${(ms / 1000).toFixed(2)}s`
}

function formatTTFT(ms?: number): string {
  if (!ms || ms <= 0) return '-'
  return `${(ms / 1000).toFixed(2)}s`
}

function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString)
    return d.toLocaleString([], {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    })
  } catch {
    return isoString
  }
}

interface TypeBadgeInfo {
  label: string
  icon: string
  badgeClass: string
  tooltip: string
}

function getRequestTypeBadge(r: RunSummary, index = 0, allLogs: RunSummary[] = []): TypeBadgeInfo {
  const type = (r.request_type || '').toUpperCase()
  const tags = r.tags || {}

  if (type === 'TOOL_CALL' || type === 'TOOL' || tags.type === 'tool_call' || tags.tool_calls) {
    return {
      label: 'Tool Call',
      icon: '🛠️',
      badgeClass: 'obs-badge-tool',
      tooltip: 'Agent action: LLM selected and invoked a tool/function call',
    }
  }

  if (type === 'RESPONSE' || type === 'SYNTHESIS' || tags.type === 'synthesis' || tags.role === 'tool_result') {
    return {
      label: 'Response',
      icon: '💬',
      badgeClass: 'obs-badge-response',
      tooltip: 'Agent answer: LLM synthesized final response from tool execution outputs',
    }
  }

  if (type === 'EMBEDDING' || type === 'EMBEDDINGS') {
    return {
      label: 'Embedding',
      icon: '⚡',
      badgeClass: 'obs-badge-embedding',
      tooltip: 'Vector text embedding generation',
    }
  }

  // Smart heuristic for consecutive agent loop steps when request_type is 'LLM':
  if (allLogs.length > 1) {
    const currentTime = new Date(r.started_at).getTime()
    const prevLog = index + 1 < allLogs.length ? allLogs[index + 1] : null // earlier chronological log
    const nextLog = index - 1 >= 0 ? allLogs[index - 1] : null // later chronological log

    const isCorrelatedWith = (other: RunSummary | null) => {
      if (!other) return false
      const otherTime = new Date(other.started_at).getTime()
      if (isNaN(currentTime) || isNaN(otherTime)) return false
      const diffSec = Math.abs(currentTime - otherTime) / 1000
      if (r.session_id && other.session_id && r.session_id === other.session_id) return true
      return diffSec <= 30 && r.model === other.model && (r.project_id === other.project_id || (!r.project_id && !other.project_id))
    }

    const isPrecededByCorrelated = isCorrelatedWith(prevLog)
    const isFollowedByCorrelated = isCorrelatedWith(nextLog)

    if (isFollowedByCorrelated && !isPrecededByCorrelated) {
      return {
        label: (r.output_tokens || 0) < 60 ? 'Tool Call' : 'Agent Step 1',
        icon: (r.output_tokens || 0) < 60 ? '🛠️' : '✦',
        badgeClass: (r.output_tokens || 0) < 60 ? 'obs-badge-tool' : 'obs-badge-type',
        tooltip: `Agent Step 1: Tool invocation / prompt processing (${r.output_tokens || 0} completion tokens)`,
      }
    }

    if (isPrecededByCorrelated) {
      return {
        label: 'Response',
        icon: '💬',
        badgeClass: 'obs-badge-response',
        tooltip: `Agent Step 2: Synthesis after tool execution (${r.input_tokens || 0} context tokens)`,
      }
    }
  }

  return {
    label: r.request_type || 'LLM',
    icon: '✦',
    badgeClass: 'obs-badge-type',
    tooltip: 'Standard LLM generation / single completion request',
  }
}

export default function RequestLogsTab() {
  const [logs, setLogs] = useState<RunSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedDossier, setSelectedDossier] = useState<RunDossier | null>(null)
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null)

  // Filters
  const [search, setSearch] = useState('')
  const [debouncedSearch, setDebouncedSearch] = useState('')
  const [hours, setHours] = useState(24)
  const [statusFilter, setStatusFilter] = useState('all')
  const [modelFilter, setModelFilter] = useState('')
  const [debouncedModel, setDebouncedModel] = useState('')
  const [providerFilter, setProviderFilter] = useState('')
  const [isFilterModalOpen, setIsFilterModalOpen] = useState(false)

  // Live tail & auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [liveTail, setLiveTail] = useState(false)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const autoRefreshTimerRef = useRef<number | null>(null)
  const liveTailRef = useRef<EventSource | null>(null)

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search)
    }, 300)
    return () => clearTimeout(timer)
  }, [search])

  // Debounce model input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedModel(modelFilter)
    }, 300)
    return () => clearTimeout(timer)
  }, [modelFilter])

  useEffect(() => {
    loadLogs()
  }, [hours, statusFilter, debouncedModel, providerFilter, debouncedSearch])

  useEffect(() => {
    if (autoRefresh && !liveTail) {
      autoRefreshTimerRef.current = window.setInterval(() => {
        loadLogs(false)
      }, 15000)
    }
    return () => {
      if (autoRefreshTimerRef.current) clearInterval(autoRefreshTimerRef.current)
    }
  }, [autoRefresh, liveTail, hours, statusFilter, debouncedModel, providerFilter, debouncedSearch])

  // Live tail SSE
  useEffect(() => {
    if (liveTail) {
      const es = new EventSource('/api/v1/observability/request-logs/stream')
      liveTailRef.current = es
      es.addEventListener('logs', (e) => {
        try {
          const newRuns = JSON.parse(e.data) as RunSummary[]
          if (Array.isArray(newRuns) && newRuns.length > 0) {
            setLogs((prev) => {
              const existingIds = new Set(prev.map((r) => r.run_id))
              const uniqueNew = newRuns.filter((r) => !existingIds.has(r.run_id))
              return [...uniqueNew, ...prev].slice(0, 100)
            })
          }
        } catch (err) {
          console.error('Failed to parse live tail:', err)
        }
      })
      return () => {
        es.close()
      }
    }
  }, [liveTail])

  const loadLogs = async (showLoading = true, overrideParams?: { search?: string; status?: string; model?: string; provider?: string; hours?: number }) => {
    if (showLoading) setLoading(true)
    setError(null)
    const effectiveHours = overrideParams?.hours !== undefined ? overrideParams.hours : hours
    const effectiveStatus = overrideParams?.status !== undefined ? overrideParams.status : statusFilter
    const effectiveModel = overrideParams?.model !== undefined ? overrideParams.model : debouncedModel
    const effectiveProvider = overrideParams?.provider !== undefined ? overrideParams.provider : providerFilter
    const effectiveSearch = overrideParams?.search !== undefined ? overrideParams.search : debouncedSearch

    try {
      const res = await api.listRequestLogs({
        hours: effectiveHours,
        limit: 50,
        status: effectiveStatus !== 'all' ? effectiveStatus : undefined,
        model: effectiveModel || undefined,
        provider: effectiveProvider || undefined,
        search: effectiveSearch || undefined,
      })
      setLogs(res.request_logs || [])
    } catch (err: any) {
      setError(err.message || 'Failed to load request logs')
    } finally {
      if (showLoading) setLoading(false)
    }
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setDebouncedSearch(search)
    loadLogs(true, { search })
  }

  const resetFilters = () => {
    setSearch('')
    setDebouncedSearch('')
    setHours(24)
    setStatusFilter('all')
    setModelFilter('')
    setDebouncedModel('')
    setProviderFilter('')
    loadLogs(true, { search: '', status: 'all', model: '', provider: '', hours: 24 })
  }

  const copyToClipboard = (text: string, key: string, e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const openDossier = async (runId: string) => {
    try {
      const d = await api.getRunDossier(runId)
      setSelectedDossier(d)
    } catch (err) {
      console.error('Failed to open dossier:', err)
    }
  }

  return (
    <div className="obs-request-logs-tab">
      {/* Auto-refresh indicator banner */}
      <div className="obs-refresh-banner">
        <div className="obs-refresh-left">
          <span className={`obs-pulse-dot ${autoRefresh || liveTail ? 'active' : ''}`} />
          <span>
            {liveTail
              ? 'Live Tail active — streaming real-time gateway requests'
              : autoRefresh
              ? 'Auto-refreshing every 15 seconds'
              : 'Auto-refresh paused'}
          </span>
        </div>
        <button
          type="button"
          className="obs-refresh-toggle-btn"
          onClick={() => {
            if (liveTail) setLiveTail(false)
            setAutoRefresh(!autoRefresh)
          }}
        >
          {autoRefresh ? 'Stop' : 'Resume'}
        </button>
      </div>

      {/* Agentic Observability Tip Banner */}
      <div className="obs-agentic-tip">
        <span className="obs-tip-icon">💡</span>
        <div className="obs-tip-text">
          <strong>Agent Observability Notice:</strong> Autonomous coding agents (such as Roo Code, Cline, and Cursor) execute multi-step ReAct loops. A single user prompt often triggers multiple sequential requests (e.g. tool execution + result synthesis). Each step is logged individually for exact token and cost accounting.
        </div>
      </div>

      {/* Filter toolbar */}
      <div className="obs-filter-toolbar">
        <form onSubmit={handleSearchSubmit} className="obs-search-box">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            placeholder="Search by Request ID, Session ID, Key Hash, or Model..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button type="button" className="obs-clear-search" onClick={() => { setSearch(''); loadLogs() }}>
              ×
            </button>
          )}
        </form>

        <div className="obs-toolbar-controls">
          {/* Time window toggle */}
          <select
            className="obs-select"
            value={hours}
            onChange={(e) => setHours(Number(e.target.value))}
            aria-label="Time Window"
          >
            <option value={1}>Last 1 Hour</option>
            <option value={24}>Last 24 Hours</option>
            <option value={168}>Last 7 Days</option>
            <option value={720}>Last 30 Days</option>
          </select>

          {/* Live tail toggle */}
          <label className="obs-live-tail-label">
            <span>Live Tail</span>
            <input
              type="checkbox"
              className="obs-switch-input"
              checked={liveTail}
              onChange={(e) => {
                setLiveTail(e.target.checked)
                if (e.target.checked) setAutoRefresh(false)
              }}
            />
            <span className="obs-switch-slider" />
          </label>

          {/* Reset Filters */}
          <button type="button" className="obs-btn-secondary" onClick={resetFilters}>
            Reset Filters
          </button>

          {/* Refresh Button */}
          <button
            type="button"
            className="obs-btn-icon"
            onClick={() => loadLogs()}
            title="Refresh logs"
            disabled={loading}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={loading ? 'obs-spin' : ''}>
              <path d="M23 4v6h-6M1 20v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
          </button>

          {/* Filters modal toggle */}
          <button
            type="button"
            className={`obs-btn-secondary ${statusFilter !== 'all' || modelFilter || providerFilter ? 'active-filter' : ''}`}
            onClick={() => setIsFilterModalOpen(!isFilterModalOpen)}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polygon points="22 3 2 3 10 12.46 10 19 14 21 14 12.46 22 3" />
            </svg>
            Filters
          </button>
        </div>
      </div>

      {/* Advanced Filter Popover */}
      {isFilterModalOpen && (
        <div className="obs-filter-popover">
          <div className="obs-filter-row">
            <label>Status:</label>
            <select
              id="request-logs-status-filter"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              aria-label="Status Filter"
            >
              <option value="all">All Statuses</option>
              <option value="SUCCESS">Success (Settled)</option>
              <option value="FAILURE">Failure (Errors & Blocks)</option>
              <option value="DENIED">Denied / Blocked</option>
              <option value="AUTHORIZED">Authorized (In-flight)</option>
              <option value="RELEASED">Released</option>
            </select>
          </div>
          <div className="obs-filter-row">
            <label>Provider:</label>
            <select
              id="request-logs-provider-filter"
              value={providerFilter}
              onChange={(e) => setProviderFilter(e.target.value)}
              aria-label="Provider Filter"
            >
              <option value="">All Providers</option>
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="google">Google Gemini</option>
              <option value="azure">Azure OpenAI</option>
              <option value="ollama">Ollama / Local</option>
            </select>
          </div>
          <div className="obs-filter-row">
            <label>Model contains:</label>
            <input
              id="request-logs-model-filter"
              type="text"
              placeholder="e.g. gpt-4o, claude"
              value={modelFilter}
              onChange={(e) => setModelFilter(e.target.value)}
            />
          </div>
        </div>
      )}

      {/* Request Logs Table */}
      <div className="obs-table-container">
        {loading && logs.length === 0 ? (
          <div className="obs-empty-state">
            <div className="obs-spinner" />
            <p>Loading request logs...</p>
          </div>
        ) : error ? (
          <div className="obs-error-state">
            <p className="obs-error-msg">{error}</p>
            <button className="obs-btn-secondary" onClick={() => loadLogs()}>Retry</button>
          </div>
        ) : logs.length === 0 ? (
          <div className="obs-empty-state">
            <div className="obs-empty-icon">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="2" y="3" width="20" height="14" rx="2" />
                <line x1="8" y1="21" x2="16" y2="21" />
                <line x1="12" y1="17" x2="12" y2="21" />
              </svg>
            </div>
            <h3>No request logs found</h3>
            <p>No LLM traffic recorded in this timeframe. Send requests via the gateway proxy to view live telemetry.</p>
          </div>
        ) : (
          <table className="obs-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Status</th>
                <th>Session ID</th>
                <th>Request ID</th>
                <th>Cost</th>
                <th>Duration (s)</th>
                <th>TTFT (s)</th>
                <th>Team</th>
                <th>Key Prefix</th>
                <th>Model</th>
                <th>Tokens</th>
                <th>User</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((r, index) => {
                const isDenied = r.state === 'DENIED' || r.state === 'BLOCKED' || (r.status_code === 403 || r.status_code === 429)
                const isReleased = r.state === 'RELEASED'
                const isFailed = r.state === 'FAILED' || r.state === 'ERROR' || (r.status_code !== undefined && r.status_code >= 400 && !isDenied) || (isReleased && (r.status_code === undefined || r.status_code >= 400))
                const isSuccess = r.state === 'SETTLED' && (r.status_code === undefined || (r.status_code >= 200 && r.status_code < 300))
                const isAuthorized = r.state === 'AUTHORIZED'

                let badgeClass = 'obs-badge-warning'
                let badgeLabel = r.state || 'Unknown'

                if (isDenied) {
                  badgeClass = 'obs-badge-danger'
                  badgeLabel = 'Denied'
                } else if (isFailed) {
                  badgeClass = 'obs-badge-danger'
                  badgeLabel = 'Failure'
                } else if (isSuccess) {
                  badgeClass = 'obs-badge-success'
                  badgeLabel = 'Success'
                } else if (isAuthorized) {
                  badgeClass = 'obs-badge-info'
                  badgeLabel = 'Authorized'
                } else if (isReleased) {
                  badgeClass = 'obs-badge-warning'
                  badgeLabel = 'Released'
                }

                // Billed cost: Only SETTLED runs incur actual spend.
                // RELEASED, FAILED, DENIED, or in-flight AUTHORIZED runs have $0.00 settled spend.
                const billedMicrocents = r.state === 'SETTLED' ? (r.settled_microcents || 0) : 0
                const costUSD = microcentsToUSD(billedMicrocents)
                const typeBadge = getRequestTypeBadge(r, index, logs)

                return (
                  <tr
                    key={r.run_id || r.request_id}
                    className="obs-table-row clickable"
                    onClick={() => openDossier(r.run_id)}
                  >
                    <td className="obs-col-time">{formatTimestamp(r.started_at)}</td>
                    <td>
                      <span className={`obs-badge ${typeBadge.badgeClass}`} title={typeBadge.tooltip}>
                        <span className="obs-type-sparkle">{typeBadge.icon}</span> {typeBadge.label}
                      </span>
                    </td>
                    <td>
                      <span className={`obs-badge ${badgeClass}`}>
                        {badgeLabel}
                      </span>
                    </td>
                    <td className="obs-col-mono">
                      {r.session_id ? (
                        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                          <button
                            type="button"
                            className="obs-copy-id-btn"
                            onClick={(e) => {
                              e.stopPropagation()
                              setSelectedSessionId(r.session_id!)
                            }}
                            title={`View Session Trace: ${r.session_id}`}
                            style={{ color: '#38bdf8' }}
                          >
                            🧭 {r.session_id.slice(0, 8)}...
                          </button>
                          <button
                            type="button"
                            className="obs-copy-id-btn"
                            onClick={(e) => copyToClipboard(r.session_id!, `sess-${r.session_id}`, e)}
                            title={`Copy Session ID`}
                          >
                            {copiedKey === `sess-${r.session_id}` ? <span className="obs-copied-tag">✓</span> : '📋'}
                          </button>
                        </div>
                      ) : (
                        <span className="obs-muted">-</span>
                      )}
                    </td>
                    <td className="obs-col-mono">
                      <button
                        type="button"
                        className="obs-copy-id-btn"
                        onClick={(e) => copyToClipboard(r.request_id, `req-${r.request_id}`, e)}
                        title={`Click to copy: ${r.request_id}`}
                      >
                        {r.request_id.slice(0, 10)}...
                        {copiedKey === `req-${r.request_id}` && <span className="obs-copied-tag">✓</span>}
                      </button>
                    </td>
                    <td className="obs-col-cost">{costUSD}</td>
                    <td>{formatDuration(r.duration_ms)}</td>
                    <td>{formatTTFT(r.ttft_ms)}</td>
                    <td>{r.project_id || 'default'}</td>
                    <td>
                      {r.virtual_key_prefix ? (
                        <span className="obs-key-pill">{r.virtual_key_prefix}</span>
                      ) : (
                        <span className="obs-muted">-</span>
                      )}
                    </td>
                    <td>
                      <span className="obs-model-name" title={`${r.provider} / ${r.model}`}>
                        {r.model}
                      </span>
                    </td>
                    <td className="obs-col-tokens">
                      {formatTokens(r.input_tokens, r.output_tokens)}
                    </td>
                    <td>{r.internal_user_id || r.end_user_id || '-'}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Pagination Footer */}
      <div className="obs-pagination-footer">
        <div className="obs-rows-per-page">
          <span>Rows per page: 50</span>
        </div>
        <div className="obs-page-summary">
          Showing 1 - {logs.length} of {logs.length}
        </div>
      </div>

      {/* Forensic Drawer */}
      {selectedDossier && (
        <RunDossierDrawer
          dossier={selectedDossier}
          onClose={() => setSelectedDossier(null)}
        />
      )}

      {/* Session Trace Drawer */}
      {selectedSessionId && (
        <SessionTraceDrawer
          sessionId={selectedSessionId}
          onClose={() => setSelectedSessionId(null)}
          onOpenRunDossier={(runId) => openDossier(runId)}
        />
      )}
    </div>
  )
}
