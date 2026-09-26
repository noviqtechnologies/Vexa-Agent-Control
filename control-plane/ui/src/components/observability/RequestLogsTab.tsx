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

function formatTokenNum(n: number): string {
  if (!n || n <= 0) return '0'
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return `${n}`
}

interface TokenInfo {
  total: number
  totalFormatted: string
  inputFormatted: string
  outputFormatted: string
  cachedFormatted?: string
  rawTooltip: string
}

function formatTokens(input = 0, output = 0, cached = 0): TokenInfo {
  const total = input + output
  const rawTooltip = `Total: ${total.toLocaleString()} tokens (Prompt: ${input.toLocaleString()}, Completion: ${output.toLocaleString()}${cached > 0 ? `, Cached: ${cached.toLocaleString()}` : ''})`
  return {
    total,
    totalFormatted: formatTokenNum(total),
    inputFormatted: formatTokenNum(input),
    outputFormatted: formatTokenNum(output),
    cachedFormatted: cached > 0 ? formatTokenNum(cached) : undefined,
    rawTooltip,
  }
}

function formatDuration(ms?: number): string {
  if (!ms || ms <= 0) return '0.00s'
  return `${(ms / 1000).toFixed(2)}s`
}

interface TTFTInfo {
  label: string
  isBatch: boolean
  tooltip: string
}

function formatTTFT(ms?: number): TTFTInfo {
  if (!ms || ms <= 0) {
    return {
      label: 'N/A (Batch)',
      isBatch: true,
      tooltip: 'Non-streaming batch request (TTFT is only measured for streaming responses)',
    }
  }
  return {
    label: `${(ms / 1000).toFixed(2)}s`,
    isBatch: false,
    tooltip: `Time To First Token: ${ms}ms`,
  }
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

type TypeIconKind = 'llm' | 'tool' | 'response' | 'embedding'

interface TypeBadgeInfo {
  label: string
  iconKind: TypeIconKind
  badgeClass: string
  tooltip: string
}

function RenderTypeIcon({ kind }: { kind: TypeIconKind }) {
  if (kind === 'tool') {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
        <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z" />
      </svg>
    )
  }
  if (kind === 'response') {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
        <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
      </svg>
    )
  }
  if (kind === 'embedding') {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
      </svg>
    )
  }
  // Default LLM Sparkle
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0 }}>
      <path d="m12 3-1.912 5.813a2 2 0 0 1-1.275 1.275L3 12l5.813 1.912a2 2 0 0 1 1.275 1.275L12 21l1.912-5.813a2 2 0 0 1 1.275-1.275L21 12l-5.813-1.912a2 2 0 0 1-1.275-1.275L12 3Z" />
    </svg>
  )
}

function getRequestTypeBadge(r: RunSummary, index = 0, allLogs: RunSummary[] = []): TypeBadgeInfo {
  const type = (r.request_type || '').toUpperCase()
  const tags = r.tags || {}

  if (type === 'TOOL_CALL' || type === 'TOOL' || tags.type === 'tool_call' || tags.tool_calls) {
    return {
      label: 'Tool Call',
      iconKind: 'tool',
      badgeClass: 'obs-badge-tool',
      tooltip: 'Agent action: LLM selected and invoked a tool/function call',
    }
  }

  if (type === 'RESPONSE' || type === 'SYNTHESIS' || tags.type === 'synthesis' || tags.role === 'tool_result') {
    return {
      label: 'Response',
      iconKind: 'response',
      badgeClass: 'obs-badge-response',
      tooltip: 'Agent answer: LLM synthesized final response from tool execution outputs',
    }
  }

  if (type === 'EMBEDDING' || type === 'EMBEDDINGS') {
    return {
      label: 'Embedding',
      iconKind: 'embedding',
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
        iconKind: (r.output_tokens || 0) < 60 ? 'tool' : 'llm',
        badgeClass: (r.output_tokens || 0) < 60 ? 'obs-badge-tool' : 'obs-badge-type',
        tooltip: `Agent Step 1: Tool invocation / prompt processing (${r.output_tokens || 0} completion tokens)`,
      }
    }

    if (isPrecededByCorrelated) {
      return {
        label: 'Response',
        iconKind: 'response',
        badgeClass: 'obs-badge-response',
        tooltip: `Agent Step 2: Synthesis after tool execution (${r.input_tokens || 0} context tokens)`,
      }
    }
  }

  return {
    label: r.request_type || 'LLM',
    iconKind: 'llm',
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
  const [downloading, setDownloading] = useState(false)
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

  const downloadExcel = () => {
    if (logs.length === 0) return
    setDownloading(true)
    try {
      const headers = [
        'Time (ISO)',
        'Time (Local)',
        'Type',
        'Status',
        'Session ID',
        'Request ID',
        'Cost (USD)',
        'Duration (s)',
        'TTFT (s)',
        'Team',
        'Key Prefix',
        'Key Alias',
        'Model',
        'Provider',
        'Total Tokens',
        'Input Tokens',
        'Output Tokens',
        'Cached Tokens',
        'User',
        'Host',
        'Device ID',
      ]

      const rows = logs.map((r, index) => {
        const isDenied = r.state === 'DENIED' || r.state === 'BLOCKED' || (r.status_code === 403 || r.status_code === 429)
        const isReleased = r.state === 'RELEASED'
        const isFailed = r.state === 'FAILED' || r.state === 'ERROR' || (r.status_code !== undefined && r.status_code >= 400 && !isDenied) || (isReleased && (r.status_code === undefined || r.status_code >= 400))
        const isSuccess = r.state === 'SETTLED' && (r.status_code === undefined || (r.status_code >= 200 && r.status_code < 300))
        const isAuthorized = r.state === 'AUTHORIZED'

        let status = r.state || 'Unknown'
        if (isDenied) status = 'Denied'
        else if (isFailed) status = 'Failure'
        else if (isSuccess) status = 'Success'
        else if (isAuthorized) status = 'Authorized'
        else if (isReleased) status = 'Released'

        const billedMicrocents = r.state === 'SETTLED' ? (r.settled_microcents || 0) : 0
        const costUSD = microcentsToUSD(billedMicrocents)
        const typeBadge = getRequestTypeBadge(r, index, logs)
        const durationSec = r.duration_ms ? (r.duration_ms / 1000).toFixed(2) : '0.00'
        const ttftInfo = formatTTFT(r.ttft_ms)
        const totalTokens = (r.input_tokens || 0) + (r.output_tokens || 0)

        const isHostUUID = r.device_name ? /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(r.device_name.trim()) : true
        const validHostName = r.device_name && !isHostUUID ? r.device_name : null

        return [
          r.started_at,
          formatTimestamp(r.started_at),
          typeBadge.label,
          status,
          r.session_id || 'N/A',
          r.request_id || '',
          costUSD,
          durationSec,
          ttftInfo.isBatch ? 'N/A (Batch)' : ttftInfo.label,
          r.project_id || 'default',
          r.virtual_key_prefix || 'Direct / Gateway',
          r.virtual_key_alias || '',
          r.model || '',
          r.provider || '',
          totalTokens,
          r.input_tokens || 0,
          r.output_tokens || 0,
          r.cached_tokens || 0,
          r.internal_user_id || r.end_user_id || (r.virtual_key_alias ? `Key: ${r.virtual_key_alias}` : 'N/A'),
          validHostName || 'N/A',
          r.device_id || '',
        ]
      })

      // RFC 4180 CSV with UTF-8 BOM (\uFEFF) for immediate Excel opening
      const csv = '\uFEFF' + [headers, ...rows]
        .map(row => row.map(val => `"${String(val ?? '').replace(/"/g, '""')}"`).join(','))
        .join('\r\n')

      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' })
      if (typeof window !== 'undefined' && window.URL && typeof window.URL.createObjectURL === 'function') {
        const url = window.URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        const d = new Date()
        const dateStr = d.toISOString().split('T')[0]
        a.download = `agentwall-request-logs-${dateStr}.csv`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        window.URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Failed to export Excel CSV:', err)
    } finally {
      setDownloading(false)
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

          {/* Export Excel Button */}
          <button
            type="button"
            className="obs-btn-secondary obs-export-btn"
            onClick={downloadExcel}
            disabled={downloading || logs.length === 0}
            title="Download Request Logs in Excel CSV format"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
              <polyline points="7 10 12 15 17 10" />
              <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            {downloading ? 'Exporting…' : 'Export Excel'}
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
                <th>Team</th>
                <th>Key</th>
                <th>Model</th>
                <th>Tokens</th>
                <th>User</th>
                <th>Host</th>
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
                const billedMicrocents = r.state === 'SETTLED' ? (r.settled_microcents || 0) : 0
                const costUSD = microcentsToUSD(billedMicrocents)
                const typeBadge = getRequestTypeBadge(r, index, logs)
                const tokenInfo = formatTokens(r.input_tokens, r.output_tokens, r.cached_tokens)

                const isHostUUID = r.device_name ? /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(r.device_name.trim()) : true
                const validHostName = r.device_name && !isHostUUID ? r.device_name : null

                return (
                  <tr
                    key={r.run_id || r.request_id}
                    className="obs-table-row clickable"
                    onClick={() => openDossier(r.run_id)}
                  >
                    <td className="obs-col-time">{formatTimestamp(r.started_at)}</td>
                    <td>
                      <span className={`obs-badge ${typeBadge.badgeClass}`} title={typeBadge.tooltip}>
                        <RenderTypeIcon kind={typeBadge.iconKind} />
                        <span>{typeBadge.label}</span>
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
                        <span className="obs-session-na" title="Session ID was not provided in request headers">
                          N/A
                        </span>
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
                    <td>
                      {r.project_id && r.project_id.trim() !== '' && r.project_id !== 'default' ? (
                        <span className="obs-team-pill" title={`Team: ${r.project_id}`}>
                          {r.project_id}
                        </span>
                      ) : (
                        <span className="obs-team-na-pill" title="No team assigned">
                          N/A
                        </span>
                      )}
                    </td>
                    <td>
                      {r.virtual_key_prefix ? (
                        <span className="obs-key-pill" title={`Virtual Key: ${r.virtual_key_alias || r.virtual_key_prefix}`}>
                          🔑 {r.virtual_key_alias || r.virtual_key_prefix}
                        </span>
                      ) : (
                        <span className="obs-key-direct-pill" title="Direct Gateway proxy credentials (No virtual key alias attached)">
                          Direct
                        </span>
                      )}
                    </td>
                    <td>
                      <span className="obs-model-name" title={`${r.provider} / ${r.model}`}>
                        {r.model}
                      </span>
                    </td>
                    <td className="obs-col-tokens" title={tokenInfo.rawTooltip}>
                      <div className="obs-tokens-compact">
                        <span className="obs-tokens-total">{tokenInfo.totalFormatted}</span>
                        <span className="obs-tokens-split" title={`Prompt: ${(r.input_tokens || 0).toLocaleString()} · Completion: ${(r.output_tokens || 0).toLocaleString()}`}>
                          <span className="obs-token-in">↑{tokenInfo.inputFormatted}</span>
                          <span className="obs-token-out">↓{tokenInfo.outputFormatted}</span>
                        </span>
                        {tokenInfo.cachedFormatted && (
                          <span className="obs-cached-token-pill" title={`Prompt cache hit: ${(r.cached_tokens || 0).toLocaleString()} tokens`}>
                            ⚡ {tokenInfo.cachedFormatted}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="obs-col-user">
                      {r.internal_user_id || r.end_user_id ? (
                        <span className="obs-user-primary" title={`User: ${r.internal_user_id || r.end_user_id}`}>
                          {r.internal_user_id || r.end_user_id}
                        </span>
                      ) : r.virtual_key_alias ? (
                        <span className="obs-user-key-sub" title={`Virtual Key Alias: ${r.virtual_key_alias}`}>
                          🔑 {r.virtual_key_alias}
                        </span>
                      ) : (
                        <span className="obs-not-available" title="No user identity tagged on this request">
                          N/A
                        </span>
                      )}
                    </td>
                    <td className="obs-col-host">
                      {validHostName ? (
                        <span className="obs-user-host-badge" title={`Host identifier: ${validHostName}`}>
                          💻 {validHostName}
                        </span>
                      ) : (
                        <span className="obs-not-available" title="No device hostname tagged on this request">
                          N/A
                        </span>
                      )}
                    </td>
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
