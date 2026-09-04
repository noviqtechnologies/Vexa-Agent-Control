import { useState, useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, type RunSummary, type RunDossier } from '../api/client'
import RunDossierDrawer from './RunDossierDrawer'
import SessionTraceDrawer from '../components/observability/SessionTraceDrawer'
import VirtualKeyQuickView from '../components/observability/VirtualKeyQuickView'
import './RunExplorer.css'

function microcentsToUSD(microcents: number): number {
  return (microcents || 0) / 100_000_000
}

export default function RunExplorer() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [runs, setRuns] = useState<RunSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [selectedDossier, setSelectedDossier] = useState<RunDossier | null>(null)
  const [dataFreshness, setDataFreshness] = useState<string>('')
  const [confidence, setConfidence] = useState<string>('observed')

  // Live Tail SSE State
  const [liveTail, setLiveTail] = useState<boolean>(() => {
    return sessionStorage.getItem('vexa_run_live_tail') === 'true'
  })

  // Popover / Drawer States
  const [activeTraceSessionId, setActiveTraceSessionId] = useState<string | null>(null)
  const [activeKeyModal, setActiveKeyModal] = useState<string | null>(null)

  // Column visibility state
  const [columnsMenuOpen, setColumnsMenuOpen] = useState(false)
  const [visibleColumns, setVisibleColumns] = useState({
    session: true,
    key: true,
    tokens: true,
    ttft: false,
    status: true,
  })

  // Sorting state
  const [sortField, setSortField] = useState<'started' | 'duration' | 'settled' | 'tokens' | 'ttft'>('started')
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')

  // Filter state
  const [hours, setHours] = useState<number>(24)
  const [provider, setProvider] = useState<string>('')
  const [state, setState] = useState<string>('')
  const [model, setModel] = useState<string>('')

  const urlRunID = searchParams.get('run_id')

  useEffect(() => {
    sessionStorage.setItem('vexa_run_live_tail', String(liveTail))
  }, [liveTail])

  useEffect(() => {
    loadRuns()
  }, [hours, provider, state, model])

  useEffect(() => {
    if (urlRunID) {
      openDossier(urlRunID)
    } else {
      setSelectedDossier(null)
    }
  }, [urlRunID])

  // Live Tail SSE Stream
  useEffect(() => {
    if (!liveTail) return
    const es = new EventSource('/api/v1/observability/request-logs/stream')
    es.addEventListener('logs', (e) => {
      try {
        const newRuns = JSON.parse(e.data) as RunSummary[]
        if (Array.isArray(newRuns) && newRuns.length > 0) {
          setRuns((prev) => {
            const existingIds = new Set(prev.map((r) => r.run_id))
            const unique = newRuns.filter((r) => !existingIds.has(r.run_id))
            return [...unique, ...prev].slice(0, 150)
          })
          setDataFreshness(new Date().toISOString())
        }
      } catch (err) {
        console.error('Error parsing live tail stream:', err)
      }
    })
    return () => {
      es.close()
    }
  }, [liveTail])

  const loadRuns = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.listRuns({
        hours,
        provider: provider || undefined,
        state: state || undefined,
        model: model || undefined,
        limit: 50,
      })
      setRuns(res.runs || [])
      setDataFreshness(res.data_freshness || '')
      setConfidence(res.confidence || 'observed')
    } catch (err: any) {
      setError(err.message || 'Failed to load runs')
    } finally {
      setLoading(false)
    }
  }

  const openDossier = async (runId: string) => {
    try {
      const d = await api.getRunDossier(runId)
      setSelectedDossier(d)
      setSearchParams({ run_id: runId })
    } catch (err: any) {
      console.error('Failed to load dossier:', err)
    }
  }

  const closeDossier = () => {
    setSelectedDossier(null)
    setSearchParams({})
  }

  const handleSort = (field: 'started' | 'duration' | 'settled' | 'tokens' | 'ttft') => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortOrder('desc')
    }
  }

  // Sorted list
  const sortedRuns = useMemo(() => {
    return [...runs].sort((a, b) => {
      let diff = 0
      if (sortField === 'started') {
        diff = new Date(a.started_at).getTime() - new Date(b.started_at).getTime()
      } else if (sortField === 'duration') {
        diff = (a.duration_ms || 0) - (b.duration_ms || 0)
      } else if (sortField === 'settled') {
        diff = (a.settled_microcents || 0) - (b.settled_microcents || 0)
      } else if (sortField === 'tokens') {
        diff = (a.total_tokens || 0) - (b.total_tokens || 0)
      } else if (sortField === 'ttft') {
        diff = (a.ttft_ms || 0) - (b.ttft_ms || 0)
      }
      return sortOrder === 'asc' ? diff : -diff
    })
  }, [runs, sortField, sortOrder])

  return (
    <div className="run-explorer-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Run Explorer & Forensics</h1>
          <p>Trace every LLM request through identity, policy snapshot, spend authorization, and upstream dispatch.</p>
        </div>
        <div className="soc-header-controls">
          {/* Live Tail Toggle Button */}
          <button
            type="button"
            className={`soc-btn-secondary ${liveTail ? 'active' : ''}`}
            onClick={() => setLiveTail(!liveTail)}
            style={{
              borderColor: liveTail ? '#10b981' : undefined,
              color: liveTail ? '#10b981' : undefined,
              background: liveTail ? 'rgba(16, 185, 129, 0.1)' : undefined,
              fontWeight: 600,
            }}
          >
            {liveTail ? '● LIVE TAIL (ON)' : '○ Live Tail'}
          </button>

          {/* Columns Dropdown Toggle */}
          <div style={{ position: 'relative' }}>
            <button
              type="button"
              className="soc-btn-secondary"
              onClick={() => setColumnsMenuOpen(!columnsMenuOpen)}
            >
              Columns ▾
            </button>
            {columnsMenuOpen && (
              <div
                style={{
                  position: 'absolute',
                  right: 0,
                  top: '110%',
                  background: 'var(--bg-surface-2)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-sm)',
                  padding: 12,
                  minWidth: 170,
                  zIndex: 100,
                  boxShadow: '0 8px 24px rgba(0,0,0,0.5)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 8,
                }}
              >
                <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--text-primary)' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns.session}
                    onChange={(e) => setVisibleColumns({ ...visibleColumns, session: e.target.checked })}
                  />
                  Session ID
                </label>
                <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--text-primary)' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns.key}
                    onChange={(e) => setVisibleColumns({ ...visibleColumns, key: e.target.checked })}
                  />
                  Virtual Key
                </label>
                <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--text-primary)' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns.tokens}
                    onChange={(e) => setVisibleColumns({ ...visibleColumns, tokens: e.target.checked })}
                  />
                  Tokens & Cache
                </label>
                <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--text-primary)' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns.ttft}
                    onChange={(e) => setVisibleColumns({ ...visibleColumns, ttft: e.target.checked })}
                  />
                  TTFT
                </label>
                <label style={{ fontSize: 12, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', color: 'var(--text-primary)' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns.status}
                    onChange={(e) => setVisibleColumns({ ...visibleColumns, status: e.target.checked })}
                  />
                  Status Code
                </label>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="run-filter-toolbar">
        <div className="soc-time-toggle" role="group" aria-label="Time Window">
          {([1, 24, 168, 720] as const).map((h) => (
            <button
              key={h}
              type="button"
              className={`soc-time-btn ${hours === h ? 'active' : ''}`}
              onClick={() => setHours(h)}
            >
              {h === 1 ? '1H' : h === 24 ? '24H' : h === 168 ? '7D' : '30D'}
            </button>
          ))}
        </div>

        <select
          className="soc-select-filter"
          value={provider}
          onChange={(e) => setProvider(e.target.value)}
          aria-label="Provider Filter"
        >
          <option value="">All Providers</option>
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic</option>
          <option value="groq">Groq</option>
        </select>

        <select
          className="soc-select-filter"
          value={state}
          onChange={(e) => setState(e.target.value)}
          aria-label="State Filter"
        >
          <option value="">All States</option>
          <option value="AUTHORIZED">AUTHORIZED</option>
          <option value="SETTLED">SETTLED</option>
          <option value="RELEASED">RELEASED</option>
          <option value="DENIED">DENIED</option>
        </select>

        <input
          type="text"
          className="soc-filter-input"
          placeholder="Filter by model (e.g. gpt-4o)..."
          value={model}
          onChange={(e) => setModel(e.target.value)}
          style={{ width: 220 }}
        />
      </div>

      {error && (
        <div className="card" style={{ padding: 16, borderColor: 'var(--danger)', color: 'var(--danger)', marginBottom: 20 }}>
          {error}
        </div>
      )}

      {/* Runs Table */}
      <div className="runs-table-card card soc-panel">
        <div className="soc-card-header" style={{ marginBottom: 20 }}>
          <div>
            <div className="card-title">LLM Execution Streams</div>
            <div className="soc-card-subtitle">{runs.length} broker execution records within {hours === 1 ? '1 hour' : hours === 24 ? '24 hours' : hours === 168 ? '7 days' : '30 days'}</div>
          </div>
          <span className={`soc-live-pill ${liveTail ? '' : 'pill-offline'}`}>
            {liveTail ? 'LIVE TAIL' : 'STANDBY'}
          </span>
        </div>

        {loading && runs.length === 0 ? (
          <div className="loading" style={{ height: 200 }}>Loading run telemetry...</div>
        ) : runs.length === 0 ? (
          <div className="empty-state">
            <p style={{ fontSize: 15, fontWeight: 500 }}>No broker LLM runs found in the selected time window.</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>Workstations routing completions through Agent Control will automatically appear here.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th style={{ cursor: 'pointer' }} onClick={() => handleSort('started')}>
                    Started {sortField === 'started' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
                  </th>
                  <th>Device / Origin</th>
                  <th>Provider & Model</th>
                  <th>State</th>
                  {visibleColumns.status && <th>Status</th>}
                  {visibleColumns.session && <th>Session Context</th>}
                  {visibleColumns.key && <th>Virtual Key</th>}
                  <th>Reserved</th>
                  <th style={{ cursor: 'pointer' }} onClick={() => handleSort('settled')}>
                    Settled {sortField === 'settled' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
                  </th>
                  {visibleColumns.tokens && (
                    <th style={{ cursor: 'pointer' }} onClick={() => handleSort('tokens')}>
                      Tokens {sortField === 'tokens' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  )}
                  {visibleColumns.ttft && (
                    <th style={{ cursor: 'pointer' }} onClick={() => handleSort('ttft')}>
                      TTFT {sortField === 'ttft' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
                    </th>
                  )}
                  <th style={{ cursor: 'pointer' }} onClick={() => handleSort('duration')}>
                    Duration {sortField === 'duration' ? (sortOrder === 'asc' ? '↑' : '↓') : ''}
                  </th>
                </tr>
              </thead>
              <tbody>
                {sortedRuns.map((r) => {
                  const stateClass = `state-${r.state.toLowerCase()}`
                  return (
                    <tr
                      key={r.run_id}
                      className="runs-table-row"
                      onClick={() => openDossier(r.run_id)}
                    >
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                        {r.run_id.substring(0, 10)}...
                      </td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                        {new Date(r.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </td>
                      <td style={{ fontSize: 13 }}>
                        {r.device_name && r.device_name !== r.device_id ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                            <span style={{ fontWeight: 600, color: 'var(--text-primary)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                              <span>💻</span>
                              <span>{r.device_name}</span>
                            </span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
                              {r.device_id.length > 18 ? `${r.device_id.slice(0, 8)}...${r.device_id.slice(-4)}` : r.device_id}
                            </span>
                          </div>
                        ) : (
                          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                            <span>💻</span>
                            <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>
                              {r.device_id ? (r.device_id.length > 18 ? `${r.device_id.slice(0, 8)}...${r.device_id.slice(-4)}` : r.device_id) : 'gateway-default'}
                            </span>
                          </div>
                        )}
                      </td>
                      <td>
                        <strong style={{ fontSize: 13 }}>{r.provider?.toUpperCase()}</strong>
                        <span style={{ color: 'var(--text-muted)', fontSize: 12, marginLeft: 6 }}>{r.model}</span>
                      </td>
                      <td>
                        <span className={`badge-state ${stateClass}`}>
                          {r.state}
                        </span>
                      </td>
                      {visibleColumns.status && (
                        <td>
                          <span className={`badge ${r.status_code === 200 ? 'green' : (r.status_code && r.status_code >= 400) ? 'red' : 'blue'}`}>
                            {r.status_code || 200}
                          </span>
                        </td>
                      )}
                      {visibleColumns.session && (
                        <td onClick={(e) => e.stopPropagation()}>
                          {r.session_id ? (
                            <button
                              type="button"
                              className="soc-btn-secondary"
                              style={{ fontSize: 11, padding: '2px 6px', borderColor: '#a78bfa', color: '#c4b5fd' }}
                              onClick={() => setActiveTraceSessionId(r.session_id || null)}
                              title="Click to open session multi-turn trajectory"
                            >
                              🧭 {r.session_id.slice(0, 8)}...
                            </button>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>—</span>
                          )}
                        </td>
                      )}
                      {visibleColumns.key && (
                        <td onClick={(e) => e.stopPropagation()}>
                          {r.virtual_key_prefix ? (
                            <button
                              type="button"
                              className="obs-key-pill"
                              style={{ border: 'none', cursor: 'pointer' }}
                              onClick={() => setActiveKeyModal(r.virtual_key_prefix || null)}
                              title="Click to preview key budget & scope"
                            >
                              {r.virtual_key_prefix}
                            </button>
                          ) : (
                            <span style={{ color: 'var(--text-muted)' }}>—</span>
                          )}
                        </td>
                      )}
                      <td style={{ color: '#38bdf8', fontSize: 13 }}>
                        ${microcentsToUSD(r.reserved_microcents).toFixed(4)}
                      </td>
                      <td style={{ color: '#10b981', fontWeight: 600, fontSize: 13 }}>
                        ${microcentsToUSD(r.settled_microcents).toFixed(4)}
                      </td>
                      {visibleColumns.tokens && (
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                          <span>{r.input_tokens || 0} / {r.output_tokens || 0}</span>
                          {Boolean(r.cached_tokens) && (
                            <span style={{ color: '#38bdf8', marginLeft: 4 }} title="Cached Tokens">⚡{r.cached_tokens}</span>
                          )}
                        </td>
                      )}
                      {visibleColumns.ttft && (
                        <td style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                          {r.ttft_ms ? `${r.ttft_ms} ms` : '—'}
                        </td>
                      )}
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                        {r.duration_ms || 0} ms
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
            <span>Confidence: <strong style={{ color: '#10b981' }}>{confidence}</strong> · System of Record: <strong>Authoritative LLM Gateway Ledger</strong></span>
          </span>
          {dataFreshness && <span>Data freshness: {new Date(dataFreshness).toLocaleTimeString()}</span>}
        </div>
      </div>

      {/* Forensic Dossier Drawer */}
      {selectedDossier && (
        <RunDossierDrawer
          dossier={selectedDossier}
          onClose={closeDossier}
        />
      )}

      {/* Session Trajectory Drawer */}
      {activeTraceSessionId && (
        <SessionTraceDrawer
          sessionId={activeTraceSessionId}
          onClose={() => setActiveTraceSessionId(null)}
          onOpenRunDossier={(runId) => {
            setActiveTraceSessionId(null)
            openDossier(runId)
          }}
        />
      )}

      {/* Virtual Key Quick View */}
      {activeKeyModal && (
        <VirtualKeyQuickView
          keyPrefixOrId={activeKeyModal}
          onClose={() => setActiveKeyModal(null)}
        />
      )}
    </div>
  )
}
