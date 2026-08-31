import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, type RunSummary, type RunDossier } from '../api/client'
import RunDossierDrawer from './RunDossierDrawer'
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

  // Filter state
  const [hours, setHours] = useState<number>(24)
  const [provider, setProvider] = useState<string>('')
  const [state, setState] = useState<string>('')
  const [model, setModel] = useState<string>('')

  const urlRunID = searchParams.get('run_id')

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

  return (
    <div className="run-explorer-page">
      <div className="page-header">
        <div>
          <h1>Run Explorer & Forensics</h1>
          <p>Trace every LLM request through identity, policy snapshot, spend authorization, and upstream dispatch.</p>
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
          className="run-filter-select"
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
          className="run-filter-select"
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
          className="run-filter-input"
          placeholder="Filter by model (e.g. gpt-4o)..."
          value={model}
          onChange={(e) => setModel(e.target.value)}
          style={{ width: 220 }}
        />
      </div>

      {error && (
        <div className="card" style={{ padding: 16, borderColor: 'var(--danger)', color: 'var(--danger)' }}>
          {error}
        </div>
      )}

      {/* Runs Table */}
      <div className="runs-table-card card">
        {loading ? (
          <div className="loading" style={{ height: 200 }}>Loading run telemetry...</div>
        ) : runs.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: 15, fontWeight: 500 }}>No broker LLM runs found in the selected time window.</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>Workstations routing completions through Vexa will automatically appear here.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Run ID</th>
                  <th>Started</th>
                  <th>Device / Origin</th>
                  <th>Provider & Model</th>
                  <th>State</th>
                  <th>Reserved</th>
                  <th>Settled</th>
                  <th>Duration</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((r) => {
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
                        {r.device_id || 'gateway-default'}
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
                      <td style={{ color: '#38bdf8', fontSize: 13 }}>
                        ${microcentsToUSD(r.reserved_microcents).toFixed(4)}
                      </td>
                      <td style={{ color: '#10b981', fontWeight: 600, fontSize: 13 }}>
                        ${microcentsToUSD(r.settled_microcents).toFixed(4)}
                      </td>
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
        <div style={{ padding: '12px 20px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)' }}>
          <span>Confidence: <strong style={{ color: '#10b981' }}>{confidence}</strong> · Evidence source: <strong>PostgreSQL spend_reservations</strong></span>
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
    </div>
  )
}
