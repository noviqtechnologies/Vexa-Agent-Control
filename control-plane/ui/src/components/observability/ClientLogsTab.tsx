import React, { useState, useEffect, useRef } from 'react'
import { api, type ClientLogItem } from '../../api/client'

export default function ClientLogsTab() {
  const [logs, setLogs] = useState<ClientLogItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)

  // Filters
  const [filterLevel, setFilterLevel] = useState<string>('all')
  const [filterHours, setFilterHours] = useState<number>(24)
  const [filterDevice, setFilterDevice] = useState<string>('')
  const [filterSearch, setFilterSearch] = useState<string>('')
  const [autoRefresh, setAutoRefresh] = useState(false)
  const timerRef = useRef<number | null>(null)

  const fetchLogs = async (showLoading = true) => {
    if (showLoading) setLoading(true)
    try {
      setError(null)
      const res = await api.listClientLogs({
        hours: filterHours,
        level: filterLevel !== 'all' ? filterLevel : undefined,
        device_id: filterDevice.trim() || undefined,
        search: filterSearch.trim() || undefined,
      })
      setLogs(res.client_logs || [])
    } catch (err: any) {
      setError(err.message || 'Failed to fetch client diagnostic logs')
    } finally {
      if (showLoading) setLoading(false)
    }
  }

  useEffect(() => {
    fetchLogs(true)
  }, [filterLevel, filterHours, filterDevice, filterSearch])

  useEffect(() => {
    if (autoRefresh) {
      timerRef.current = window.setInterval(() => {
        fetchLogs(false)
      }, 5000)
    }
    return () => {
      if (timerRef.current) clearInterval(timerRef.current)
    }
  }, [autoRefresh, filterLevel, filterHours, filterDevice, filterSearch])

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    fetchLogs(true)
  }

  const getLevelBadge = (level: string) => {
    const l = level.toLowerCase()
    if (l === 'error') {
      return (
        <span className="obs-badge obs-badge-danger">
          🔴 ERROR
        </span>
      )
    }
    if (l === 'warn' || l === 'warning') {
      return (
        <span className="obs-badge obs-badge-warning">
          🟡 WARN
        </span>
      )
    }
    return (
      <span className="obs-badge obs-badge-info">
        🔵 {level.toUpperCase()}
      </span>
    )
  }

  return (
    <div className="obs-request-logs-tab">
      {/* Auto-refresh indicator banner */}
      {autoRefresh && (
        <div className="obs-refresh-banner">
          <div className="obs-refresh-left">
            <span className="obs-pulse-dot active" />
            <span>Live Stream active — polling workstation logs every 5 seconds</span>
          </div>
          <button
            type="button"
            className="obs-refresh-toggle-btn"
            onClick={() => setAutoRefresh(false)}
          >
            Pause
          </button>
        </div>
      )}

      {/* Filter toolbar */}
      <div className="obs-filter-toolbar">
        <form onSubmit={handleSearchSubmit} className="obs-search-box">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            placeholder="Search message, event, error code, request ID..."
            value={filterSearch}
            onChange={(e) => setFilterSearch(e.target.value)}
          />
          {filterSearch && (
            <button type="button" className="obs-clear-search" onClick={() => { setFilterSearch(''); }}>
              ×
            </button>
          )}
        </form>

        <div className="obs-toolbar-controls">
          {/* Severity selector */}
          <select
            className="obs-select"
            value={filterLevel}
            onChange={(e) => setFilterLevel(e.target.value)}
            aria-label="Severity Filter"
          >
            <option value="all">All Severities</option>
            <option value="error">Errors Only</option>
            <option value="warn">Warnings Only</option>
            <option value="info">Info</option>
          </select>

          {/* Time window selector */}
          <select
            className="obs-select"
            value={filterHours}
            onChange={(e) => setFilterHours(Number(e.target.value))}
            aria-label="Time Window"
          >
            <option value={1}>Last 1 Hour</option>
            <option value={6}>Last 6 Hours</option>
            <option value={24}>Last 24 Hours</option>
            <option value={168}>Last 7 Days</option>
          </select>

          {/* Device / Host filter input */}
          <input
            type="text"
            className="obs-select"
            style={{ width: '180px' }}
            placeholder="Filter Device / Host..."
            value={filterDevice}
            onChange={(e) => setFilterDevice(e.target.value)}
          />

          {/* Live Stream toggle */}
          <label className="obs-live-tail-label">
            <span>Live Stream (5s)</span>
            <input
              type="checkbox"
              className="obs-switch-input"
              checked={autoRefresh}
              onChange={(e) => setAutoRefresh(e.target.checked)}
            />
            <span className="obs-switch-slider" />
          </label>

          {/* Refresh icon button */}
          <button
            type="button"
            className="obs-btn-icon"
            onClick={() => fetchLogs(true)}
            title="Refresh logs"
            disabled={loading}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={loading ? 'obs-spin' : ''}>
              <path d="M23 4v6h-6M1 20v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
          </button>
        </div>
      </div>

      {error && (
        <div className="obs-error-state" style={{ marginBottom: '16px', padding: '12px' }}>
          <p className="obs-error-msg">{error}</p>
        </div>
      )}

      {/* Logs Table */}
      <div className="obs-table-container">
        {loading && logs.length === 0 ? (
          <div className="obs-empty-state">
            <div className="obs-spinner" />
            <p>Loading workstation diagnostic logs...</p>
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
            <h3>No Client Logs Recorded</h3>
            <p>Workstation daemons across Windows, macOS, and Linux are operating normally without diagnostic dropouts.</p>
          </div>
        ) : (
          <table className="obs-table">
            <thead>
              <tr>
                <th style={{ width: '32px' }}></th>
                <th>Timestamp</th>
                <th>Level</th>
                <th>Event</th>
                <th>Device / Host</th>
                <th>User</th>
                <th>Message / Error Code</th>
                <th style={{ textAlign: 'right' }}>Request ID</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => {
                const isExpanded = expandedId === log.id
                return (
                  <React.Fragment key={log.id}>
                    <tr
                      className={`obs-table-row clickable ${isExpanded ? 'expanded-row' : ''}`}
                      onClick={() => setExpandedId(isExpanded ? null : log.id)}
                    >
                      <td className="obs-expand-col">
                        <span className={`obs-caret ${isExpanded ? 'open' : ''}`}>▶</span>
                      </td>
                      <td className="obs-col-time">
                        {new Date(log.timestamp).toLocaleString([], {
                          month: 'short',
                          day: 'numeric',
                          hour: '2-digit',
                          minute: '2-digit',
                          second: '2-digit',
                        })}
                      </td>
                      <td>
                        {getLevelBadge(log.level)}
                      </td>
                      <td>
                        <span className="obs-table-name-tag" style={{ fontFamily: 'monospace', fontSize: '11.5px' }}>
                          {log.event}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontWeight: 500, color: '#f8fafc' }}>
                          {log.hostname || 'Unknown Host'}
                        </div>
                        {log.device_id && (
                          <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#64748b' }}>
                            {log.device_id.slice(0, 12)}
                          </div>
                        )}
                      </td>
                      <td>
                        <span className="obs-actor-name">{log.user_identifier || 'system'}</span>
                      </td>
                      <td style={{ maxWidth: '340px' }}>
                        <div
                          style={{
                            color: log.level.toLowerCase() === 'error' ? '#f87171' : log.level.toLowerCase() === 'warn' || log.level.toLowerCase() === 'warning' ? '#fbbf24' : '#94a3b8',
                            fontWeight: 500,
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                          title={log.message || log.error_code || ''}
                        >
                          {log.message || log.error_code || '—'}
                        </div>
                        {log.error_code && log.message && (
                          <div style={{ fontFamily: 'monospace', fontSize: '11px', color: '#64748b' }}>
                            {log.error_code}
                          </div>
                        )}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        {log.request_id ? (
                          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'flex-end', gap: '4px' }}>
                            <button
                              type="button"
                              className="obs-copy-id-btn"
                              onClick={(e) => {
                                e.stopPropagation()
                                copyToClipboard(log.request_id!, `req-${log.id}`)
                              }}
                              title={`Click to copy: ${log.request_id}`}
                            >
                              {log.request_id.slice(0, 10)}...
                              {copiedKey === `req-${log.id}` && <span className="obs-copied-tag">✓</span>}
                            </button>
                          </div>
                        ) : (
                          <span className="obs-session-na">—</span>
                        )}
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="obs-expanded-detail-tr" key={`${log.id}-detail`}>
                        <td colSpan={8} className="obs-expanded-cell">
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                            <span style={{ fontSize: '13px', fontWeight: 600, color: '#f8fafc' }}>
                              🔍 Diagnostic Log Inspection: <span style={{ fontFamily: 'monospace', color: '#38bdf8' }}>{log.event}</span>
                            </span>
                            <button
                              type="button"
                              className="obs-btn-secondary"
                              style={{ padding: '4px 8px', fontSize: '11px' }}
                              onClick={(e) => {
                                e.stopPropagation()
                                setExpandedId(null)
                              }}
                            >
                              Close
                            </button>
                          </div>
                          <div className="obs-json-box">
                            <pre>{JSON.stringify(log.details || log, null, 2)}</pre>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
