import React, { useState, useEffect } from 'react'
import { api, type AuditLogItem } from '../../api/client'

function formatTimestamp(isoString: string): string {
  try {
    const d = new Date(isoString)
    return d.toLocaleString([], {
      month: '2-digit',
      day: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true,
    })
  } catch {
    return isoString
  }
}

const ACTION_COLORS: Record<string, string> = {
  created: 'obs-badge-success',
  rotated: 'obs-badge-info',
  updated: 'obs-badge-warning',
  deleted: 'obs-badge-danger',
  revoked: 'obs-badge-danger',
}

export default function AuditLogsTab() {
  const [logs, setLogs] = useState<AuditLogItem[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [objectId, setObjectId] = useState('')
  const [action, setAction] = useState('all')
  const [tableName, setTableName] = useState('all')
  const [expandedIds, setExpandedIds] = useState<Set<string>>(new Set())

  useEffect(() => {
    loadAuditLogs()
  }, [action, tableName])

  const loadAuditLogs = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.listAuditLogs({
        limit: 50,
        object_id: objectId || undefined,
        action: action !== 'all' ? action : undefined,
        table_name: tableName !== 'all' ? tableName : undefined,
      })
      setLogs(res.audit_logs || [])
      setTotal(res.total || (res.audit_logs || []).length)
    } catch (err: any) {
      setError(err.message || 'Failed to load audit logs')
    } finally {
      setLoading(false)
    }
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    loadAuditLogs()
  }

  const toggleRow = (id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }
      return next
    })
  }

  return (
    <div className="obs-audit-logs-tab">
      {/* Search and Action Toolbar */}
      <div className="obs-filter-toolbar">
        <form onSubmit={handleSearchSubmit} className="obs-search-box">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            placeholder="Search by Object ID..."
            value={objectId}
            onChange={(e) => setObjectId(e.target.value)}
          />
          {objectId && (
            <button type="button" className="obs-clear-search" onClick={() => { setObjectId(''); loadAuditLogs() }}>
              ×
            </button>
          )}
        </form>

        <div className="obs-toolbar-controls">
          {/* Action Filter */}
          <select
            className="obs-select"
            value={action}
            onChange={(e) => setAction(e.target.value)}
            aria-label="All Actions"
          >
            <option value="all">All Actions</option>
            <option value="created">Created</option>
            <option value="updated">Updated</option>
            <option value="rotated">Rotated</option>
            <option value="deleted">Deleted</option>
            <option value="revoked">Revoked</option>
          </select>

          {/* Table / Resource Filter */}
          <select
            className="obs-select"
            value={tableName}
            onChange={(e) => setTableName(e.target.value)}
            aria-label="All Tables"
          >
            <option value="all">All Tables</option>
            <option value="virtual_keys">Virtual Keys</option>
            <option value="users">Users</option>
            <option value="policies">Policies</option>
            <option value="provider_keys">Provider Keys</option>
            <option value="devices">Devices</option>
            <option value="group_policies">Group Policies</option>
          </select>

          {/* Refresh Button */}
          <button
            type="button"
            className="obs-btn-secondary"
            onClick={() => loadAuditLogs()}
            disabled={loading}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className={loading ? 'obs-spin' : ''}>
              <path d="M23 4v6h-6M1 20v-6h6" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            Refresh
          </button>
        </div>
      </div>

      {/* Audit Log Table */}
      <div className="obs-table-container">
        {loading && logs.length === 0 ? (
          <div className="obs-empty-state">
            <div className="obs-spinner" />
            <p>Loading audit ledger...</p>
          </div>
        ) : error ? (
          <div className="obs-error-state">
            <p className="obs-error-msg">{error}</p>
            <button className="obs-btn-secondary" onClick={() => loadAuditLogs()}>Retry</button>
          </div>
        ) : logs.length === 0 ? (
          <div className="obs-empty-state">
            <div className="obs-empty-icon">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                <polyline points="14 2 14 8 20 8" />
                <line x1="16" y1="13" x2="8" y2="13" />
                <line x1="16" y1="17" x2="8" y2="17" />
              </svg>
            </div>
            <h3>No audit records found</h3>
            <p>Administrative changes to virtual keys, users, and policies will be immutably recorded here.</p>
          </div>
        ) : (
          <table className="obs-table obs-audit-table">
            <thead>
              <tr>
                <th style={{ width: '40px' }} />
                <th>Timestamp</th>
                <th>Table Name</th>
                <th>Action</th>
                <th>Changed By</th>
                <th>Affected Item ID</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((item) => {
                const isExpanded = expandedIds.has(item.id)
                const actionBadgeClass = ACTION_COLORS[item.action.toLowerCase()] || 'obs-badge-neutral'

                return (
                  <React.Fragment key={item.id}>
                    <tr
                      className={`obs-table-row clickable ${isExpanded ? 'expanded-row' : ''}`}
                      onClick={() => toggleRow(item.id)}
                    >
                      <td className="obs-expand-col">
                        <span className={`obs-caret ${isExpanded ? 'open' : ''}`}>▶</span>
                      </td>
                      <td className="obs-col-time">{formatTimestamp(item.timestamp)}</td>
                      <td>
                        <span className="obs-table-name-tag">{item.table_name || 'System'}</span>
                      </td>
                      <td>
                        <span className={`obs-badge ${actionBadgeClass}`}>
                          {item.action}
                        </span>
                      </td>
                      <td className="obs-col-actor">
                        <div className="obs-actor-info">
                          <span className="obs-actor-name">{item.changed_by}</span>
                          {item.actor_role && <span className="obs-role-pill">{item.actor_role}</span>}
                        </div>
                      </td>
                      <td className="obs-col-mono">{item.affected_item_id || item.id}</td>
                    </tr>
                    {isExpanded && (
                      <tr className="obs-expanded-detail-tr" key={`${item.id}-detail`}>
                        <td colSpan={6} className="obs-expanded-cell">
                          <div className="obs-diff-grid">
                            <div className="obs-diff-block">
                              <div className="obs-diff-title">Before Value:</div>
                              <div className="obs-json-box">
                                {item.before_value ? (
                                  <pre>{JSON.stringify(item.before_value, null, 2)}</pre>
                                ) : (
                                  <span className="obs-muted">N/A</span>
                                )}
                              </div>
                            </div>
                            <div className="obs-diff-block">
                              <div className="obs-diff-title">Updated Value:</div>
                              <div className="obs-json-box">
                                {item.updated_value ? (
                                  <pre>{JSON.stringify(item.updated_value, null, 2)}</pre>
                                ) : (
                                  <span className="obs-muted">No state payload available</span>
                                )}
                              </div>
                            </div>
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

      {/* Pagination Footer */}
      <div className="obs-pagination-footer">
        <div className="obs-rows-per-page">
          <span>Rows per page: 50</span>
        </div>
        <div className="obs-page-summary">
          Showing 1 - {logs.length} of {total} results
        </div>
      </div>
    </div>
  )
}
