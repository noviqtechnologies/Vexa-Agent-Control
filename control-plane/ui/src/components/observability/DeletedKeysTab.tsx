import { useState, useEffect } from 'react'
import { api, type DeletedVirtualKey } from '../../api/client'

function microcentsToUSD(microcents?: number): string {
  if (microcents === undefined || microcents === null || microcents === 0) return '$0.00'
  const dollars = microcents / 100_000_000
  return `$${dollars.toFixed(2)}`
}

function formatTimestamp(isoString?: string): string {
  if (!isoString) return '-'
  try {
    const d = new Date(isoString)
    return d.toLocaleString([], {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return isoString
  }
}

export default function DeletedKeysTab() {
  const [keys, setKeys] = useState<DeletedVirtualKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  useEffect(() => {
    loadDeletedKeys()
  }, [])

  const loadDeletedKeys = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.listDeletedVirtualKeys({ limit: 50 })
      setKeys(res.deleted_virtual_keys || [])
    } catch (err: any) {
      setError(err.message || 'Failed to load deleted keys')
    } finally {
      setLoading(false)
    }
  }

  const filteredKeys = keys.filter((k) => {
    if (!search) return true
    const term = search.toLowerCase()
    return (
      k.id.toLowerCase().includes(term) ||
      (k.key_prefix && k.key_prefix.toLowerCase().includes(term)) ||
      (k.name && k.name.toLowerCase().includes(term)) ||
      (k.created_by && k.created_by.toLowerCase().includes(term)) ||
      (k.deleted_by && k.deleted_by.toLowerCase().includes(term))
    )
  })

  return (
    <div className="obs-deleted-keys-tab">
      {/* Compliance banner */}
      <div className="obs-compliance-banner">
        <div className="obs-compliance-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        </div>
        <div className="obs-compliance-text">
          <strong>Enterprise Audit & Compliance Suite</strong>
          <p>Decommissioned and revoked virtual keys remain immutably tracked here for historical spend auditing and compliance reconciliation.</p>
        </div>
      </div>

      {/* Search toolbar */}
      <div className="obs-filter-toolbar">
        <div className="obs-search-box">
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <input
            type="text"
            placeholder="Search deleted keys by ID, prefix, or user..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button type="button" className="obs-clear-search" onClick={() => setSearch('')}>
              ×
            </button>
          )}
        </div>

        <div className="obs-toolbar-controls">
          <button
            type="button"
            className="obs-btn-secondary"
            onClick={() => loadDeletedKeys()}
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

      {/* Table */}
      <div className="obs-table-container">
        {loading ? (
          <div className="obs-empty-state">
            <div className="obs-spinner" />
            <p>Loading deleted keys...</p>
          </div>
        ) : error ? (
          <div className="obs-error-state">
            <p className="obs-error-msg">{error}</p>
            <button className="obs-btn-secondary" onClick={() => loadDeletedKeys()}>Retry</button>
          </div>
        ) : filteredKeys.length === 0 ? (
          <div className="obs-empty-state">
            <div className="obs-empty-icon">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
            </div>
            <h3>No deleted keys found</h3>
            <p>Keys deleted or revoked from this proxy will show up here.</p>
          </div>
        ) : (
          <table className="obs-table">
            <thead>
              <tr>
                <th>Key ID</th>
                <th>Key Alias</th>
                <th>Team</th>
                <th>Spend (USD)</th>
                <th>Budget (USD)</th>
                <th>Created By</th>
                <th>Created At</th>
                <th>Deleted By</th>
                <th>Deleted At</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {filteredKeys.map((k) => (
                <tr key={k.id} className="obs-table-row">
                  <td className="obs-col-mono">{k.id.slice(0, 12)}...</td>
                  <td>
                    <span className="obs-key-pill">{k.key_prefix || k.name}</span>
                  </td>
                  <td>{k.team_id || 'default'}</td>
                  <td className="obs-col-cost">{microcentsToUSD(k.spent_microcents)}</td>
                  <td>
                    {k.monthly_budget_microcents > 0
                      ? microcentsToUSD(k.monthly_budget_microcents)
                      : 'Unlimited'}
                  </td>
                  <td>{k.created_by || 'admin'}</td>
                  <td className="obs-col-time">{formatTimestamp(k.created_at)}</td>
                  <td className="obs-col-actor">{k.deleted_by || 'admin'}</td>
                  <td className="obs-col-time">{formatTimestamp(k.deleted_at)}</td>
                  <td>
                    <span className="obs-badge obs-badge-danger">
                      {k.deleted_reason || 'revoked'}
                    </span>
                  </td>
                </tr>
              ))}
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
          Showing 1 - {filteredKeys.length} of {filteredKeys.length}
        </div>
      </div>
    </div>
  )
}
