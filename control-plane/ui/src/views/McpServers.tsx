import { useEffect, useState, useMemo } from 'react'

interface McpServer {
  agent_id: string
  ide_target: string
  server_name: string
  wrapped: boolean
  path_verified: boolean
  last_seen_at: string
}

function getIdeBadgeClass(ide: string): string {
  const normalized = (ide || '').toLowerCase()
  if (normalized.includes('antigravity')) return 'ide-badge-antigravity'
  if (normalized.includes('codex') || normalized.includes('chatgpt')) return 'ide-badge-codex'
  if (normalized.includes('claude')) return 'ide-badge-claude'
  if (normalized.includes('cursor')) return 'ide-badge-cursor'
  if (normalized.includes('vscode') || normalized.includes('vs code')) return 'ide-badge-vscode'
  if (normalized.includes('jetbrains') || normalized.includes('intellij')) return 'ide-badge-jetbrains'
  return 'ide-badge-default'
}

export default function McpServers() {
  const [servers, setServers] = useState<McpServer[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [ideFilter, setIdeFilter] = useState('all')
  const [wrapFilter, setWrapFilter] = useState('all')

  const fetchServers = async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await fetch('/api/v1/fleet/mcp-servers')
      if (!res.ok) {
        throw new Error('Failed to fetch MCP servers. You may not have administrative permissions.')
      }
      const data = await res.json()
      setServers(data || [])
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchServers()
  }, [])

  const getHostname = (agentId: string) => {
    if (agentId && agentId.startsWith('agent-')) {
      const parts = agentId.split('-')
      if (parts.length >= 3) {
        return parts.slice(2).join('-')
      }
    }
    return agentId || '-'
  }

  // Summary Metrics
  const metrics = useMemo(() => {
    const total = servers.length
    const wrapped = servers.filter((s) => s.wrapped).length
    const verified = servers.filter((s) => s.path_verified).length
    const uniqueHosts = new Set(servers.map((s) => getHostname(s.agent_id))).size
    const uniqueIdes = new Set(servers.map((s) => s.ide_target).filter(Boolean)).size
    return {
      total,
      wrapped,
      wrappedPct: total > 0 ? Math.round((wrapped / total) * 100) : 100,
      verified,
      verifiedPct: total > 0 ? Math.round((verified / total) * 100) : 100,
      uniqueHosts,
      uniqueIdes,
    }
  }, [servers])

  // Filtered servers list
  const filteredServers = useMemo(() => {
    return servers.filter((s) => {
      const host = getHostname(s.agent_id).toLowerCase()
      const agent = (s.agent_id || '').toLowerCase()
      const server = (s.server_name || '').toLowerCase()
      const ide = (s.ide_target || '').toLowerCase()
      const query = searchQuery.toLowerCase()

      const matchesSearch =
        !query ||
        host.includes(query) ||
        agent.includes(query) ||
        server.includes(query) ||
        ide.includes(query)

      const matchesIde =
        ideFilter === 'all' || (s.ide_target && s.ide_target.toLowerCase().includes(ideFilter.toLowerCase()))

      const matchesWrap =
        wrapFilter === 'all' ||
        (wrapFilter === 'wrapped' && s.wrapped) ||
        (wrapFilter === 'unwrapped' && !s.wrapped)

      return matchesSearch && matchesIde && matchesWrap
    })
  }, [servers, searchQuery, ideFilter, wrapFilter])

  // Unique list of IDE targets for dropdown
  const availableIdes = useMemo(() => {
    const ides = new Set<string>()
    servers.forEach((s) => {
      if (s.ide_target) ides.add(s.ide_target)
    })
    return Array.from(ides)
  }, [servers])

  if (loading) return <div className="loading">Loading MCP servers...</div>

  return (
    <div className="soc-mcp-inventory">
      {/* Page Header */}
      <div className="page-header soc-page-header">
        <div>
          <h1>MCP Server Inventory (Admin)</h1>
          <p>Fleet-wide Model Context Protocol (MCP) server endpoints discovered, wrapped, and verified across connected IDE environments</p>
        </div>
        <div className="soc-header-controls">
          <button
            type="button"
            className="refresh-btn"
            onClick={fetchServers}
            title="Reload live MCP server inventory"
          >
            ↻ Refresh Inventory
          </button>
        </div>
      </div>

      {error && (
        <div className="ap-global-warning-banner" style={{ marginBottom: 24 }}>
          <div className="ap-global-warning-icon">⚠️</div>
          <div className="ap-global-warning-content">
            <strong>Inventory Sync Error</strong>
            <p>{error}</p>
          </div>
        </div>
      )}

      {/* KPI Summary Tiles */}
      <div className="stats-grid soc-stats-grid">
        <div className="card stat-tile">
          <div className="stat-header-row">
            <span className="stat-label">Total MCP Servers</span>
            <span className="soc-delta-badge delta-neutral">Discovered</span>
          </div>
          <div className="stat-value">{metrics.total}</div>
          <div className="stat-subtext">Active fleet endpoints</div>
        </div>

        <div className="card stat-tile">
          <div className="stat-header-row">
            <span className="stat-label">Wrapped by Proxy</span>
            <span className="soc-delta-badge delta-success">{metrics.wrappedPct}% Enforcing</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {metrics.wrapped} <span style={{ fontSize: 16, color: 'var(--text-muted)' }}>/ {metrics.total}</span>
          </div>
          <div className="stat-subtext">Zero-Trust Intercept Active</div>
        </div>

        <div className="card stat-tile">
          <div className="stat-header-row">
            <span className="stat-label">Path Verified</span>
            <span className="soc-delta-badge delta-success">{metrics.verifiedPct}% Verified</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {metrics.verified} <span style={{ fontSize: 16, color: 'var(--text-muted)' }}>/ {metrics.total}</span>
          </div>
          <div className="stat-subtext">Executable hash matched</div>
        </div>

        <div className="card stat-tile">
          <div className="stat-header-row">
            <span className="stat-label">Host Workstations</span>
            <span className="soc-delta-badge delta-neutral">{metrics.uniqueIdes} IDE Targets</span>
          </div>
          <div className="stat-value text-accent">{metrics.uniqueHosts}</div>
          <div className="stat-subtext">Connected Developer Nodes</div>
        </div>
      </div>

      {/* Main Table Card */}
      <div className="card soc-panel">
        <div className="soc-card-header" style={{ marginBottom: 20 }}>
          <div>
            <div className="card-title">Discovered MCP Endpoints</div>
            <div className="soc-card-subtitle">
              {filteredServers.length} of {servers.length} servers matching filter criteria
            </div>
          </div>

          {/* Search & Filter Bar */}
          <div className="soc-filter-bar">
            <div className="soc-filter-search-box">
              <span className="search-icon">🔍</span>
              <input
                type="text"
                className="soc-filter-input"
                placeholder="Filter by agent, host, server, or IDE..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              {searchQuery && (
                <button type="button" className="clear-search-btn" onClick={() => setSearchQuery('')}>
                  ×
                </button>
              )}
            </div>

            <select
              className="soc-select-filter"
              value={ideFilter}
              onChange={(e) => setIdeFilter(e.target.value)}
              aria-label="Filter by IDE Target"
            >
              <option value="all">All IDE Targets</option>
              {availableIdes.map((ide) => (
                <option key={ide} value={ide}>
                  {ide}
                </option>
              ))}
            </select>

            <select
              className="soc-select-filter"
              value={wrapFilter}
              onChange={(e) => setWrapFilter(e.target.value)}
              aria-label="Filter by Wrapped State"
            >
              <option value="all">All States</option>
              <option value="wrapped">Wrapped (Enforcing)</option>
              <option value="unwrapped">Unwrapped</option>
            </select>
          </div>
        </div>

        {/* Table View */}
        <div className="table-wrap">
          <table className="soc-table">
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Host Name</th>
                <th>IDE Target</th>
                <th>Server Name</th>
                <th>Wrapped</th>
                <th>Path Verified</th>
                <th>Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {filteredServers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="empty-state">
                    {servers.length === 0
                      ? 'No MCP servers found.'
                      : 'No MCP servers match the current search filters.'}
                  </td>
                </tr>
              ) : (
                filteredServers.map((s, i) => (
                  <tr key={`${s.agent_id}-${s.ide_target}-${s.server_name}-${i}`} className="soc-table-row">
                    <td className="font-mono text-mono-id">
                      {s.agent_id}
                    </td>
                    <td>
                      <span className="soc-host-badge font-mono">
                        {getHostname(s.agent_id)}
                      </span>
                    </td>
                    <td>
                      <span className={`soc-ide-pill ${getIdeBadgeClass(s.ide_target)}`}>
                        {s.ide_target || '-'}
                      </span>
                    </td>
                    <td>
                      <span className="soc-server-badge font-mono">
                        {s.server_name || '-'}
                      </span>
                    </td>
                    <td>
                      {s.server_name ? (
                        <span className={`badge ${s.wrapped ? 'badge-success' : 'badge-danger'}`}>
                          {s.wrapped ? '✓ Yes' : '✗ No'}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td>
                      {s.server_name ? (
                        <span className={`badge ${s.path_verified ? 'badge-success' : 'badge-danger'}`}>
                          {s.path_verified ? '✓ Yes' : '✗ No'}
                        </span>
                      ) : (
                        '-'
                      )}
                    </td>
                    <td className="soc-timestamp-cell font-mono">
                      {new Date(s.last_seen_at).toLocaleString([], {
                        year: 'numeric',
                        month: 'numeric',
                        day: 'numeric',
                        hour: 'numeric',
                        minute: '2-digit',
                        second: '2-digit',
                      })}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
