import { useEffect, useState } from 'react'
import './Users.css' // Reusing basic table styles

interface McpServer {
  agent_id: string
  ide_target: string
  server_name: string
  wrapped: boolean
  path_verified: boolean
  last_seen_at: string
}

export default function McpServers() {
  const [servers, setServers] = useState<McpServer[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchServers = async () => {
      try {
        const res = await fetch('/api/v1/fleet/mcp-servers')
        if (!res.ok) {
          throw new Error('Failed to fetch MCP servers. You may not have permission.')
        }
        const data = await res.json()
        setServers(data || [])
      } catch (e: any) {
        setError(e.message)
      } finally {
        setLoading(false)
      }
    }
    fetchServers()
  }, [])

  if (loading) return <div className="loading">Loading MCP servers...</div>
  if (error) return <div className="error">{error}</div>

  return (
    <div className="users-container">
      <h2>MCP Server Inventory (Admin)</h2>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>IDE Target</th>
              <th>Server Name</th>
              <th>Wrapped</th>
              <th>Path Verified</th>
              <th>Last Seen</th>
            </tr>
          </thead>
          <tbody>
            {servers.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center' }}>No MCP servers found.</td>
              </tr>
            ) : (
              servers.map((s, i) => (
                <tr key={`${s.agent_id}-${s.ide_target}-${s.server_name}-${i}`}>
                  <td>{s.agent_id}</td>
                  <td>{s.ide_target || '-'}</td>
                  <td>{s.server_name || '-'}</td>
                  <td>
                    {s.server_name ? (
                      <span className={`status-badge ${s.wrapped ? 'active' : 'inactive'}`}>
                        {s.wrapped ? 'Yes' : 'No'}
                      </span>
                    ) : '-'}
                  </td>
                  <td>
                    {s.server_name ? (
                      <span className={`status-badge ${s.path_verified ? 'active' : 'inactive'}`}>
                        {s.path_verified ? 'Yes' : 'No'}
                      </span>
                    ) : '-'}
                  </td>
                  <td>{new Date(s.last_seen_at).toLocaleString()}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
