import { useState, useEffect } from 'react'
import { api } from '../../api/client'

export default function DeletedTeamsTab() {
  const [teams, setTeams] = useState<any[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    loadDeletedTeams()
  }, [])

  const loadDeletedTeams = async () => {
    setLoading(true)
    try {
      const res = await api.listDeletedTeams()
      setTeams(res.deleted_teams || [])
    } catch {
      setTeams([])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="obs-deleted-teams-tab">
      <div className="obs-compliance-banner">
        <div className="obs-compliance-icon">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
            <circle cx="9" cy="7" r="4" />
            <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
            <path d="M16 3.13a4 4 0 0 1 0 7.75" />
          </svg>
        </div>
        <div className="obs-compliance-text">
          <strong>Enterprise Team Governance</strong>
          <p>Historical records of decommissioned teams and projects for multi-tenant budget auditing.</p>
        </div>
      </div>

      <div className="obs-table-container">
        {loading ? (
          <div className="obs-empty-state">
            <div className="obs-spinner" />
            <p>Loading deleted teams...</p>
          </div>
        ) : teams.length === 0 ? (
          <div className="obs-empty-state">
            <div className="obs-empty-icon">
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                <circle cx="9" cy="7" r="4" />
              </svg>
            </div>
            <h3>No deleted teams found</h3>
            <p>Teams deleted from this tenant will be archived here for compliance records.</p>
          </div>
        ) : (
          <table className="obs-table">
            <thead>
              <tr>
                <th>Team ID</th>
                <th>Team Name</th>
                <th>Deleted By</th>
                <th>Deleted At</th>
              </tr>
            </thead>
            <tbody>
              {teams.map((t) => (
                <tr key={t.id} className="obs-table-row">
                  <td className="obs-col-mono">{t.id}</td>
                  <td>{t.name}</td>
                  <td>{t.deleted_by || 'admin'}</td>
                  <td className="obs-col-time">{t.deleted_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
