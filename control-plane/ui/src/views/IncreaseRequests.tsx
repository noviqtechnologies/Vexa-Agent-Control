import { useState, useEffect } from 'react'
import { api, type IncreaseRequest } from '../api/client'

export default function IncreaseRequests() {
  const [requests, setRequests] = useState<IncreaseRequest[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchRequests()
  }, [])

  const fetchRequests = async () => {
    setLoading(true)
    try {
      const res = await api.listIncreaseRequests()
      setRequests(res || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleResolve = async (id: string, action: 'approve' | 'deny') => {
    try {
      await api.resolveIncreaseRequest(id, { action })
      fetchRequests()
    } catch (e: any) {
      alert(`Error: ${e.message}`)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Limit Increase Requests</h1>
        <p>Review and approve budget increase requests submitted by agents.</p>
      </div>

      <div className="card">
        {loading ? (
          <div className="loading">Loading requests...</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Request ID</th>
                  <th>Agent ID</th>
                  <th>Requested Cap (USD)</th>
                  <th>Reason</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {requests.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No increase requests found.</td></tr>
                )}
                {requests.map(r => (
                  <tr key={r.request_id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-muted)' }}>{r.request_id.slice(0,8)}...</td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{r.agent_id}</td>
                    <td><strong style={{ color: 'var(--warning)' }}>${((r.new_cap || 0) / 100).toFixed(2)}</strong></td>
                    <td style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={r.reason}>{r.reason}</td>
                    <td>
                      <span className={`badge ${r.status === 'pending' ? 'badge-warning' : r.status === 'approved' ? 'badge-success' : 'badge-danger'}`}>
                        {r.status}
                      </span>
                    </td>
                    <td>
                      {r.status === 'pending' && (
                        <div style={{ display: 'flex', gap: 8 }}>
                          <button 
                            onClick={() => handleResolve(r.request_id, 'approve')}
                            style={{ background: 'var(--success-dim)', color: 'var(--success)', border: '1px solid var(--success)', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}
                          >
                            Approve
                          </button>
                          <button 
                            onClick={() => handleResolve(r.request_id, 'deny')}
                            style={{ background: 'var(--danger-dim)', color: 'var(--danger)', border: '1px solid var(--danger)', borderRadius: 4, padding: '4px 8px', cursor: 'pointer', fontSize: 12, fontWeight: 600 }}
                          >
                            Deny
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
