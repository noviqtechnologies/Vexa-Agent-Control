import { useState, useEffect } from 'react'
import { api, type IncreaseRequestV2 } from '../api/client'

function microcentsToUSD(microcents: number): string {
  return (microcents / 100_000_000).toFixed(2)
}

export default function IncreaseRequests() {
  const [requests, setRequests] = useState<IncreaseRequestV2[]>([])
  const [loading, setLoading] = useState(true)
  const [resolvingId, setResolvingId] = useState<string | null>(null)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  useEffect(() => {
    fetchRequests()
  }, [])

  const fetchRequests = async () => {
    setLoading(true)
    try {
      const res = await api.listIncreaseRequestsV2()
      setRequests(res.requests || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleResolve = async (id: string, decision: 'APPROVED' | 'REJECTED') => {
    setResolvingId(id)
    setMessage(null)
    try {
      await api.decideIncreaseRequestV2(id, decision, `Resolved by admin as ${decision}`)
      setMessage({ type: 'success', text: `Request ${id.substring(0, 8)}... successfully ${decision.toLowerCase()}` })
      fetchRequests()
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setResolvingId(null)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Spend Limit Increase Requests</h1>
        <p>Review and decide budget increase requests from project workloads with automatic PostgreSQL policy updates.</p>
      </div>

      {message && (
        <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
          {message.text}
        </div>
      )}

      <div className="card">
        {loading ? (
          <div className="loading">Loading requests...</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Request ID</th>
                  <th>Project / Scope</th>
                  <th>Requested Cap (USD)</th>
                  <th>Business Justification</th>
                  <th>Submitted By</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {requests.length === 0 && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No increase requests found.</td></tr>
                )}
                {requests.map(r => (
                  <tr key={r.request_id}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{r.request_id.substring(0, 8)}...</td>
                    <td><strong style={{ fontFamily: 'var(--font-mono)' }}>{r.project_id}</strong></td>
                    <td><strong style={{ color: 'var(--warning)' }}>${microcentsToUSD(r.requested_limit_microcents)}</strong></td>
                    <td style={{ maxWidth: 300, fontSize: 13 }}>{r.reason}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{r.created_by}</td>
                    <td>
                      <span className={`badge ${r.status === 'APPROVED' ? 'badge-success' : r.status === 'REJECTED' ? 'badge-danger' : 'badge-warning'}`}>
                        {r.status}
                      </span>
                    </td>
                    <td>
                      {r.status === 'PENDING' ? (
                        <div style={{ display: 'flex', gap: 8 }}>
                          <button 
                            className="btn-primary" 
                            disabled={resolvingId === r.request_id}
                            onClick={() => handleResolve(r.request_id, 'APPROVED')}
                            style={{ padding: '6px 12px', fontSize: 12 }}
                          >
                            Approve
                          </button>
                          <button 
                            className="btn-secondary" 
                            disabled={resolvingId === r.request_id}
                            onClick={() => handleResolve(r.request_id, 'REJECTED')}
                            style={{ padding: '6px 12px', fontSize: 12 }}
                          >
                            Reject
                          </button>
                        </div>
                      ) : (
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                          Decided by {r.decided_by || 'admin'}
                        </span>
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
