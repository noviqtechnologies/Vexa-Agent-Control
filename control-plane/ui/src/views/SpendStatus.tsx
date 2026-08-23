import { useState, useEffect } from 'react'
import { api, type BudgetWindowV2, type SpendEventV2 } from '../api/client'
import { useAuth } from '../auth/AuthContext'

function microcentsToUSD(microcents: number): string {
  return (microcents / 100_000_000).toFixed(4)
}

function formatScopeLabel(scopeType: string, scopeId: string, tenantId?: string): string {
  if (scopeType === 'organization' || scopeId === '00000000-0000-0000-0000-000000000001' || scopeId === 'global' || (tenantId && scopeId === tenantId)) {
    return 'Organization (Global Fleet)'
  }
  if (scopeType === 'project') {
    return `Project: ${scopeId}`
  }
  return `${scopeType}: ${scopeId}`
}

export default function SpendStatus() {
  const { user } = useAuth()
  const [windows, setWindows] = useState<BudgetWindowV2[]>([])
  const [events, setEvents] = useState<SpendEventV2[]>([])
  const [loading, setLoading] = useState(true)
  
  const [reqAmount, setReqAmount] = useState('')
  const [reqReason, setReqReason] = useState('')
  const [reqProject, setReqProject] = useState('default')
  const [submitting, setSubmitting] = useState(false)
  const [message, setMessage] = useState<{type: 'success'|'error', text: string} | null>(null)

  useEffect(() => {
    fetchStatus()
  }, [])

  const fetchStatus = async () => {
    setLoading(true)
    try {
      const [winRes, evRes] = await Promise.allSettled([
        api.getEffectiveSpendV2(),
        api.listSpendEventsV2(20)
      ])

      if (winRes.status === 'fulfilled') {
        setWindows(winRes.value.windows || [])
      }
      if (evRes.status === 'fulfilled') {
        setEvents(evRes.value.events || [])
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleSubmitRequest = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!reqAmount || !reqReason) return
    
    setSubmitting(true)
    setMessage(null)
    try {
      await api.createIncreaseRequestV2({
        project_id: reqProject || 'default',
        requested_limit_usd: parseFloat(reqAmount),
        current_limit_microcents: 0,
        reason: reqReason
      })
      setMessage({ type: 'success', text: 'Budget increase request submitted successfully and queued for administrative review.' })
      setReqAmount('')
      setReqReason('')
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Authoritative Spend Status</h1>
        <p>Real-time PostgreSQL budget enforcement, active preflight reservations, and immutable settlement events.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, alignItems: 'flex-start', marginBottom: 24 }}>
        
        {/* Active Budget Windows */}
        <div className="card" style={{ padding: 24 }}>
          <h3 style={{ marginBottom: 20 }}>Active Budget Windows</h3>
          {loading ? (
            <div className="loading" style={{ height: 100 }}>Loading budgets...</div>
          ) : windows.length === 0 ? (
            <p style={{ color: 'var(--text-muted)' }}>No active budget windows currently active.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              {windows.map((w, idx) => {
                const totalUsed = w.settled_microcents + w.reserved_microcents
                const percent = Math.min(100, Math.max(0, (totalUsed / (w.limit_microcents || 1)) * 100))
                const exhausted = totalUsed >= w.limit_microcents
                
                return (
                  <div key={idx} style={{ padding: 16, background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                      <div>
                        <strong style={{ fontSize: 14 }}>{formatScopeLabel(w.scope_type, w.scope_id, user?.tenant_id)}</strong>
                        <span style={{ fontSize: 11, marginLeft: 8, color: 'var(--text-muted)' }}>
                          Resets: {new Date(w.window_end).toLocaleDateString()}
                        </span>
                      </div>
                      <span style={{ fontSize: 13, fontWeight: 600, color: exhausted ? 'var(--danger)' : 'var(--text-main)' }}>
                        ${microcentsToUSD(totalUsed)} / ${microcentsToUSD(w.limit_microcents)}
                      </span>
                    </div>

                    <div style={{ height: 10, background: 'rgba(255,255,255,0.1)', borderRadius: 5, overflow: 'hidden', marginBottom: 12 }}>
                      <div style={{ 
                        height: '100%', 
                        width: `${percent}%`, 
                        background: exhausted ? 'var(--danger)' : (percent > 80 ? 'var(--warning)' : 'var(--success)'),
                        transition: 'width 0.5s ease'
                      }} />
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)' }}>
                      <span>Settled: <strong style={{ color: '#fff' }}>${microcentsToUSD(w.settled_microcents)}</strong></span>
                      <span>Reserved: <strong style={{ color: 'var(--warning)' }}>${microcentsToUSD(w.reserved_microcents)}</strong></span>
                      <span>Available: <strong style={{ color: 'var(--success)' }}>${microcentsToUSD(w.available_microcents)}</strong></span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Increase Request Form */}
        <div className="card" style={{ padding: 24 }}>
          <h3 style={{ marginBottom: 20 }}>Submit Increase Request</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 20 }}>
            If your project is approaching budget limits, submit an authorized increase request for admin review.
          </p>
          
          {message && (
            <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
              {message.text}
            </div>
          )}

          <form onSubmit={handleSubmitRequest} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>PROJECT / SCOPE ID</label>
              <input type="text" value={reqProject} onChange={e => setReqProject(e.target.value)} required style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>REQUESTED NEW CAP (USD)</label>
              <input type="number" step="0.01" value={reqAmount} onChange={e => setReqAmount(e.target.value)} min="1" required placeholder="e.g. 50.00" style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>BUSINESS JUSTIFICATION</label>
              <textarea value={reqReason} onChange={e => setReqReason(e.target.value)} required rows={3} placeholder="Describe the workload requirements..." style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff', resize: 'none' }} />
            </div>
            
            <button type="submit" className="btn-primary" disabled={submitting}>
              {submitting ? 'Submitting...' : 'Submit Request'}
            </button>
          </form>
        </div>

      </div>

      {/* Immutable Financial Transition Log */}
      <div className="card">
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: 16, margin: 0 }}>Immutable Spend Event Log</h3>
        </div>
        {loading ? (
          <div className="loading">Loading events...</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Type</th>
                  <th>Amount (USD)</th>
                  <th>Actor / Gateway</th>
                  <th>Reason / Status</th>
                  <th>Occurred At</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No spend events recorded.</td></tr>
                )}
                {events.map((e, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.event_id.substring(0, 8)}...</td>
                    <td>
                      <span className={`badge ${e.event_type === 'SETTLED' ? 'badge-success' : e.event_type === 'AUTHORIZED' ? 'badge-warning' : 'badge-info'}`}>
                        {e.event_type}
                      </span>
                    </td>
                    <td><strong style={{ color: 'var(--warning)' }}>${microcentsToUSD(e.amount_microcents)}</strong></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.actor}</td>
                    <td>{e.reason_code}</td>
                    <td style={{ color: 'var(--text-muted)' }}>{new Date(e.occurred_at).toLocaleString()}</td>
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
