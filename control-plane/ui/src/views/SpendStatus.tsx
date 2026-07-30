import { useState, useEffect } from 'react'
import { api, type SpendSnapshot } from '../api/client'

export default function SpendStatus() {
  const [snapshots, setSnapshots] = useState<SpendSnapshot[]>([])
  const [loading, setLoading] = useState(true)
  
  const [reqAmount, setReqAmount] = useState('')
  const [reqReason, setReqReason] = useState('')
  const [reqAgent, setReqAgent] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [message, setMessage] = useState<{type: 'success'|'error', text: string} | null>(null)

  useEffect(() => {
    fetchStatus()
  }, [])

  const fetchStatus = async () => {
    setLoading(true)
    try {
      const res = await api.listSnapshots()
      setSnapshots(res || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleSubmitRequest = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!reqAgent || !reqAmount || !reqReason) return
    
    setSubmitting(true)
    setMessage(null)
    try {
      await api.submitIncreaseRequest({
        agent_id: reqAgent,
        new_cap: Math.round(parseFloat(reqAmount) * 100),
        reason: reqReason
      })
      setMessage({ type: 'success', text: 'Increase request submitted successfully' })
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
        <h1>Spend Status</h1>
        <p>Agent self-service portal to view current spend against budget limits.</p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, alignItems: 'flex-start' }}>
        
        <div className="card" style={{ padding: 24 }}>
          <h3 style={{ marginBottom: 20 }}>Current Spend vs Limits</h3>
          {loading ? (
            <div className="loading" style={{ height: 100 }}>Loading...</div>
          ) : snapshots.length === 0 ? (
            <p style={{ color: 'var(--text-muted)' }}>No spend records found.</p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>
              {snapshots.map((s, idx) => {
                const limit = s.cap_cents || 1
                const spend = s.spent_cents
                const percent = Math.min(100, Math.max(0, (spend / limit) * 100))
                const exhausted = spend >= limit && s.cap_cents !== null
                
                return (
                  <div key={idx}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                      <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 14 }}>{s.agent_id}</strong>
                      <span style={{ fontSize: 13, color: exhausted ? 'var(--danger)' : 'var(--text-muted)' }}>
                        ${(spend / 100).toFixed(2)} / {s.cap_cents ? `$${(s.cap_cents / 100).toFixed(2)}` : '∞'}
                      </span>
                    </div>
                    <div style={{ height: 8, background: 'rgba(255,255,255,0.1)', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{ 
                        height: '100%', 
                        width: `${percent}%`, 
                        background: exhausted ? 'var(--danger)' : (percent > 80 ? 'var(--warning)' : 'var(--success)'),
                        transition: 'width 0.5s ease'
                      }} />
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="card" style={{ padding: 24 }}>
          <h3 style={{ marginBottom: 20 }}>Submit Increase Request</h3>
          <p style={{ color: 'var(--text-muted)', fontSize: 14, marginBottom: 20 }}>
            If your agent is hitting a limit, submit a request for an admin to review.
          </p>
          
          {message && (
            <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
              {message.text}
            </div>
          )}

          <form onSubmit={handleSubmitRequest} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>AGENT ID</label>
              <input type="text" value={reqAgent} onChange={e => setReqAgent(e.target.value)} required style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>REQUESTED LIMIT (USD)</label>
              <input type="number" step="0.01" value={reqAmount} onChange={e => setReqAmount(e.target.value)} min="1" required style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
            </div>
            <div>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>BUSINESS JUSTIFICATION</label>
              <textarea value={reqReason} onChange={e => setReqReason(e.target.value)} required rows={3} style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff', resize: 'none' }} />
            </div>
            
            <button type="submit" className="btn-primary" disabled={submitting}>
              {submitting ? 'Submitting...' : 'Submit Request'}
            </button>
          </form>
        </div>

      </div>
    </div>
  )
}
