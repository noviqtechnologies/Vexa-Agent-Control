import { useState, useEffect } from 'react'
import { api, type SpendBudget, type GroupPolicy, type AgentSummary } from '../api/client'

export default function SpendLimits() {
  const [budgets, setBudgets] = useState<SpendBudget[]>([])
  const [groups, setGroups] = useState<string[]>([])
  const [agents, setAgents] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  
  // Form State
  const [scope, setScope] = useState('group')
  const [targetId, setTargetId] = useState('')
  const [customTargetId, setCustomTargetId] = useState('')
  const [period, setPeriod] = useState('daily')
  const [limit, setLimit] = useState('1.00')
  const [submitting, setSubmitting] = useState(false)
  const [message, setMessage] = useState<{type: 'success'|'error', text: string} | null>(null)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [resBudgets, resGroups, resAgents] = await Promise.allSettled([
        api.listBudgets(),
        api.listGroupPolicies(),
        api.listAgents()
      ])

      if (resBudgets.status === 'fulfilled') {
        setBudgets(resBudgets.value || [])
      }

      if (resGroups.status === 'fulfilled') {
        const data: any = resGroups.value
        const list: GroupPolicy[] = Array.isArray(data) ? data : (data?.policies || [])
        const groupIds = list.map(g => g.group_id)
        setGroups(groupIds)
        if (groupIds.length > 0) {
          setTargetId(groupIds[0])
        } else {
          setTargetId('custom')
        }
      }

      if (resAgents.status === 'fulfilled') {
        const list: AgentSummary[] = resAgents.value || []
        const agentIds = list.map(a => a.agent_id)
        setAgents(agentIds)
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleScopeChange = (newScope: string) => {
    setScope(newScope)
    setCustomTargetId('')
    if (newScope === 'group') {
      setTargetId(groups.length > 0 ? groups[0] : 'custom')
    } else if (newScope === 'user') {
      setTargetId(agents.length > 0 ? agents[0] : 'custom')
    } else if (newScope === 'organization') {
      setTargetId('global')
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const finalTargetId = targetId === 'custom' ? customTargetId : targetId
    if (!finalTargetId || !limit) return
    
    setSubmitting(true)
    setMessage(null)
    try {
      await api.createBudget({
        scope_type: scope,
        scope_key: finalTargetId,
        period,
        cap_cents: Math.round(parseFloat(limit) * 100)
      })
      setMessage({ type: 'success', text: 'Budget created successfully' })
      setCustomTargetId('')
      setLimit('1.00')
      fetchData()
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h1>Spend Limits</h1>
        <p>Configure hierarchical spend limits for organizations, groups, and individual agents.</p>
      </div>

      <div className="card" style={{ padding: 24, marginBottom: 24 }}>
        <h3 style={{ marginBottom: 16, fontSize: 16 }}>Create New Limit</h3>
        
        {message && (
          <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
            {message.text}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 150 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>SCOPE</label>
            <select value={scope} onChange={e => handleScopeChange(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
              <option value="group" style={{ background: '#12121a', color: '#e8e8ed' }}>Group</option>
              <option value="organization" style={{ background: '#12121a', color: '#e8e8ed' }}>Organization</option>
              <option value="user" style={{ background: '#12121a', color: '#e8e8ed' }}>Agent / User</option>
            </select>
          </div>
          
          <div style={{ flex: 2, minWidth: 220 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>TARGET ID</label>
            
            {scope === 'group' ? (
              <div style={{ display: 'flex', gap: 8 }}>
                <select value={targetId} onChange={e => setTargetId(e.target.value)} style={{ flex: 1, padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
                  {groups.map(g => (
                    <option key={g} value={g} style={{ background: '#12121a', color: '#e8e8ed' }}>{g}</option>
                  ))}
                  <option value="custom" style={{ background: '#12121a', color: '#e8e8ed' }}>+ Custom Group ID...</option>
                </select>
                {targetId === 'custom' && (
                  <input type="text" value={customTargetId} onChange={e => setCustomTargetId(e.target.value)} placeholder="e.g. engineering" required style={{ flex: 1, padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
                )}
              </div>
            ) : scope === 'user' ? (
              <div style={{ display: 'flex', gap: 8 }}>
                <select value={targetId} onChange={e => setTargetId(e.target.value)} style={{ flex: 1, padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
                  {agents.map(a => (
                    <option key={a} value={a} style={{ background: '#12121a', color: '#e8e8ed' }}>{a}</option>
                  ))}
                  <option value="custom" style={{ background: '#12121a', color: '#e8e8ed' }}>+ Custom Agent ID...</option>
                </select>
                {targetId === 'custom' && (
                  <input type="text" value={customTargetId} onChange={e => setCustomTargetId(e.target.value)} placeholder="e.g. agent-123" required style={{ flex: 1, padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
                )}
              </div>
            ) : (
              <input type="text" value={targetId} onChange={e => setTargetId(e.target.value)} placeholder="global" required style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
            )}
          </div>

          <div style={{ flex: 1, minWidth: 150 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>PERIOD</label>
            <select value={period} onChange={e => setPeriod(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
              <option value="daily" style={{ background: '#12121a', color: '#e8e8ed' }}>Daily</option>
              <option value="monthly" style={{ background: '#12121a', color: '#e8e8ed' }}>Monthly</option>
              <option value="all_time" style={{ background: '#12121a', color: '#e8e8ed' }}>All Time</option>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: 150 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>LIMIT (USD)</label>
            <input type="number" step="0.01" value={limit} onChange={e => setLimit(e.target.value)} min="0.01" required style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
          </div>

          <button type="submit" className="btn-primary" disabled={submitting} style={{ padding: '10px 24px', height: 41 }}>
            {submitting ? 'Saving...' : 'Add Limit'}
          </button>
        </form>
      </div>

      <div className="card">
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: 16, margin: 0 }}>Active Budgets</h3>
        </div>
        {loading ? (
          <div className="loading">Loading budgets...</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Scope</th>
                  <th>Target ID</th>
                  <th>Period</th>
                  <th>Limit (USD)</th>
                  <th>Created At</th>
                </tr>
              </thead>
              <tbody>
                {budgets.length === 0 && (
                  <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No budgets configured.</td></tr>
                )}
                {budgets.map((b, idx) => (
                  <tr key={idx}>
                    <td><span className="badge badge-info">{b.scope_type}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{b.scope_key}</td>
                    <td>{b.period}</td>
                    <td><strong style={{ color: 'var(--warning)' }}>${(b.cap_cents / 100).toFixed(2)}</strong></td>
                    <td style={{ color: 'var(--text-muted)' }}>{b.updated_at ? new Date(b.updated_at).toLocaleString() : '—'}</td>
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
