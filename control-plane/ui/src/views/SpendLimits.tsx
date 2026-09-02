import { useState, useEffect } from 'react'
import { api, type SpendPolicyV2 } from '../api/client'
import { useAuth } from '../auth/AuthContext'

function microcentsToUSD(microcents: number): string {
  return (microcents / 100_000_000).toFixed(2)
}

function formatScopeLabel(scopeType: string, scopeId: string, tenantId?: string): string {
  if (scopeType === 'organization' || scopeId === '00000000-0000-0000-0000-000000000001' || scopeId === 'global' || (tenantId && scopeId === tenantId)) {
    return 'Global Fleet'
  }
  if (scopeType === 'provider') {
    return `Provider: ${scopeId.toUpperCase()}`
  }
  return scopeId
}

export default function SpendLimits() {
  const { user } = useAuth()
  const [policies, setPolicies] = useState<SpendPolicyV2[]>([])
  const [loading, setLoading] = useState(true)
  
  // Form State
  const [scope, setScope] = useState('organization')
  const [targetId, setTargetId] = useState('')
  const [providerChoice, setProviderChoice] = useState('openai')
  const [period, setPeriod] = useState('monthly')
  const [limit, setLimit] = useState('100.00')
  const [action, setAction] = useState('hard_deny')
  const [submitting, setSubmitting] = useState(false)
  const [message, setMessage] = useState<{type: 'success'|'error', text: string} | null>(null)

  const [licenseNotAvailable, setLicenseNotAvailable] = useState<string | null>(null)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    setLicenseNotAvailable(null)
    try {
      const res = await api.listSpendPoliciesV2()
      setPolicies(res.policies || [])
    } catch (e: any) {
      if (e.status === 403 || (e.message && e.message.includes('license'))) {
        setLicenseNotAvailable(e.message || 'Spend Caps & Policies require a Team or Enterprise license tier.')
      } else {
        console.error(e)
      }
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    let scopeId = 'global'
    if (scope === 'organization') {
      scopeId = user?.tenant_id || 'global'
    } else if (scope === 'provider') {
      scopeId = providerChoice.toLowerCase()
    } else {
      scopeId = targetId || 'default'
    }

    if (!limit) return
    
    setSubmitting(true)
    setMessage(null)
    try {
      await api.createSpendPolicyV2({
        scope_type: scope,
        scope_id: scopeId,
        period_type: period,
        limit_usd: parseFloat(limit),
        action: action
      })
      setMessage({ type: 'success', text: `Authoritative ${scope.toUpperCase()} spend policy published successfully` })
      setTargetId('')
      setLimit('100.00')
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
        <h1>Spend Policy Governance</h1>
        <p>Define authoritative PostgreSQL spend policies with preflight bounded reservation limits and hard fail-closed enforcement.</p>
      </div>

      {licenseNotAvailable && (
        <div className="card" style={{ padding: 20, marginBottom: 24, border: '1px solid rgba(245, 158, 11, 0.4)', background: 'rgba(245, 158, 11, 0.08)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 24 }}>🛡️</span>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: '#f59e0b' }}>Team or Enterprise Feature</h3>
              <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--text-muted)' }}>{licenseNotAvailable}</p>
            </div>
          </div>
        </div>
      )}

      <div className="card" style={{ padding: 24, marginBottom: 24 }}>
        <h3 style={{ marginBottom: 16, fontSize: 16 }}>Publish New Spend Policy</h3>
        
        {message && (
          <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
            {message.text}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 150 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>SCOPE</label>
            <select value={scope} onChange={e => setScope(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
              <option value="organization" style={{ background: '#12121a', color: '#e8e8ed' }}>Organization (Global)</option>
              <option value="project" style={{ background: '#12121a', color: '#e8e8ed' }}>Project / Workload</option>
              <option value="provider" style={{ background: '#12121a', color: '#e8e8ed' }}>LLM Provider</option>
            </select>
          </div>
          
          {scope === 'project' && (
            <div style={{ flex: 2, minWidth: 180 }}>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>PROJECT / SCOPE ID</label>
              <input type="text" value={targetId} onChange={e => setTargetId(e.target.value)} placeholder="e.g. customer-support" required style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
            </div>
          )}

          {scope === 'provider' && (
            <div style={{ flex: 2, minWidth: 180 }}>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>LLM PROVIDER</label>
              <select value={providerChoice} onChange={e => setProviderChoice(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
                <option value="openai" style={{ background: '#12121a', color: '#e8e8ed' }}>OpenAI</option>
                <option value="anthropic" style={{ background: '#12121a', color: '#e8e8ed' }}>Anthropic</option>
                <option value="google" style={{ background: '#12121a', color: '#e8e8ed' }}>Google Gemini</option>
              </select>
            </div>
          )}

          <div style={{ flex: 1, minWidth: 120 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>PERIOD</label>
            <select value={period} onChange={e => setPeriod(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
              <option value="daily" style={{ background: '#12121a', color: '#e8e8ed' }}>Daily</option>
              <option value="monthly" style={{ background: '#12121a', color: '#e8e8ed' }}>Monthly</option>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: 130 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>ACTION</label>
            <select value={action} onChange={e => setAction(e.target.value)} style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}>
              <option value="hard_deny" style={{ background: '#12121a', color: '#e8e8ed' }}>Hard Deny (429)</option>
              <option value="warn" style={{ background: '#12121a', color: '#e8e8ed' }}>Warn / Observe</option>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: 130 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>LIMIT (USD)</label>
            <input type="number" step="0.01" value={limit} onChange={e => setLimit(e.target.value)} min="0.01" required style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }} />
          </div>

          <button type="submit" className="btn-primary" disabled={submitting} style={{ padding: '10px 24px', height: 41 }}>
            {submitting ? 'Publishing...' : 'Publish Policy'}
          </button>
        </form>
      </div>

      <div className="card">
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: 16, margin: 0 }}>Published Spend Policies</h3>
        </div>
        {loading ? (
          <div className="loading">Loading policies...</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Scope</th>
                  <th>Scope ID</th>
                  <th>Period</th>
                  <th>Action</th>
                  <th>Limit (USD)</th>
                  <th>Status</th>
                  <th>Last Updated</th>
                </tr>
              </thead>
              <tbody>
                {policies.length === 0 && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No policies configured.</td></tr>
                )}
                {policies.map((p, idx) => (
                  <tr key={idx}>
                    <td><span className="badge badge-info">{p.scope_type}</span></td>
                    <td style={{ fontFamily: 'var(--font-mono)' }}>{formatScopeLabel(p.scope_type, p.scope_id, user?.tenant_id)}</td>
                    <td>{p.period_type}</td>
                    <td>
                      <span className={`badge ${p.action === 'hard_deny' ? 'badge-danger' : 'badge-warning'}`}>
                        {p.action}
                      </span>
                    </td>
                    <td><strong style={{ color: 'var(--warning)' }}>${microcentsToUSD(p.limit_microcents)}</strong></td>
                    <td><span className="badge badge-success">{p.status}</span></td>
                    <td style={{ color: 'var(--text-muted)' }}>{p.updated_at ? new Date(p.updated_at).toLocaleString() : '—'}</td>
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
