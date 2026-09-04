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
    <div className="soc-spend-limits-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Spend Policy Governance</h1>
          <p>Define authoritative PostgreSQL spend policies with preflight bounded reservation limits and hard fail-closed enforcement.</p>
        </div>
      </div>

      {licenseNotAvailable && (
        <div className="card soc-panel" style={{ padding: 20, marginBottom: 24, border: '1px solid rgba(245, 158, 11, 0.4)', background: 'rgba(245, 158, 11, 0.08)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 24 }}>🛡️</span>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, color: '#f59e0b' }}>Team or Enterprise Feature</h3>
              <p style={{ margin: '4px 0 0', fontSize: 13, color: 'var(--text-muted)' }}>{licenseNotAvailable}</p>
            </div>
          </div>
        </div>
      )}

      <div className="card soc-panel" style={{ marginBottom: 24 }}>
        <div className="soc-card-header">
          <div>
            <div className="card-title">Publish New Spend Policy</div>
            <div className="soc-card-subtitle">Set preflight budget ceilings with hard 429 denial or passive observation</div>
          </div>
        </div>
        
        {message && (
          <div style={{ padding: '10px 14px', borderRadius: 'var(--radius-sm)', marginBottom: 20, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)', fontSize: 13 }}>
            {message.text}
          </div>
        )}

        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 16, alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 150 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>SCOPE</label>
            <select value={scope} onChange={e => setScope(e.target.value)} className="soc-select-filter" style={{ width: '100%', padding: '10px 12px' }}>
              <option value="organization">Organization (Global)</option>
              <option value="project">Project / Workload</option>
              <option value="provider">LLM Provider</option>
            </select>
          </div>
          
          {scope === 'project' && (
            <div style={{ flex: 2, minWidth: 180 }}>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>PROJECT / SCOPE ID</label>
              <input type="text" value={targetId} onChange={e => setTargetId(e.target.value)} placeholder="e.g. customer-support" required className="soc-filter-input" style={{ width: '100%', padding: '10px 12px' }} />
            </div>
          )}

          {scope === 'provider' && (
            <div style={{ flex: 2, minWidth: 180 }}>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>LLM PROVIDER</label>
              <select value={providerChoice} onChange={e => setProviderChoice(e.target.value)} className="soc-select-filter" style={{ width: '100%', padding: '10px 12px' }}>
                <option value="openai">OpenAI</option>
                <option value="anthropic">Anthropic</option>
                <option value="google">Google Gemini</option>
              </select>
            </div>
          )}

          <div style={{ flex: 1, minWidth: 120 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>PERIOD</label>
            <select value={period} onChange={e => setPeriod(e.target.value)} className="soc-select-filter" style={{ width: '100%', padding: '10px 12px' }}>
              <option value="daily">Daily</option>
              <option value="monthly">Monthly</option>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: 130 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>ACTION</label>
            <select value={action} onChange={e => setAction(e.target.value)} className="soc-select-filter" style={{ width: '100%', padding: '10px 12px' }}>
              <option value="hard_deny">Hard Deny (429)</option>
              <option value="warn">Warn / Observe</option>
            </select>
          </div>

          <div style={{ flex: 1, minWidth: 130 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>LIMIT (USD)</label>
            <input type="number" step="0.01" value={limit} onChange={e => setLimit(e.target.value)} min="0.01" required className="soc-filter-input" style={{ width: '100%', padding: '10px 12px' }} />
          </div>

          <button type="submit" className="soc-btn-primary" disabled={submitting} style={{ padding: '10px 22px', height: 42 }}>
            {submitting ? 'Publishing...' : 'Publish Policy'}
          </button>
        </form>
      </div>

      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Published Spend Policies</div>
            <div className="soc-card-subtitle">{policies.length} active budget allocation rules enforced across workloads</div>
          </div>
          <span className="soc-badge">{policies.length} Rules</span>
        </div>
        {loading ? (
          <div className="loading">Loading policies...</div>
        ) : (
          <div className="table-wrap">
            <table className="soc-table">
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
                {policies.length === 0 ? (
                  <tr><td colSpan={7} className="empty-state">No policies configured.</td></tr>
                ) : (
                  policies.map((p, idx) => (
                    <tr key={idx} className="soc-table-row">
                      <td><span className="badge badge-info">{p.scope_type}</span></td>
                      <td style={{ fontFamily: 'var(--font-mono)' }} className="text-mono-id">{formatScopeLabel(p.scope_type, p.scope_id, user?.tenant_id)}</td>
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
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
