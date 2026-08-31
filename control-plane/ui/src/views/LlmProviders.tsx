import { useEffect, useState } from 'react'
import './Users.css'
import { api, type SpendPolicyV2, type BudgetWindowV2 } from '../api/client'

interface ProviderKey {
  id: string
  provider: string
  api_key_masked: string
  created_at: string
}

function microcentsToUSD(microcents: number): number {
  return microcents / 100_000_000
}

export default function LlmProviders() {
  const [keys, setKeys] = useState<ProviderKey[]>([])
  const [policies, setPolicies] = useState<SpendPolicyV2[]>([])
  const [windows, setWindows] = useState<BudgetWindowV2[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)
  
  // Form State
  const [provider, setProvider] = useState('openai')
  const [apiKey, setApiKey] = useState('')
  const [initialSpendLimit, setInitialSpendLimit] = useState('')
  const [saving, setSaving] = useState(false)

  // Edit Limit Modal State
  const [editingProvider, setEditingProvider] = useState<string | null>(null)
  const [editLimitVal, setEditLimitVal] = useState('')
  const [savingLimit, setSavingLimit] = useState(false)

  const fetchData = async () => {
    try {
      setLoading(true)
      const [keysRes, polRes, statusRes] = await Promise.all([
        fetch('/api/v1/providers/keys').then(r => r.ok ? r.json() : []),
        api.listSpendPoliciesV2().then(r => r.policies || []).catch(() => []),
        api.getEffectiveSpendV2().then(r => r.windows || []).catch(() => [])
      ])
      setKeys(keysRes || [])
      setPolicies(polRes || [])
      setWindows(statusRes || [])
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setError(null)
    setSuccessMsg(null)
    try {
      const res = await fetch('/api/v1/providers/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ provider, api_key: apiKey }),
      })
      if (!res.ok) {
        const errData = await res.json()
        throw new Error(errData.error || 'Failed to save key')
      }

      // If initial spend limit specified, create & publish provider spend policy
      if (initialSpendLimit && parseFloat(initialSpendLimit) > 0) {
        await api.createSpendPolicyV2({
          scope_type: 'provider',
          scope_id: provider.toLowerCase(),
          period_type: 'monthly',
          limit_usd: parseFloat(initialSpendLimit),
          action: 'hard_deny'
        })
      }

      setApiKey('')
      setInitialSpendLimit('')
      setSuccessMsg(`Configured API key and governance for ${provider.toUpperCase()}`)
      await fetchData()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setSaving(false)
    }
  }
  
  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this key?')) return
    try {
      const res = await fetch(`/api/v1/providers/keys/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete key')
      await fetchData()
    } catch (err: any) {
      setError(err.message)
    }
  }

  const handleSaveLimit = async () => {
    if (!editingProvider || !editLimitVal) return
    setSavingLimit(true)
    setError(null)
    try {
      await api.createSpendPolicyV2({
        scope_type: 'provider',
        scope_id: editingProvider.toLowerCase(),
        period_type: 'monthly',
        limit_usd: parseFloat(editLimitVal),
        action: 'hard_deny'
      })
      setSuccessMsg(`Updated monthly spend limit for ${editingProvider.toUpperCase()} to $${parseFloat(editLimitVal).toFixed(2)}`)
      setEditingProvider(null)
      setEditLimitVal('')
      await fetchData()
    } catch (err: any) {
      setError(err.message)
    } finally {
      setSavingLimit(false)
    }
  }

  const getProviderPolicy = (providerName: string) => {
    return policies.find(p => p.scope_type === 'provider' && p.scope_id.toLowerCase() === providerName.toLowerCase())
  }

  const getProviderWindow = (providerName: string) => {
    return windows.find(w => w.scope_type === 'provider' && w.scope_id.toLowerCase() === providerName.toLowerCase())
  }

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">LLM Providers & Spend Governance</h1>
          <p className="view-subtitle">Manage centralized API keys and enforce provider-level spend budgets</p>
        </div>
      </div>

      {error && <div className="error-banner" style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: 'var(--danger-dim)', color: 'var(--danger)' }}>{error}</div>}
      {successMsg && <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: 'var(--success-dim)', color: 'var(--success)' }}>{successMsg}</div>}

      <div className="card glass mb-20" style={{ padding: '24px' }}>
        <h2 style={{ marginBottom: '16px', fontSize: '1.2rem' }}>Add Provider Key</h2>
        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '16px', alignItems: 'flex-end', flexWrap: 'wrap' }}>
          <div style={{ flex: 1, minWidth: 150 }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Provider</label>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="form-input"
              style={{ width: '100%', padding: '10px' }}
            >
              <option value="openai">OpenAI (Central Enforce & Local)</option>
              <option value="anthropic">Anthropic (Central Enforce & Local)</option>
              <option value="google">Google Gemini (Central Enforce & Local)</option>
            </select>
          </div>
          <div style={{ flex: 2, minWidth: 200 }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>API Key</label>
            <input
              type="password"
              className="form-input"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="sk-..."
              required
              style={{ width: '100%', padding: '10px' }}
            />
          </div>
          <div style={{ flex: 1, minWidth: 140 }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Monthly Spend Cap ($)</label>
            <input
              type="number"
              step="0.01"
              className="form-input"
              value={initialSpendLimit}
              onChange={(e) => setInitialSpendLimit(e.target.value)}
              placeholder="e.g. 100.00"
              style={{ width: '100%', padding: '10px' }}
            />
          </div>
          <button 
            type="submit" 
            className="btn btn-primary" 
            disabled={saving || !apiKey}
            style={{ padding: '10px 24px', height: '41px' }}
          >
            {saving ? 'Saving...' : 'Add Key'}
          </button>
        </form>
      </div>

      <div className="card glass">
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <h3 style={{ fontSize: 16, margin: 0 }}>Configured Provider Gateways</h3>
        </div>
        {loading ? (
          <div className="loading" style={{ padding: 24 }}>Loading provider keys & budgets...</div>
        ) : keys.length === 0 ? (
          <div className="empty-state" style={{ padding: 24 }}>No provider keys configured yet.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>API Key (Masked)</th>
                <th>Monthly Spend Limit</th>
                <th>Current Consumption</th>
                <th>Added</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => {
                const pol = getProviderPolicy(k.provider)
                const win = getProviderWindow(k.provider)
                const limitUSD = pol ? microcentsToUSD(pol.limit_microcents) : (win ? microcentsToUSD(win.limit_microcents) : null)
                const settledUSD = win ? microcentsToUSD(win.settled_microcents) : 0
                const reservedUSD = win ? microcentsToUSD(win.reserved_microcents) : 0
                const totalUsedUSD = settledUSD + reservedUSD
                const percent = limitUSD && limitUSD > 0 ? Math.min(100, (totalUsedUSD / limitUSD) * 100) : 0

                return (
                  <tr key={k.id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="badge" style={{ background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8', border: '1px solid rgba(99, 102, 241, 0.3)', fontWeight: 600, padding: '4px 10px', borderRadius: 6, textTransform: 'uppercase' }}>
                          {k.provider}
                        </span>
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono, monospace)', color: 'var(--text-muted)' }}>{k.api_key_masked}</td>
                    <td>
                      {limitUSD ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <strong style={{ color: 'var(--warning)', fontSize: 14 }}>${limitUSD.toFixed(2)}</strong>
                          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/ mo</span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>Uncapped</span>
                      )}
                    </td>
                    <td style={{ minWidth: 200 }}>
                      {limitUSD ? (
                        <div>
                          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, marginBottom: 4 }}>
                            <span>${totalUsedUSD.toFixed(2)} spent</span>
                            <span style={{ color: percent > 90 ? 'var(--danger)' : percent > 70 ? 'var(--warning)' : 'var(--success)' }}>
                              {percent.toFixed(1)}%
                            </span>
                          </div>
                          <div style={{ width: '100%', height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, overflow: 'hidden' }}>
                            <div
                              style={{
                                width: `${percent}%`,
                                height: '100%',
                                background: percent > 90 ? 'var(--danger)' : percent > 70 ? 'var(--warning)' : 'var(--success)',
                                transition: 'width 0.3s ease'
                              }}
                            />
                          </div>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>Inherits Global Org Budget</span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 13 }}>{new Date(k.created_at).toLocaleDateString()}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 8 }}>
                        <button 
                          className="btn btn-secondary btn-sm"
                          style={{ padding: '4px 10px', fontSize: 12 }}
                          onClick={() => {
                            setEditingProvider(k.provider)
                            setEditLimitVal(limitUSD ? limitUSD.toString() : '100.00')
                          }}
                        >
                          {limitUSD ? 'Edit Limit' : 'Set Limit'}
                        </button>
                        <button 
                          className="btn btn-danger btn-sm"
                          style={{ padding: '4px 10px', fontSize: 12 }}
                          onClick={() => handleDelete(k.id)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Edit Spend Limit Modal */}
      {editingProvider && (
        <div style={{
          position: 'fixed',
          top: 0, left: 0, right: 0, bottom: 0,
          background: 'rgba(0,0,0,0.7)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000
        }}>
          <div className="card" style={{ width: 420, padding: 24, background: '#13131f', border: '1px solid var(--border)' }}>
            <h3 style={{ margin: '0 0 12px 0', fontSize: 18 }}>
              Configure Spend Limit for <span style={{ textTransform: 'uppercase', color: 'var(--accent)' }}>{editingProvider}</span>
            </h3>
            <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20 }}>
              Set an authoritative monthly spend limit enforced before LLM requests are dispatched.
            </p>

            <div style={{ marginBottom: 20 }}>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>
                MONTHLY LIMIT (USD)
              </label>
              <input
                type="number"
                step="0.01"
                min="0.01"
                value={editLimitVal}
                onChange={e => setEditLimitVal(e.target.value)}
                placeholder="100.00"
                style={{ width: '100%', padding: '10px', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                className="btn btn-secondary"
                disabled={savingLimit}
                onClick={() => setEditingProvider(null)}
              >
                Cancel
              </button>
              <button
                className="btn btn-primary"
                disabled={savingLimit || !editLimitVal}
                onClick={handleSaveLimit}
              >
                {savingLimit ? 'Saving...' : 'Save Limit Policy'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
