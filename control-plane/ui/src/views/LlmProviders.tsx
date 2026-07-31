import { useEffect, useState } from 'react'
import './Users.css' // Reusing basic table and form styles

interface ProviderKey {
  id: string
  provider: string
  api_key_masked: string
  created_at: string
}

export default function LlmProviders() {
  const [keys, setKeys] = useState<ProviderKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  
  // Form State
  const [provider, setProvider] = useState('openai')
  const [apiKey, setApiKey] = useState('')
  const [saving, setSaving] = useState(false)

  const fetchKeys = async () => {
    try {
      setLoading(true)
      const res = await fetch('/api/v1/providers/keys')
      if (!res.ok) {
        throw new Error('Failed to fetch provider keys')
      }
      const data = await res.json()
      setKeys(data || [])
    } catch (e: any) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchKeys()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSaving(true)
    setError(null)
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
      setApiKey('')
      await fetchKeys()
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
      await fetchKeys()
    } catch (err: any) {
      setError(err.message)
    }
  }

  return (
    <div className="view-container">
      <div className="view-header">
        <div>
          <h1 className="view-title">LLM Providers</h1>
          <p className="view-subtitle">Manage centralized API keys pushed to AgentWall Gateways</p>
        </div>
      </div>

      {error && <div className="error-banner">{error}</div>}

      <div className="card glass mb-20" style={{ padding: '24px' }}>
        <h2 style={{ marginBottom: '16px', fontSize: '1.2rem' }}>Add Provider Key</h2>
        <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '16px', alignItems: 'flex-end' }}>
          <div style={{ flex: 1 }}>
            <label style={{ display: 'block', marginBottom: '8px', fontSize: '0.9rem', color: 'var(--text-muted)' }}>Provider</label>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              className="form-input"
              style={{ width: '100%', padding: '10px' }}
            >
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="google">Google Gemini</option>
              <option value="xai">xAI</option>
            </select>
          </div>
          <div style={{ flex: 2 }}>
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
        {loading ? (
          <div className="loading">Loading provider keys...</div>
        ) : keys.length === 0 ? (
          <div className="empty-state">No provider keys configured yet.</div>
        ) : (
          <table className="data-table">
            <thead>
              <tr>
                <th>Provider</th>
                <th>API Key (Masked)</th>
                <th>Added</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {keys.map((k) => (
                <tr key={k.id}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span className="badge" style={{ background: 'var(--accent)', color: '#000' }}>
                        {k.provider}
                      </span>
                    </div>
                  </td>
                  <td style={{ fontFamily: 'monospace' }}>{k.api_key_masked}</td>
                  <td>{new Date(k.created_at).toLocaleString()}</td>
                  <td>
                    <button 
                      className="btn btn-danger btn-sm"
                      onClick={() => handleDelete(k.id)}
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
