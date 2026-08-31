import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, type EffectivePolicyResponse } from '../api/client'
import './EffectivePolicyExplorer.css'

function microcentsToUSD(microcents: number): number {
  return (microcents || 0) / 100_000_000
}

export default function EffectivePolicyExplorer() {
  const [searchParams, setSearchParams] = useSearchParams()

  const [deviceId, setDeviceId] = useState(searchParams.get('device_id') || '')
  const [agentId, setAgentId] = useState(searchParams.get('agent_id') || '')
  const [vkId, setVkId] = useState(searchParams.get('virtual_key_id') || '')
  const [projectId, setProjectId] = useState(searchParams.get('project_id') || 'default')
  const [provider, setProvider] = useState(searchParams.get('provider') || '')
  const [model, setModel] = useState(searchParams.get('model') || '')
  const [route, setRoute] = useState(searchParams.get('route') || '')
  const [atTime, setAtTime] = useState(searchParams.get('at') || '')

  const [response, setResponse] = useState<EffectivePolicyResponse | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    handleResolve()
  }, [])

  const handleResolve = async () => {
    setLoading(true)
    setError(null)
    const params: Record<string, string> = {}
    if (deviceId) params.device_id = deviceId
    if (agentId) params.agent_id = agentId
    if (vkId) params.virtual_key_id = vkId
    if (projectId) params.project_id = projectId
    if (provider) params.provider = provider
    if (model) params.model = model
    if (route) params.route = route
    if (atTime) params.at = atTime

    setSearchParams(params)

    try {
      const res = await api.getEffectivePolicy(params)
      setResponse(res)
    } catch (err: any) {
      setError(err.message || 'Failed to resolve policy')
    } finally {
      setLoading(false)
    }
  }

  const handleReset = () => {
    setDeviceId('')
    setAgentId('')
    setVkId('')
    setProjectId('default')
    setProvider('')
    setModel('')
    setRoute('')
    setAtTime('')
    setSearchParams({})
  }

  return (
    <div className="effective-policy-page">
      <div className="page-header">
        <div>
          <h1>Effective Policy Explorer</h1>
          <p>Deterministic multi-layer policy resolution across Organization, Group, Spend, Virtual-Key, and Device governance.</p>
        </div>
      </div>

      {/* Query Builder */}
      <div className="query-builder-card card">
        <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>Query Parameters</h3>
        <div className="query-grid">
          <div className="query-field">
            <label className="query-label" htmlFor="device-id-input">Device ID</label>
            <input
              id="device-id-input"
              className="query-input"
              placeholder="e.g. win-endpoint-1"
              value={deviceId}
              onChange={(e) => setDeviceId(e.target.value)}
            />
          </div>

          <div className="query-field">
            <label className="query-label" htmlFor="agent-id-input">Agent ID</label>
            <input
              id="agent-id-input"
              className="query-input"
              placeholder="e.g. agent-alpha"
              value={agentId}
              onChange={(e) => setAgentId(e.target.value)}
            />
          </div>

          <div className="query-field">
            <label className="query-label" htmlFor="vk-id-input">Virtual Key ID</label>
            <input
              id="vk-id-input"
              className="query-input"
              placeholder="e.g. vk-019..."
              value={vkId}
              onChange={(e) => setVkId(e.target.value)}
            />
          </div>

          <div className="query-field">
            <label className="query-label" htmlFor="project-id-input">Project ID</label>
            <input
              id="project-id-input"
              className="query-input"
              placeholder="default"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            />
          </div>

          <div className="query-field">
            <label className="query-label" htmlFor="provider-input">Provider</label>
            <input
              id="provider-input"
              className="query-input"
              placeholder="e.g. openai"
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
            />
          </div>

          <div className="query-field">
            <label className="query-label" htmlFor="model-input">Model</label>
            <input
              id="model-input"
              className="query-input"
              placeholder="e.g. gpt-4o"
              value={model}
              onChange={(e) => setModel(e.target.value)}
            />
          </div>

          <div className="query-field">
            <label className="query-label" htmlFor="route-input">API Route</label>
            <input
              id="route-input"
              className="query-input"
              placeholder="e.g. /v1/chat/completions"
              value={route}
              onChange={(e) => setRoute(e.target.value)}
            />
          </div>

          <div className="query-field">
            <label className="query-label" htmlFor="timestamp-input">Historical Timestamp (UTC)</label>
            <input
              id="timestamp-input"
              className="query-input"
              placeholder="e.g. 2026-08-01T12:00:00Z"
              value={atTime}
              onChange={(e) => setAtTime(e.target.value)}
            />
          </div>
        </div>

        <div style={{ display: 'flex', gap: 12 }}>
          <button
            type="button"
            className="soc-btn-primary"
            onClick={handleResolve}
            disabled={loading}
          >
            {loading ? 'Resolving...' : '🔍 Resolve Effective Policy'}
          </button>
          <button
            type="button"
            className="soc-btn-secondary"
            onClick={handleReset}
          >
            Reset
          </button>
        </div>
      </div>

      {error && (
        <div className="card" style={{ padding: 16, borderColor: 'var(--danger)', color: 'var(--danger)' }}>
          {error}
        </div>
      )}

      {/* Effective Decision Summary */}
      {response && (
        <div className="effective-summary-card card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
            <div>
              <span style={{ fontSize: 12, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, letterSpacing: '0.05em' }}>
                SYNTHESIZED EFFECTIVE CONSTRAINT
              </span>
              <h2 style={{ fontSize: 22, margin: '4px 0 0' }}>Enforced Policy Bound</h2>
            </div>
            <span className={`badge-state state-${response.effective.action === 'hard_deny' ? 'denied' : response.effective.action === 'warn' ? 'released' : 'settled'}`}>
              ACTION: {response.effective.action.toUpperCase()}
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16, marginBottom: 16 }}>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Effective Spend Limit</div>
              <div style={{ fontSize: 24, fontWeight: 600, color: '#10b981', marginTop: 4 }}>
                ${microcentsToUSD(response.effective.spend_limit_microcents).toFixed(2)}/mo
              </div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Allowed Models</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--font-mono)', marginTop: 6 }}>
                {response.effective.allowed_models.join(', ') || '*'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>Allowed Routes</div>
              <div style={{ fontSize: 14, fontFamily: 'var(--font-mono)', marginTop: 6 }}>
                {response.effective.allowed_routes.join(', ') || '*'}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 5-Level Provenance Ladder */}
      {response && (
        <div className="card" style={{ padding: 24 }}>
          <h3 style={{ margin: '0 0 16px', fontSize: 16 }}>5-Level Provenance Ladder</h3>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20 }}>
            Policy evaluation is resolved hierarchically. Confidence indicators reflect authoritative measurements versus unconfigured tiers.
          </p>

          <div className="provenance-ladder-container">
            {response.provenance_ladder.map((tier, idx) => {
              const confClass = tier.confidence === 'observed' ? 'conf-observed' : tier.confidence === 'unknown' ? 'conf-unknown' : 'conf-not-configured'
              return (
                <div key={idx} className="ladder-tier-card">
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>LEVEL {idx + 1}:</span>
                      <strong style={{ fontSize: 15, textTransform: 'capitalize' }}>{tier.level.replace('_', ' ')}</strong>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>({tier.source})</span>
                    </div>
                    {tier.confidence === 'not_configured' ? (
                      <p style={{ margin: '6px 0 0', fontSize: 13, color: 'var(--text-muted)' }}>
                        No specific override configured at this tier (inherits default hierarchy rules).
                      </p>
                    ) : (
                      <pre className="json-code-box" style={{ marginTop: 10, padding: 10, fontSize: 11, maxHeight: 180 }}>
                        {JSON.stringify(tier.policy || tier.policies || tier.scope || tier.state, null, 2)}
                      </pre>
                    )}
                  </div>

                  <span className={`confidence-pill ${confClass}`}>
                    {tier.confidence}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
