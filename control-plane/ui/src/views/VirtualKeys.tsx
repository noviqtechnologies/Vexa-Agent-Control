import React, { useState, useEffect } from 'react'
import {
  api,
  type VirtualKey,
  type CreateVirtualKeyRequest
} from '../api/client'
import './VirtualKeys.css'

function microcentsToUSD(microcents: number): number {
  return (microcents || 0) / 100_000_000
}

function usdToMicrocents(usd: number): number {
  return Math.round((usd || 0) * 100_000_000)
}

export function formatErrorMessage(err: any): string {
  if (!err) return 'An unexpected error occurred'
  const message = typeof err === 'string' ? err : err.message || 'An unexpected error occurred'
  const clean = message.replace(/^API \d+:\s*/i, '').trim()
  try {
    const parsed = JSON.parse(clean)
    return parsed.message || parsed.error || clean
  } catch {}
  return clean || message
}

export default function VirtualKeys() {
  const [keys, setKeys] = useState<VirtualKey[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'active' | 'rotating' | 'revoked'>('all')

  // Create Modal
  const [createModalOpen, setCreateModalOpen] = useState(false)
  const [creating, setCreating] = useState(false)
  const [createModalError, setCreateModalError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({})
  const [formName, setFormName] = useState('')
  const [formTeamId, setFormTeamId] = useState('')
  const [formOwnerType, setFormOwnerType] = useState<'user' | 'service_account' | 'agent'>('user')
  const [formBudgetPeriod, setFormBudgetPeriod] = useState<'monthly' | 'weekly' | 'daily'>('monthly')
  const [formExpiryDays, setFormExpiryDays] = useState('90')
  const [formBudgetUSD, setFormBudgetUSD] = useState('50.00')
  const [formMaxRPM, setFormMaxRPM] = useState('60')
  const [formMaxTPM, setFormMaxTPM] = useState('100000')
  const [formMaxConcurrent, setFormMaxConcurrent] = useState('10')
  const [formAllowedModels, setFormAllowedModels] = useState('claude-3-5-sonnet*, gpt-4o, gpt-4o-mini')
  const [formAllowedRoutes, setFormAllowedRoutes] = useState('/v1/chat/completions, /v1/messages')
  const [formAllowedIPs, setFormAllowedIPs] = useState('')

  // One-time Secret Reveal Modal
  const [secretModalOpen, setSecretModalOpen] = useState(false)
  const [revealedSecret, setRevealedSecret] = useState('')
  const [revealedKey, setRevealedKey] = useState<VirtualKey | null>(null)
  const [activeSnippetTab, setActiveSnippetTab] = useState<'curl' | 'python' | 'ts' | 'cursor' | 'claude'>('cursor')
  const [copiedKey, setCopiedKey] = useState(false)
  const [copiedSnippet, setCopiedSnippet] = useState(false)

  // Rotate Modal
  const [rotateTargetKey, setRotateTargetKey] = useState<VirtualKey | null>(null)
  const [rotateGracePeriodSec, setRotateGracePeriodSec] = useState(3600)
  const [rotating, setRotating] = useState(false)
  const [rotateModalError, setRotateModalError] = useState<string | null>(null)

  // Revoke / Delete Modal
  const [deleteTargetKey, setDeleteTargetKey] = useState<VirtualKey | null>(null)
  const [deleting, setDeleting] = useState(false)
  const [deleteModalError, setDeleteModalError] = useState<string | null>(null)

  const openCreateModal = () => {
    setCreateModalError(null)
    setFieldErrors({})
    setCreateModalOpen(true)
  }

  const loadKeys = async () => {
    try {
      setLoading(true)
      setError(null)
      const res = await api.listVirtualKeys()
      setKeys(res.virtual_keys || [])
    } catch (err: any) {
      setError(formatErrorMessage(err) || 'Failed to load virtual keys')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadKeys()
  }, [])

  const handleCreateSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    const errors: Record<string, string> = {}
    if (!formName.trim()) {
      errors.name = 'Key Name is required'
    }
    const budgetNum = parseFloat(formBudgetUSD)
    if (isNaN(budgetNum) || budgetNum < 0) {
      errors.budget = 'Spend budget must be 0 or greater'
    }
    const rpmNum = parseInt(formMaxRPM)
    if (isNaN(rpmNum) || rpmNum < 0) {
      errors.rpm = 'Max RPM must be 0 or greater'
    }
    const tpmNum = parseInt(formMaxTPM)
    if (isNaN(tpmNum) || tpmNum < 0) {
      errors.tpm = 'Max TPM must be 0 or greater'
    }
    const concNum = parseInt(formMaxConcurrent)
    if (isNaN(concNum) || concNum < 0) {
      errors.concurrent = 'Max concurrent requests must be 0 or greater'
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors)
      setCreateModalError(Object.values(errors)[0])
      return
    }

    try {
      setCreating(true)
      setCreateModalError(null)
      setFieldErrors({})

      let expiresAt: string | undefined
      if (formExpiryDays !== 'never' && parseInt(formExpiryDays) > 0) {
        const d = new Date()
        d.setDate(d.getDate() + parseInt(formExpiryDays))
        expiresAt = d.toISOString()
      }

      const allowedModels = formAllowedModels
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)

      const allowedRoutes = formAllowedRoutes
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)

      const allowedIPs = formAllowedIPs
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean)

      const req: CreateVirtualKeyRequest = {
        name: formName.trim(),
        team_id: formTeamId.trim(),
        owner_type: formOwnerType,
        budget_period: formBudgetPeriod,
        expires_at: expiresAt,
        monthly_budget_microcents: usdToMicrocents(parseFloat(formBudgetUSD) || 0),
        max_rpm: parseInt(formMaxRPM) || 0,
        max_tpm: parseInt(formMaxTPM) || 0,
        max_concurrent_requests: parseInt(formMaxConcurrent) || 0,
        allowed_models: allowedModels,
        allowed_routes: allowedRoutes,
        allowed_ips: allowedIPs,
      }

      const res = await api.createVirtualKey(req)
      setCreateModalOpen(false)
      setCreateModalError(null)
      setFieldErrors({})

      // Reset form
      setFormName('')
      setFormTeamId('')
      setFormOwnerType('user')
      setFormBudgetPeriod('monthly')
      setFormBudgetUSD('50.00')

      // Open Secret Reveal Modal
      setRevealedSecret(res.raw_secret)
      setRevealedKey(res.virtual_key)
      setSecretModalOpen(true)
      setSuccessMsg(`Virtual Key '${res.virtual_key?.name || formName.trim()}' issued successfully!`)

      await loadKeys()
    } catch (err: any) {
      setCreateModalError(formatErrorMessage(err))
    } finally {
      setCreating(false)
    }
  }

  const handleRotateConfirm = async () => {
    if (!rotateTargetKey) return
    try {
      setRotating(true)
      setRotateModalError(null)
      const res = await api.rotateVirtualKey(rotateTargetKey.id, rotateGracePeriodSec)
      setRotateTargetKey(null)
      setRotateModalError(null)
      setRevealedSecret(res.raw_secret)
      setRevealedKey(res.virtual_key)
      setSecretModalOpen(true)
      setSuccessMsg(`Virtual Key '${rotateTargetKey.name}' rotated successfully with grace period.`)
      await loadKeys()
    } catch (err: any) {
      setRotateModalError(formatErrorMessage(err))
    } finally {
      setRotating(false)
    }
  }

  const handleResetSpend = async (key: VirtualKey) => {
    if (!confirm(`Reset monthly spend for '${key.name}' back to $0.00?`)) return
    try {
      setError(null)
      await api.resetVirtualKeySpend(key.id)
      setSuccessMsg(`Spend reset for '${key.name}'.`)
      await loadKeys()
    } catch (err: any) {
      setError(formatErrorMessage(err))
    }
  }

  const handleDeleteConfirm = async () => {
    if (!deleteTargetKey) return
    try {
      setDeleting(true)
      setDeleteModalError(null)
      await api.deleteVirtualKey(deleteTargetKey.id)
      setDeleteTargetKey(null)
      setDeleteModalError(null)
      setSuccessMsg(`Virtual Key '${deleteTargetKey.name}' revoked and evicted from edge caches.`)
      await loadKeys()
    } catch (err: any) {
      setDeleteModalError(formatErrorMessage(err))
    } finally {
      setDeleting(false)
    }
  }

  const copyToClipboard = (text: string, isSecret = false) => {
    navigator.clipboard.writeText(text)
    if (isSecret) {
      setCopiedKey(true)
      setTimeout(() => setCopiedKey(false), 2000)
    } else {
      setCopiedSnippet(true)
      setTimeout(() => setCopiedSnippet(false), 2000)
    }
  }

  // Filtered keys
  const filteredKeys = keys.filter((k) => {
    const matchesStatus = statusFilter === 'all' || k.status === statusFilter
    const q = searchQuery.toLowerCase()
    const matchesSearch =
      !q ||
      k.name.toLowerCase().includes(q) ||
      k.key_prefix.toLowerCase().includes(q) ||
      (k.team_id && k.team_id.toLowerCase().includes(q)) ||
      (k.allowed_models && k.allowed_models.some((m) => m.toLowerCase().includes(q)))
    return matchesStatus && matchesSearch
  })

  // Metrics
  const totalKeysCount = keys.length
  const activeKeysCount = keys.filter((k) => k.status === 'active' || k.status === 'rotating').length
  const totalBudgetUSD = keys.reduce((acc, k) => acc + microcentsToUSD(k.monthly_budget_microcents), 0)
  const totalSpentUSD = keys.reduce((acc, k) => acc + microcentsToUSD(k.spent_microcents), 0)

  // Integration Snippets
  const getIntegrationSnippet = () => {
    const secret = revealedSecret || 'sk-vex-example-key'
    const endpoint = window.location.origin + '/api/v3/broker/dispatch'

    switch (activeSnippetTab) {
      case 'cursor':
        return `# In your Cursor / VS Code settings or .env:
OPENAI_API_BASE="${window.location.origin}/v1"
OPENAI_API_KEY="${secret}"
ANTHROPIC_BASE_URL="${window.location.origin}/v1"
ANTHROPIC_API_KEY="${secret}"`
      case 'claude':
        return `# Claude Code Configuration:
export ANTHROPIC_BASE_URL="${window.location.origin}/v1"
export ANTHROPIC_API_KEY="${secret}"
claude`
      case 'curl':
        return `curl -X POST ${endpoint} \\
  -H "Authorization: Bearer ${secret}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello via Governed Virtual Key"}]
  }'`
      case 'python':
        return `from openai import OpenAI

client = OpenAI(
    base_url="${window.location.origin}/v1",
    api_key="${secret}"
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello AgentWall"}]
)
print(response.choices[0].message.content)`
      case 'ts':
        return `import OpenAI from 'openai';

const openai = new OpenAI({
  baseURL: '${window.location.origin}/v1',
  apiKey: '${secret}',
});

async function main() {
  const completion = await openai.chat.completions.create({
    messages: [{ role: 'user', content: 'Hello AgentWall' }],
    model: 'gpt-4o',
  });
  console.log(completion.choices[0].message);
}`
    }
  }

  return (
    <div className="virtual-keys-container">
      {/* Header */}
      <div className="vk-header">
        <div className="vk-title-section">
          <h1>
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M21 2l-2 2m-1.5 1.5L14 9a5.5 5.5 0 1 0 4 4l3.5-3.5-2-2-1.5 1.5M15.5 7.5L14 9"/>
            </svg>
            Scoped Virtual Keys
          </h1>
          <p>
            Issue, govern, and monitor fine-grained LLM client tokens with sub-millisecond local caching, rate limits, model allowlists, and spend caps.
          </p>
        </div>
        <div className="vk-header-actions">
          <button
            className="btn-primary-gradient"
            onClick={openCreateModal}
            id="btn-issue-virtual-key"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="12" y1="5" x2="12" y2="19"/>
              <line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            Issue Virtual Key
          </button>
        </div>
      </div>

      {/* Banners */}
      {successMsg && (
        <div className="vk-banner success">
          <span>{successMsg}</span>
          <button className="vk-copy-btn" onClick={() => setSuccessMsg(null)}>✕</button>
        </div>
      )}
      {error && (
        <div className="vk-banner error">
          <span>{error}</span>
          <button className="vk-copy-btn" onClick={() => setError(null)}>✕</button>
        </div>
      )}

      {/* Metric KPI Summary */}
      <div className="vk-metrics-grid">
        <div className="vk-metric-card">
          <div className="vk-metric-icon emerald">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <div className="vk-metric-data">
            <div className="vk-metric-value">{activeKeysCount} / {totalKeysCount}</div>
            <div className="vk-metric-label">Active Virtual Keys</div>
          </div>
        </div>

        <div className="vk-metric-card">
          <div className="vk-metric-icon blue">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"/><path d="M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8"/><path d="M12 18V6"/>
            </svg>
          </div>
          <div className="vk-metric-data">
            <div className="vk-metric-value">${totalSpentUSD.toFixed(2)}</div>
            <div className="vk-metric-label">MTD Spend Consumed</div>
          </div>
        </div>

        <div className="vk-metric-card">
          <div className="vk-metric-icon purple">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="2" y="4" width="20" height="16" rx="2"/><path d="M7 15h10M7 9h10"/>
            </svg>
          </div>
          <div className="vk-metric-data">
            <div className="vk-metric-value">${totalBudgetUSD.toFixed(2)}</div>
            <div className="vk-metric-label">Total Monthly Budget Cap</div>
          </div>
        </div>

        <div className="vk-metric-card">
          <div className="vk-metric-icon amber">
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
            </svg>
          </div>
          <div className="vk-metric-data">
            <div className="vk-metric-value">&lt; 0.5 ms</div>
            <div className="vk-metric-label">Local Edge Proxy Latency</div>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="vk-toolbar">
        <div className="vk-search-wrapper">
          <svg className="vk-search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            type="text"
            className="vk-search-input"
            placeholder="Search by key name, prefix, team, or allowed models..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div className="vk-filter-chips">
          {(['all', 'active', 'rotating', 'revoked'] as const).map((st) => (
            <button
              key={st}
              className={`vk-filter-chip ${statusFilter === st ? 'active' : ''}`}
              onClick={() => setStatusFilter(st)}
            >
              {st.charAt(0).toUpperCase() + st.slice(1)}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="vk-table-card">
        {loading ? (
          <div className="vk-empty-state">
            <div className="vk-empty-icon">⏳</div>
            <p>Loading virtual keys...</p>
          </div>
        ) : filteredKeys.length === 0 ? (
          <div className="vk-empty-state">
            <div className="vk-empty-icon">🔑</div>
            <p>No virtual keys match your query.</p>
            <button
              className="btn-secondary"
              style={{ margin: '12px auto 0 auto' }}
              onClick={openCreateModal}
            >
              Issue your first Virtual Key
            </button>
          </div>
        ) : (
          <table className="vk-table">
            <thead>
              <tr>
                <th>Virtual Key</th>
                <th>Status</th>
                <th>Monthly Spend & Budget</th>
                <th>Rate & Concurrency Limits</th>
                <th>Scoped Models & Routes</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredKeys.map((key) => {
                const budgetUSD = microcentsToUSD(key.monthly_budget_microcents)
                const spentUSD = microcentsToUSD(key.spent_microcents)
                const percentSpent = budgetUSD > 0 ? Math.min(100, Math.round((spentUSD / budgetUSD) * 100)) : 0
                const progressColor = percentSpent > 90 ? 'red' : percentSpent > 65 ? 'amber' : 'green'

                return (
                  <tr key={key.id}>
                    <td>
                      <div className="vk-key-name-col">
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="vk-key-name">{key.name}</span>
                          <span className={`badge ${key.owner_type === 'agent' ? 'badge-warning' : key.owner_type === 'service_account' ? 'badge-info' : 'badge-neutral'}`} style={{ fontSize: 10, padding: '2px 6px' }}>
                            {key.owner_type === 'agent' ? '🤖 AGENT' : key.owner_type === 'service_account' ? '⚙️ SVC' : '🧑 USER'}
                          </span>
                        </div>
                        <div className="vk-key-prefix-badge">
                          <code>{key.key_prefix}</code>
                          <button
                            className="vk-copy-btn"
                            title="Copy Prefix"
                            onClick={() => copyToClipboard(key.key_prefix)}
                          >
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>
                              <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
                            </svg>
                          </button>
                        </div>
                        {key.team_id && (
                          <span style={{ fontSize: '11.5px', color: '#94a3b8' }}>
                            Team: <strong style={{ color: '#cbd5e1' }}>{key.team_id}</strong>
                          </span>
                        )}
                      </div>
                    </td>

                    <td>
                      <span className={`vk-status-badge ${key.status}`}>
                        <span className="vk-pulse-dot" />
                        {key.status}
                      </span>
                    </td>

                    <td>
                      <div className="vk-spend-meter-wrapper">
                        <div className="vk-spend-labels">
                          <span className="vk-spend-spent">${spentUSD.toFixed(2)}</span>
                          <span>${budgetUSD.toFixed(2)} / {key.budget_period === 'daily' ? 'day' : key.budget_period === 'weekly' ? 'wk' : 'mo'}</span>
                        </div>
                        <div className="vk-progress-track">
                          <div
                            className={`vk-progress-fill ${progressColor}`}
                            style={{ width: `${percentSpent}%` }}
                          />
                        </div>
                        <div style={{ fontSize: '11px', color: '#64748b', textAlign: 'right' }}>
                          {percentSpent}% utilized
                        </div>
                      </div>
                    </td>

                    <td>
                      <div className="vk-ratelimits-cell">
                        <div>RPM: <span>{key.max_rpm > 0 ? `${key.max_rpm} req/m` : 'Unlimited'}</span></div>
                        <div>TPM: <span>{key.max_tpm > 0 ? `${key.max_tpm.toLocaleString()} tok/m` : 'Unlimited'}</span></div>
                        <div>Max Concurrency: <span>{key.max_concurrent_requests > 0 ? key.max_concurrent_requests : 'Unlimited'}</span></div>
                      </div>
                    </td>

                    <td>
                      <div className="vk-pills-wrap">
                        {key.allowed_models && key.allowed_models.length > 0 ? (
                          key.allowed_models.slice(0, 3).map((m, idx) => (
                            <span key={idx} className="vk-scope-pill model">{m}</span>
                          ))
                        ) : (
                          <span className="vk-scope-pill model">All Models (*)</span>
                        )}
                        {key.allowed_models && key.allowed_models.length > 3 && (
                          <span className="vk-scope-pill model">+{key.allowed_models.length - 3} more</span>
                        )}
                        {key.allowed_ips && key.allowed_ips.length > 0 && (
                          <span className="vk-scope-pill ip">CIDR: {key.allowed_ips.join(', ')}</span>
                        )}
                      </div>
                    </td>

                    <td>
                      <div className="vk-actions-cell">
                        <button
                          className="vk-action-icon-btn rotate"
                          title="Rotate Key (Zero Downtime)"
                          onClick={() => {
                            setRotateTargetKey(key)
                            setRotateGracePeriodSec(3600)
                          }}
                        >
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="23 4 23 10 17 10"/>
                            <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                          </svg>
                        </button>
                        <button
                          className="vk-action-icon-btn reset"
                          title="Reset Monthly Spend Counter"
                          onClick={() => handleResetSpend(key)}
                        >
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
                          </svg>
                        </button>
                        <button
                          className="vk-action-icon-btn delete"
                          title="Revoke and Invalidate Key"
                          onClick={() => setDeleteTargetKey(key)}
                        >
                          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <polyline points="3 6 5 6 21 6"/>
                            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/>
                          </svg>
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

      {/* CREATE VIRTUAL KEY MODAL */}
      {createModalOpen && (
        <div className="vk-modal-backdrop" onClick={() => setCreateModalOpen(false)}>
          <div className="vk-modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="vk-modal-header">
              <h2>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M21 2l-2 2m-1.5 1.5L14 9a5.5 5.5 0 1 0 4 4l3.5-3.5-2-2-1.5 1.5M15.5 7.5L14 9"/>
                </svg>
                Issue Scoped Virtual Key
              </h2>
              <button className="vk-modal-close-btn" onClick={() => setCreateModalOpen(false)}>✕</button>
            </div>

            <form onSubmit={handleCreateSubmit} noValidate>
              <div className="vk-modal-body">
                {createModalError && (
                  <div className="vk-modal-alert error" role="alert">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }}>
                      <circle cx="12" cy="12" r="10"/>
                      <line x1="12" y1="8" x2="12" y2="12"/>
                      <line x1="12" y1="16" x2="12.01" y2="16"/>
                    </svg>
                    <span>{createModalError}</span>
                    <button type="button" className="vk-copy-btn" onClick={() => setCreateModalError(null)}>✕</button>
                  </div>
                )}

                <div className="vk-form-grid">
                  <div className="vk-form-group full-width">
                    <label className="vk-form-label">Key Ownership Persona</label>
                    <div style={{ display: 'flex', gap: 16, marginTop: 4 }}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13 }}>
                        <input
                          type="radio"
                          name="ownerType"
                          value="user"
                          checked={formOwnerType === 'user'}
                          onChange={() => setFormOwnerType('user')}
                        />
                        <span>🧑 User / Developer</span>
                      </label>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13 }}>
                        <input
                          type="radio"
                          name="ownerType"
                          value="service_account"
                          checked={formOwnerType === 'service_account'}
                          onChange={() => setFormOwnerType('service_account')}
                        />
                        <span>⚙️ Service Account (CI/CD)</span>
                      </label>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 13 }}>
                        <input
                          type="radio"
                          name="ownerType"
                          value="agent"
                          checked={formOwnerType === 'agent'}
                          onChange={() => setFormOwnerType('agent')}
                        />
                        <span>🤖 Autonomous AI Agent</span>
                      </label>
                    </div>
                    <span className="vk-form-help">Declares the principal entity for risk profiling & audit attribution</span>
                  </div>

                  <div className="vk-form-group">
                    <label className="vk-form-label">Key Name *</label>
                    <input
                      type="text"
                      className={`vk-form-input ${fieldErrors.name ? 'has-error' : ''}`}
                      placeholder="e.g. cursor-ide-team, release-agent"
                      value={formName}
                      onChange={(e) => {
                        setFormName(e.target.value)
                        if (fieldErrors.name) {
                          setFieldErrors((prev) => ({ ...prev, name: '' }))
                          setCreateModalError(null)
                        }
                      }}
                      required
                    />
                    {fieldErrors.name ? (
                      <span className="vk-field-error">{fieldErrors.name}</span>
                    ) : (
                      <span className="vk-form-help">Human-readable identifier for audit trails</span>
                    )}
                  </div>

                  <div className="vk-form-group">
                    <label className="vk-form-label">Team / Developer ID</label>
                    <input
                      type="text"
                      className="vk-form-input"
                      placeholder="e.g. backend-eng, alice@acme.com"
                      value={formTeamId}
                      onChange={(e) => setFormTeamId(e.target.value)}
                    />
                    <span className="vk-form-help">Optional tenant subgroup attribution</span>
                  </div>

                  <div className="vk-form-group">
                    <label className="vk-form-label">Spend Budget ($ USD)</label>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <input
                        type="number"
                        step="0.01"
                        min="0"
                        className={`vk-form-input ${fieldErrors.budget ? 'has-error' : ''}`}
                        placeholder="50.00"
                        value={formBudgetUSD}
                        onChange={(e) => {
                          setFormBudgetUSD(e.target.value)
                          if (fieldErrors.budget) {
                            setFieldErrors((prev) => ({ ...prev, budget: '' }))
                            setCreateModalError(null)
                          }
                        }}
                        style={{ flex: 1 }}
                      />
                      <select
                        className="vk-form-select"
                        value={formBudgetPeriod}
                        onChange={(e) => setFormBudgetPeriod(e.target.value as any)}
                        style={{ width: 115 }}
                        aria-label="Budget Cadence"
                      >
                        <option value="daily">/ Daily</option>
                        <option value="weekly">/ Weekly</option>
                        <option value="monthly">/ Monthly</option>
                      </select>
                    </div>
                    {fieldErrors.budget ? (
                      <span className="vk-field-error">{fieldErrors.budget}</span>
                    ) : (
                      <span className="vk-form-help">Hard limit enforced prior to upstream dispatch</span>
                    )}
                  </div>

                  <div className="vk-form-group">
                    <label className="vk-form-label">Expiration</label>
                    <select
                      className="vk-form-select"
                      value={formExpiryDays}
                      onChange={(e) => setFormExpiryDays(e.target.value)}
                    >
                      <option value="30">30 Days</option>
                      <option value="90">90 Days</option>
                      <option value="180">180 Days</option>
                      <option value="365">1 Year</option>
                      <option value="never">Never Expire</option>
                    </select>
                    <span className="vk-form-help">Automatic token revocation timeline</span>
                  </div>

                  <div className="vk-form-group">
                    <label className="vk-form-label">Max RPM (Req / Min)</label>
                    <input
                      type="number"
                      min="0"
                      className={`vk-form-input ${fieldErrors.rpm ? 'has-error' : ''}`}
                      placeholder="60"
                      value={formMaxRPM}
                      onChange={(e) => {
                        setFormMaxRPM(e.target.value)
                        if (fieldErrors.rpm) {
                          setFieldErrors((prev) => ({ ...prev, rpm: '' }))
                          setCreateModalError(null)
                        }
                      }}
                    />
                    {fieldErrors.rpm && <span className="vk-field-error">{fieldErrors.rpm}</span>}
                  </div>

                  <div className="vk-form-group">
                    <label className="vk-form-label">Max TPM (Tokens / Min)</label>
                    <input
                      type="number"
                      min="0"
                      className={`vk-form-input ${fieldErrors.tpm ? 'has-error' : ''}`}
                      placeholder="100000"
                      value={formMaxTPM}
                      onChange={(e) => {
                        setFormMaxTPM(e.target.value)
                        if (fieldErrors.tpm) {
                          setFieldErrors((prev) => ({ ...prev, tpm: '' }))
                          setCreateModalError(null)
                        }
                      }}
                    />
                    {fieldErrors.tpm && <span className="vk-field-error">{fieldErrors.tpm}</span>}
                  </div>

                  <div className="vk-form-group full-width">
                    <label className="vk-form-label">Max Concurrent In-Flight Requests</label>
                    <input
                      type="number"
                      min="0"
                      className={`vk-form-input ${fieldErrors.concurrent ? 'has-error' : ''}`}
                      placeholder="10"
                      value={formMaxConcurrent}
                      onChange={(e) => {
                        setFormMaxConcurrent(e.target.value)
                        if (fieldErrors.concurrent) {
                          setFieldErrors((prev) => ({ ...prev, concurrent: '' }))
                          setCreateModalError(null)
                        }
                      }}
                    />
                    {fieldErrors.concurrent ? (
                      <span className="vk-field-error">{fieldErrors.concurrent}</span>
                    ) : (
                      <span className="vk-form-help">Adaptive concurrency limits per virtual key</span>
                    )}
                  </div>

                  <div className="vk-form-group full-width">
                    <label className="vk-form-label">Allowed Models (Comma-separated)</label>
                    <input
                      type="text"
                      className="vk-form-input"
                      placeholder="claude-3-5-sonnet*, gpt-4o, gpt-4o-mini"
                      value={formAllowedModels}
                      onChange={(e) => setFormAllowedModels(e.target.value)}
                    />
                    <span className="vk-form-help">Wildcards supported. Leave blank for unrestricted access.</span>
                  </div>

                  <div className="vk-form-group full-width">
                    <label className="vk-form-label">Allowed Routes</label>
                    <input
                      type="text"
                      className="vk-form-input"
                      placeholder="/v1/chat/completions, /v1/messages"
                      value={formAllowedRoutes}
                      onChange={(e) => setFormAllowedRoutes(e.target.value)}
                    />
                  </div>

                  <div className="vk-form-group full-width">
                    <label className="vk-form-label">Allowed Client IP CIDRs (Optional)</label>
                    <input
                      type="text"
                      className="vk-form-input"
                      placeholder="e.g. 10.0.0.0/8, 192.168.1.100"
                      value={formAllowedIPs}
                      onChange={(e) => setFormAllowedIPs(e.target.value)}
                    />
                  </div>
                </div>
              </div>

              <div className="vk-modal-footer">
                <button
                  type="button"
                  className="btn-secondary"
                  onClick={() => setCreateModalOpen(false)}
                  disabled={creating}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn-primary-gradient"
                  disabled={creating}
                >
                  {creating ? 'Generating Key...' : 'Generate Virtual Key'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ONE-TIME SECRET REVEAL MODAL */}
      {secretModalOpen && (
        <div className="vk-modal-backdrop">
          <div className="vk-modal-card" style={{ maxWidth: '720px' }}>
            <div className="vk-modal-header">
              <h2 style={{ color: '#34d399' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
                  <polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
                Virtual Key Secret Generated
              </h2>
              <button className="vk-modal-close-btn" onClick={() => setSecretModalOpen(false)}>✕</button>
            </div>

            <div className="vk-modal-body">
              {revealedKey && (
                <div style={{ fontSize: '13px', color: '#94a3b8', marginBottom: '-6px' }}>
                  Key Name: <strong style={{ color: '#f1f5f9' }}>{revealedKey.name}</strong> ({revealedKey.key_prefix})
                </div>
              )}
              <div className="vk-secret-alert">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }}>
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                <div>
                  <strong>Please copy this key now.</strong> For security, this secret token will <strong>never be shown again</strong>.
                </div>
              </div>

              <div className="vk-secret-display-box">
                <code>{revealedSecret}</code>
                <button
                  className="btn-primary-gradient"
                  style={{ padding: '6px 12px', fontSize: '12px' }}
                  onClick={() => copyToClipboard(revealedSecret, true)}
                >
                  {copiedKey ? '✓ Copied' : 'Copy Key'}
                </button>
              </div>

              <div style={{ marginTop: '12px' }}>
                <label className="vk-form-label">Quick Client Integration</label>
                <div className="vk-snippet-tabs">
                  <button
                    className={`vk-snippet-tab ${activeSnippetTab === 'cursor' ? 'active' : ''}`}
                    onClick={() => setActiveSnippetTab('cursor')}
                  >
                    Cursor / VSCode
                  </button>
                  <button
                    className={`vk-snippet-tab ${activeSnippetTab === 'claude' ? 'active' : ''}`}
                    onClick={() => setActiveSnippetTab('claude')}
                  >
                    Claude Code
                  </button>
                  <button
                    className={`vk-snippet-tab ${activeSnippetTab === 'curl' ? 'active' : ''}`}
                    onClick={() => setActiveSnippetTab('curl')}
                  >
                    cURL
                  </button>
                  <button
                    className={`vk-snippet-tab ${activeSnippetTab === 'python' ? 'active' : ''}`}
                    onClick={() => setActiveSnippetTab('python')}
                  >
                    Python (OpenAI/Anthropic)
                  </button>
                  <button
                    className={`vk-snippet-tab ${activeSnippetTab === 'ts' ? 'active' : ''}`}
                    onClick={() => setActiveSnippetTab('ts')}
                  >
                    TypeScript
                  </button>
                </div>

                <div className="vk-snippet-code-box">
                  {getIntegrationSnippet()}
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '8px' }}>
                  <button
                    className="btn-secondary"
                    onClick={() => copyToClipboard(getIntegrationSnippet() || '', false)}
                  >
                    {copiedSnippet ? '✓ Snippet Copied' : 'Copy Integration Snippet'}
                  </button>
                </div>
              </div>
            </div>

            <div className="vk-modal-footer">
              <button
                className="btn-primary-gradient"
                onClick={() => setSecretModalOpen(false)}
              >
                I Have Saved My Secret Key
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ROTATE KEY MODAL */}
      {rotateTargetKey && (
        <div className="vk-modal-backdrop" onClick={() => !rotating && setRotateTargetKey(null)}>
          <div className="vk-modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="vk-modal-header">
              <h2>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="23 4 23 10 17 10"/>
                  <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                </svg>
                Rotate Virtual Key: {rotateTargetKey.name}
              </h2>
              <button className="vk-modal-close-btn" onClick={() => !rotating && setRotateTargetKey(null)}>✕</button>
            </div>

            <div className="vk-modal-body">
              {rotateModalError && (
                <div className="vk-modal-alert error" role="alert">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }}>
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <span>{rotateModalError}</span>
                  <button type="button" className="vk-copy-btn" onClick={() => setRotateModalError(null)}>✕</button>
                </div>
              )}

              <p style={{ fontSize: '13.5px', color: '#cbd5e1', lineHeight: 1.6, margin: 0 }}>
                Zero-downtime rotation generates a new active secret while keeping the previous secret valid for the duration of the grace period. This allows agents to seamlessly update without request drop.
              </p>

              <div className="vk-form-group">
                <label className="vk-form-label">Grace Period for Old Secret</label>
                <select
                  className="vk-form-select"
                  value={rotateGracePeriodSec}
                  onChange={(e) => setRotateGracePeriodSec(parseInt(e.target.value))}
                  disabled={rotating}
                >
                  <option value={3600}>1 Hour (Standard)</option>
                  <option value={21600}>6 Hours</option>
                  <option value={86400}>24 Hours (Recommended for distributed agents)</option>
                  <option value={604800}>7 Days</option>
                  <option value={0}>Immediate (0 grace period — invalidates previous key instantly)</option>
                </select>
              </div>
            </div>

            <div className="vk-modal-footer">
              <button className="btn-secondary" onClick={() => setRotateTargetKey(null)} disabled={rotating}>
                Cancel
              </button>
              <button
                className="btn-primary-gradient"
                onClick={handleRotateConfirm}
                disabled={rotating}
              >
                {rotating ? 'Rotating...' : 'Rotate & Generate New Secret'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* REVOKE / DELETE MODAL */}
      {deleteTargetKey && (
        <div className="vk-modal-backdrop" onClick={() => !deleting && setDeleteTargetKey(null)}>
          <div className="vk-modal-card" onClick={(e) => e.stopPropagation()}>
            <div className="vk-modal-header">
              <h2 style={{ color: '#f87171' }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
                Revoke Virtual Key
              </h2>
              <button className="vk-modal-close-btn" onClick={() => !deleting && setDeleteTargetKey(null)}>✕</button>
            </div>

            <div className="vk-modal-body">
              {deleteModalError && (
                <div className="vk-modal-alert error" role="alert">
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }}>
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="12" y1="8" x2="12" y2="12"/>
                    <line x1="12" y1="16" x2="12.01" y2="16"/>
                  </svg>
                  <span>{deleteModalError}</span>
                  <button type="button" className="vk-copy-btn" onClick={() => setDeleteModalError(null)}>✕</button>
                </div>
              )}

              <p style={{ fontSize: '13.5px', color: '#cbd5e1', lineHeight: 1.6, margin: 0 }}>
                Are you sure you want to revoke <strong>{deleteTargetKey.name}</strong> (<code>{deleteTargetKey.key_prefix}</code>)?
              </p>
              <div className="vk-banner error" style={{ margin: 0 }}>
                Revocation is immediate. An invalidation broadcast will instantly evict this key from all connected Edge Proxies and Brokers.
              </div>
            </div>

            <div className="vk-modal-footer">
              <button className="btn-secondary" onClick={() => setDeleteTargetKey(null)} disabled={deleting}>
                Cancel
              </button>
              <button
                className="btn-danger"
                onClick={handleDeleteConfirm}
                disabled={deleting}
              >
                {deleting ? 'Revoking...' : 'Revoke Immediately'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
