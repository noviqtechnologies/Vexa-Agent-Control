import { useState, useEffect } from 'react'
import './SaaSOperator.css'

interface OrgSummary {
  id: string
  name: string
  slug: string
  contact_email: string
  license_tier: string
  max_seats: number
  is_trial: boolean
  trial_days: number
  trial_ends_at?: string
  license_expires_at?: string
  days_remaining: number
  status: string
  created_at: string
  has_bootstrap: boolean
}

interface PlatformStats {
  total_organizations: number
  active_trials: number
  expiring_within_7d: number
  total_seats: number
}

interface CreateOrgResponse {
  organization: {
    id: string
    name: string
    slug: string
    contact_email?: string
    license_tier: string
    max_seats: number
    gateway_secret?: string
    policy_read_secret?: string
  }
  bootstrap_token: string
  console_url: string
}

export default function SaaSOperator() {
  const [orgs, setOrgs] = useState<OrgSummary[]>([])
  const [stats, setStats] = useState<PlatformStats | null>(null)
  const [loading, setLoading] = useState(true)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [createdSuccess, setCreatedSuccess] = useState<CreateOrgResponse | null>(null)
  const [selectedOrg, setSelectedOrg] = useState<OrgSummary | null>(null)
  const [showRenewModal, setShowRenewModal] = useState(false)
  const [renewDays, setRenewDays] = useState(30)
  const [isRenewTrial, setIsRenewTrial] = useState(false)
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [regeneratedToken, setRegeneratedToken] = useState<{ orgName: string; token: string } | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterStatus, setFilterStatus] = useState<'ALL' | 'ACTIVE' | 'SUSPENDED' | 'TRIAL'>('ALL')

  // Create Form State
  const [formName, setFormName] = useState('')
  const [formSlug, setFormSlug] = useState('')
  const [formEmail, setFormEmail] = useState('')
  const [formTier, setFormTier] = useState('enterprise')
  const [formSeats, setFormSeats] = useState(25)
  const [formPlanType, setFormPlanType] = useState<'trial15' | 'trial30' | 'paid'>('trial15')
  const [formCustomDays, setFormCustomDays] = useState(365)
  const [submitting, setSubmitting] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  async function loadData() {
    try {
      const [orgsRes, statsRes] = await Promise.all([
        fetch('/api/v1/operator/organizations'),
        fetch('/api/v1/operator/stats')
      ])

      if (orgsRes.ok) {
        setOrgs(await orgsRes.json())
      }
      if (statsRes.ok) {
        setStats(await statsRes.json())
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  function handleNameChange(name: string) {
    setFormName(name)
    // auto-generate slug
    const derivedSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '')
    setFormSlug(derivedSlug)
  }

  async function extractErrorMessage(res: Response, fallback: string): Promise<string> {
    try {
      const text = await res.text()
      if (!text) return `${fallback} (HTTP ${res.status})`
      if (text.startsWith('{')) {
        const parsed = JSON.parse(text)
        return parsed.error || parsed.message || fallback
      }
      if (text.toLowerCase().includes('<!doctype') || text.startsWith('<')) {
        if (res.status === 403) {
          return 'Access Denied (HTTP 403 Forbidden): Request was blocked by security policy or requires SaaS Operator privileges.'
        }
        return `${fallback} (HTTP ${res.status}: ${res.statusText || 'Error'})`
      }
      return text
    } catch {
      return `${fallback} (${res.status})`
    }
  }

  async function handleCreateOrg(e: React.FormEvent) {
    e.preventDefault()
    setSubmitting(true)
    setErrorMsg(null)

    const isTrial = formPlanType === 'trial15' || formPlanType === 'trial30'
    const trialDays = formPlanType === 'trial15' ? 15 : formPlanType === 'trial30' ? 30 : 0
    const validDays = isTrial ? trialDays : formCustomDays

    try {
      const res = await fetch('/api/v1/operator/organizations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formName,
          slug: formSlug,
          contact_email: formEmail,
          license_tier: formTier,
          max_seats: Number(formSeats),
          is_trial: isTrial,
          trial_days: trialDays,
          valid_days: validDays
        })
      })

      if (!res.ok) {
        const errorText = await extractErrorMessage(res, 'Failed to create organization')
        throw new Error(errorText)
      }

      const data: CreateOrgResponse = await res.json()
      setCreatedSuccess(data)
      setShowCreateModal(false)
      loadData()
    } catch (err: any) {
      setErrorMsg(err.message || 'Error occurred')
    } finally {
      setSubmitting(false)
    }
  }

  async function handleRenewLicense(e: React.FormEvent) {
    e.preventDefault()
    if (!selectedOrg) return

    try {
      const res = await fetch(`/api/v1/operator/organizations/${selectedOrg.id}/renew-license`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          additional_days: Number(renewDays),
          is_trial: isRenewTrial
        })
      })
      if (res.ok) {
        setShowRenewModal(false)
        loadData()
      }
    } catch {
      // ignore
    }
  }

  async function handleStatusToggle(org: OrgSummary) {
    const newStatus = org.status === 'ACTIVE' ? 'SUSPENDED' : 'ACTIVE'
    try {
      await fetch(`/api/v1/operator/organizations/${org.id}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus })
      })
      loadData()
    } catch {
      // ignore
    }
  }

  async function handleRegenerateBootstrap(org: OrgSummary) {
    try {
      const res = await fetch(`/api/v1/operator/organizations/${org.id}/regenerate-bootstrap`, {
        method: 'POST'
      })
      if (res.ok) {
        const data = await res.json()
        setRegeneratedToken({
          orgName: org.name || org.slug,
          token: data.bootstrap_token
        })
        loadData()
      }
    } catch {
      // ignore
    }
  }

  function copyText(text: string, key: string) {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const filteredOrgs = orgs.filter(org => {
    const query = searchQuery.trim().toLowerCase()
    const matchesQuery = !query ||
      org.name.toLowerCase().includes(query) ||
      org.slug.toLowerCase().includes(query) ||
      (org.contact_email && org.contact_email.toLowerCase().includes(query))

    if (!matchesQuery) return false
    if (filterStatus === 'ACTIVE') return org.status === 'ACTIVE'
    if (filterStatus === 'SUSPENDED') return org.status === 'SUSPENDED'
    if (filterStatus === 'TRIAL') return org.is_trial
    return true
  })

  return (
    <div className="saas-operator-container">
      {/* Header */}
      <div className="saas-header">
        <div>
          <h1>
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2.5">
              <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
              <line x1="8" y1="21" x2="16" y2="21"/>
              <line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
            Platform Operations & Tenant Onboarding
          </h1>
          <p style={{ color: 'var(--text-secondary)', fontSize: 13, marginTop: 4 }}>
            Multi-Tenant SaaS Hub • Automated Ed25519 License Minting • Zero-Trust Tenant Registry
          </p>
        </div>
        <div className="saas-header-actions">
          <button className="saas-btn-primary" onClick={() => {
            setFormName('')
            setFormSlug('')
            setFormEmail('')
            setFormPlanType('trial15')
            setCreatedSuccess(null)
            setShowCreateModal(true)
          }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
            </svg>
            Onboard Organization
          </button>
        </div>
      </div>

      {/* Success Banner if an org was just created */}
      {createdSuccess && (
        <div className="saas-banner-callout">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h4 style={{ fontSize: 15, fontWeight: 700 }}>
              🎉 Successfully Provisioned Tenant: {createdSuccess.organization.name}
            </h4>
            <button className="saas-btn-sm" onClick={() => setCreatedSuccess(null)}>Dismiss</button>
          </div>
          <div style={{ marginTop: 12, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 12 }}>
            <div>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Console URL:</span>
              <div className="saas-secret-box">
                <span className="saas-secret-val">{createdSuccess.console_url}</span>
                <button className="saas-copy-btn" onClick={() => copyText(createdSuccess.console_url, 'url')}>
                  {copiedKey === 'url' ? 'Copied!' : 'Copy URL'}
                </button>
              </div>
            </div>
            <div>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Single-Use Bootstrap Token (Password):</span>
              <div className="saas-secret-box">
                <span className="saas-secret-val">{createdSuccess.bootstrap_token}</span>
                <button className="saas-copy-btn" onClick={() => copyText(createdSuccess.bootstrap_token, 'bt')}>
                  {copiedKey === 'bt' ? 'Copied!' : 'Copy Token'}
                </button>
              </div>
            </div>
            {createdSuccess.organization.contact_email && (
              <div>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Admin Contact Email:</span>
                <div className="saas-secret-box">
                  <span className="saas-secret-val">{createdSuccess.organization.contact_email}</span>
                  <button className="saas-copy-btn" onClick={() => copyText(createdSuccess.organization.contact_email!, 'email')}>
                    {copiedKey === 'email' ? 'Copied!' : 'Copy Email'}
                  </button>
                </div>
              </div>
            )}
          </div>
          <p style={{ marginTop: 8, fontSize: 12, color: 'var(--text-muted)' }}>
            ⚠️ Provide this token to the customer administrator to complete their initial BYOK credential setup.
          </p>
        </div>
      )}

      {/* KPI Cards */}
      <div className="saas-kpi-grid">
        <div className="saas-kpi-card highlight">
          <span className="saas-kpi-label">Active Tenants</span>
          <span className="saas-kpi-val">{stats?.total_organizations ?? orgs.length}</span>
        </div>
        <div className="saas-kpi-card">
          <span className="saas-kpi-label">Active Free Trials</span>
          <span className="saas-kpi-val" style={{ color: '#f59e0b' }}>
            {stats?.active_trials ?? orgs.filter(o => o.is_trial).length}
          </span>
        </div>
        <div className="saas-kpi-card">
          <span className="saas-kpi-label">Expiring in &lt; 7 Days</span>
          <span className="saas-kpi-val" style={{ color: stats?.expiring_within_7d ? '#ef4444' : 'var(--text-primary)' }}>
            {stats?.expiring_within_7d ?? 0}
          </span>
        </div>
        <div className="saas-kpi-card">
          <span className="saas-kpi-label">Total Allocated Seats</span>
          <span className="saas-kpi-val">{stats?.total_seats ?? orgs.reduce((acc, o) => acc + o.max_seats, 0)}</span>
        </div>
      </div>

      {/* Organizations Directory */}
      <div className="saas-table-card">
        <div className="saas-table-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h2>Tenant Organizations Directory</h2>
            <span style={{ fontSize: 13, color: 'var(--text-muted)' }}>
              {filteredOrgs.length} of {orgs.length} organizations
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              background: 'var(--bg-surface-0)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
              padding: '4px 10px',
              gap: 6
            }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input
                type="text"
                placeholder="Search organizations..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  background: 'none',
                  border: 'none',
                  outline: 'none',
                  color: 'var(--text-primary)',
                  fontSize: 13,
                  width: 180
                }}
              />
            </div>

            <div style={{ display: 'flex', background: 'var(--bg-surface-0)', padding: 3, borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-default)', gap: 2 }}>
              {(['ALL', 'ACTIVE', 'TRIAL', 'SUSPENDED'] as const).map(tab => (
                <button
                  key={tab}
                  type="button"
                  onClick={() => setFilterStatus(tab)}
                  style={{
                    padding: '3px 10px',
                    fontSize: 11.5,
                    fontWeight: 600,
                    borderRadius: 4,
                    border: 'none',
                    cursor: 'pointer',
                    background: filterStatus === tab ? 'var(--accent)' : 'transparent',
                    color: filterStatus === tab ? '#ffffff' : 'var(--text-secondary)',
                    transition: 'all 0.15s ease'
                  }}
                >
                  {tab}
                </button>
              ))}
            </div>
          </div>
        </div>

        {loading ? (
          <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)' }}>Loading tenant registry...</div>
        ) : filteredOrgs.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            {orgs.length === 0 ? 'No organizations registered. Click "Onboard Organization" to create the first tenant.' : 'No organizations matching the current search/filter.'}
          </div>
        ) : (
          <table className="saas-table">
            <thead>
              <tr>
                <th>Organization</th>
                <th>License &amp; Plan</th>
                <th>Trial / Expiry</th>
                <th>Seats</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredOrgs.map(org => (
                <tr key={org.id}>
                  <td>
                    <span className="saas-org-name">{org.name}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
                      <span className="saas-org-slug">slug: {org.slug}</span>
                      {org.contact_email && (
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                          • {org.contact_email}
                        </span>
                      )}
                    </div>
                  </td>
                  <td>
                    <span className={`saas-badge ${org.is_trial ? 'trial' : org.license_tier === 'community' ? 'community' : 'paid'}`}>
                      {org.is_trial ? `${org.trial_days}d Free Trial` : org.license_tier}
                    </span>
                  </td>
                  <td>
                    {org.is_trial ? (
                      <span style={{ fontSize: 13, fontWeight: 600, color: org.days_remaining <= 3 ? '#ef4444' : '#f59e0b' }}>
                        {org.days_remaining <= 0
                          ? 'Trial Expired'
                          : org.days_remaining > 3650
                          ? `${org.trial_days || 30} days left`
                          : `${org.days_remaining} days left`}
                      </span>
                    ) : (
                      <span style={{ fontSize: 13, color: 'var(--text-secondary)' }}>
                        {org.days_remaining > 3650 ? 'Lifetime / Perpetual' : `${org.days_remaining} days left`}
                      </span>
                    )}
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)' }}>{org.max_seats}</td>
                  <td>
                    <span className={`saas-badge ${org.status.toLowerCase()}`}>
                      {org.status}
                    </span>
                  </td>
                  <td>
                    <div className="saas-actions-cell">
                      <button className="saas-btn-sm" onClick={() => {
                        setSelectedOrg(org)
                        setIsRenewTrial(org.is_trial)
                        setRenewDays(org.is_trial ? 15 : 365)
                        setShowRenewModal(true)
                      }}>
                        Extend / Renew
                      </button>
                      <button className="saas-btn-sm" onClick={() => handleRegenerateBootstrap(org)} title="Issue new single-use bootstrap token">
                        New Token
                      </button>
                      <button className="saas-btn-sm" onClick={() => handleStatusToggle(org)}>
                        {org.status === 'ACTIVE' ? 'Suspend' : 'Activate'}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Onboard Organization Modal */}
      {showCreateModal && (
        <div className="saas-modal-backdrop" onClick={() => setShowCreateModal(false)}>
          <div className="saas-modal" onClick={e => e.stopPropagation()}>
            <div className="saas-modal-header">
              <h3>Onboard New Organization</h3>
              <button className="saas-close-btn" onClick={() => setShowCreateModal(false)}>✕</button>
            </div>

            {errorMsg && (
              <div style={{ padding: 10, background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', borderRadius: 6, marginBottom: 16, fontSize: 13 }}>
                {errorMsg}
              </div>
            )}

            <form onSubmit={handleCreateOrg}>
              <div className="saas-form-group">
                <label>Organization Name</label>
                <input
                  type="text"
                  className="saas-form-input"
                  placeholder="e.g. Acme Corp"
                  value={formName}
                  onChange={e => handleNameChange(e.target.value)}
                  required
                />
              </div>

              <div className="saas-form-group">
                <label>Tenant Identifier (Slug)</label>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <input
                    type="text"
                    className="saas-form-input"
                    placeholder="acme-corp"
                    value={formSlug}
                    onChange={e => setFormSlug(e.target.value)}
                    required
                  />
                  <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>(slug)</span>
                </div>
              </div>

              <div className="saas-form-group">
                <label>Customer Administrator Email</label>
                <input
                  type="email"
                  className="saas-form-input"
                  placeholder="admin@acmecorp.com"
                  value={formEmail}
                  onChange={e => setFormEmail(e.target.value)}
                  required
                />
              </div>

              <div className="saas-form-group">
                <label>License Plan &amp; Duration</label>
                <div className="saas-radio-group">
                  <div
                    className={`saas-radio-pill ${formPlanType === 'trial15' ? 'selected' : ''}`}
                    onClick={() => setFormPlanType('trial15')}
                  >
                    <span>⭐ 15-Day Free Trial</span>
                  </div>
                  <div
                    className={`saas-radio-pill ${formPlanType === 'trial30' ? 'selected' : ''}`}
                    onClick={() => setFormPlanType('trial30')}
                  >
                    <span>🌟 30-Day Free Trial</span>
                  </div>
                  <div
                    className={`saas-radio-pill ${formPlanType === 'paid' ? 'selected' : ''}`}
                    onClick={() => setFormPlanType('paid')}
                  >
                    <span>💼 Paid Contract</span>
                  </div>
                </div>
              </div>

              {formPlanType === 'paid' && (
                <div className="saas-form-group">
                  <label>Agreed Contract Duration (Days)</label>
                  <input
                    type="number"
                    className="saas-form-input"
                    value={formCustomDays}
                    onChange={e => setFormCustomDays(Number(e.target.value))}
                    min="1"
                    placeholder="365"
                  />
                </div>
              )}

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="saas-form-group">
                  <label>License Tier</label>
                  <select
                    className="saas-form-select"
                    value={formTier}
                    onChange={e => setFormTier(e.target.value)}
                  >
                    <option value="enterprise">Enterprise (Full Suite)</option>
                    <option value="team">Team (Spend &amp; Policies)</option>
                    <option value="community">Community</option>
                  </select>
                </div>
                <div className="saas-form-group">
                  <label>Max Seat Allocation</label>
                  <input
                    type="number"
                    className="saas-form-input"
                    value={formSeats}
                    onChange={e => setFormSeats(Number(e.target.value))}
                    min="1"
                    required
                  />
                </div>
              </div>

              <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="saas-btn-sm" onClick={() => setShowCreateModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="saas-btn-primary" disabled={submitting}>
                  {submitting ? 'Minting License & Provisioning...' : 'Provision Organization'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* License Renewal / Trial Extension Modal */}
      {showRenewModal && selectedOrg && (
        <div className="saas-modal-backdrop" onClick={() => setShowRenewModal(false)}>
          <div className="saas-modal" onClick={e => e.stopPropagation()}>
            <div className="saas-modal-header">
              <h3>Extend / Renew License: {selectedOrg.name}</h3>
              <button className="saas-close-btn" onClick={() => setShowRenewModal(false)}>✕</button>
            </div>

            <form onSubmit={handleRenewLicense}>
              <div className="saas-form-group">
                <label>Extension Duration (Days)</label>
                <input
                  type="number"
                  className="saas-form-input"
                  value={renewDays}
                  onChange={e => setRenewDays(Number(e.target.value))}
                  min="1"
                  required
                />
              </div>

              <div className="saas-form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={isRenewTrial}
                    onChange={e => setIsRenewTrial(e.target.checked)}
                    style={{ marginRight: 8 }}
                  />
                  Mark as Trial Period
                </label>
              </div>

              <div style={{ marginTop: 24, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button type="button" className="saas-btn-sm" onClick={() => setShowRenewModal(false)}>
                  Cancel
                </button>
                <button type="submit" className="saas-btn-primary">
                  Mint &amp; Apply Extension
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Regenerated Bootstrap Token Modal */}
      {regeneratedToken && (
        <div className="saas-modal-backdrop" onClick={() => setRegeneratedToken(null)}>
          <div className="saas-modal" onClick={e => e.stopPropagation()} style={{ maxWidth: 520 }}>
            <div className="saas-modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{
                  width: 34,
                  height: 34,
                  borderRadius: 8,
                  background: 'rgba(16, 185, 129, 0.15)',
                  border: '1px solid rgba(16, 185, 129, 0.3)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#10b981'
                }}>
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: 16, color: 'var(--text-primary)' }}>New Bootstrap Token Generated</h3>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>{regeneratedToken.orgName}</div>
                </div>
              </div>
              <button className="saas-close-btn" onClick={() => setRegeneratedToken(null)}>✕</button>
            </div>

            <div style={{ padding: '8px 0' }}>
              <p style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 14 }}>
                Provide this single-use credential to the customer organization administrator for initial console login.
              </p>

              <div style={{
                background: 'var(--bg-surface-0)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
                padding: '12px 14px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
                marginBottom: 14
              }}>
                <code style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: 13,
                  color: '#10b981',
                  wordBreak: 'break-all'
                }}>
                  {regeneratedToken.token}
                </code>
                <button
                  type="button"
                  className="saas-btn-copy"
                  onClick={() => copyText(regeneratedToken.token, 'regen_token')}
                  style={{ flexShrink: 0 }}
                >
                  {copiedKey === 'regen_token' ? '✓ Copied!' : 'Copy Token'}
                </button>
              </div>

              <div style={{
                background: 'rgba(234, 179, 8, 0.1)',
                border: '1px solid rgba(234, 179, 8, 0.25)',
                borderRadius: 'var(--radius-sm)',
                padding: '10px 12px',
                fontSize: 12,
                color: '#eab308',
                display: 'flex',
                alignItems: 'center',
                gap: 8
              }}>
                <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                  <line x1="12" y1="9" x2="12" y2="13"/>
                  <line x1="12" y1="17" x2="12.01" y2="17"/>
                </svg>
                <span>This token will be permanently consumed upon first customer login.</span>
              </div>
            </div>

            <div style={{ marginTop: 20, display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="button"
                className="saas-btn-primary"
                onClick={() => setRegeneratedToken(null)}
              >
                Done
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
