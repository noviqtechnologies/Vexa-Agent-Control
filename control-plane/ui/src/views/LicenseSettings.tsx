import React, { useState, useEffect } from 'react'
import { useAuth } from '../auth/AuthContext'

interface OrgSummary {
  id: string
  name: string
  slug: string
  contact_email: string
  license_tier: string
  max_devices: number
  enrolled_devices: number
  license_expires_at?: string
  days_remaining: number
  has_license_key?: boolean
  is_evaluation_expired?: boolean
  status: string
  created_at: string
}

export const LicenseSettings: React.FC = () => {
  const { checkSession } = useAuth()
  const [org, setOrg] = useState<OrgSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [licenseKey, setLicenseKey] = useState('')
  const [submitting, setSubmitting] = useState(false)

  // Organization editing state
  const [editingOrg, setEditingOrg] = useState(false)
  const [orgName, setOrgName] = useState('')
  const [contactEmail, setContactEmail] = useState('')
  const [updatingOrg, setUpdatingOrg] = useState(false)

  const fetchOrgSummary = async () => {
    try {
      setLoading(true)
      const res = await fetch('/api/v1/organization')
      if (res.ok) {
        const data = await res.json()
        setOrg(data)
      } else {
        setError('Failed to load organization settings')
      }
    } catch {
      setError('Network error while loading organization settings')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchOrgSummary()
  }, [])

  const handleActivateLicense = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!licenseKey.trim()) return

    setSubmitting(true)
    setError(null)
    setSuccess(null)

    try {
      const res = await fetch('/api/v1/license/activate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ license_key_jwt: licenseKey.trim() }),
      })

      if (res.ok) {
        setSuccess('License activated successfully!')
        setLicenseKey('')
        await fetchOrgSummary()
      } else {
        const text = await res.text()
        setError(`Activation failed: ${text || 'Invalid license token'}`)
      }
    } catch {
      setError('Network error while activating license')
    } finally {
      setSubmitting(false)
    }
  }

  const handleUpdateOrg = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!orgName.trim()) {
      setError('Organization name cannot be empty')
      return
    }

    setUpdatingOrg(true)
    setError(null)
    setSuccess(null)

    try {
      const res = await fetch('/api/v1/organization', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: orgName.trim(),
          contact_email: contactEmail.trim(),
        }),
      })

      if (res.ok) {
        setSuccess('Organization details updated successfully!')
        setEditingOrg(false)
        await fetchOrgSummary()
        await checkSession()
      } else {
        const text = await res.text()
        setError(`Update failed: ${text || 'Could not update organization'}`)
      }
    } catch {
      setError('Network error while updating organization')
    } finally {
      setUpdatingOrg(false)
    }
  }

  if (loading) {
    return <div style={{ padding: '24px', color: '#94a3b8' }}>Loading license information...</div>
  }

  const tier = (org?.license_tier || 'developer').toLowerCase()
  const maxDevices = org?.max_devices ?? 5
  const enrolledDevices = org?.enrolled_devices ?? 0
  const isUnlimited = maxDevices === -1 || maxDevices >= 999999
  const hasLicense = Boolean(org?.has_license_key)
  const isQuotaReached = !isUnlimited && enrolledDevices >= maxDevices && !hasLicense

  return (
    <div className="soc-license-page" style={{ maxWidth: '1000px', margin: '0 auto' }}>
      <div className="page-header soc-page-header">
        <div>
          <h1>Organization & License</h1>
          <p>Manage your organization profile, active license tier, and enrolled device capacity.</p>
        </div>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: 'var(--danger-dim)', border: '1px solid rgba(239, 68, 68, 0.4)', borderRadius: 'var(--radius-sm)', color: '#fca5a5', marginBottom: '16px', fontSize: '14px' }}>
          {error}
        </div>
      )}

      {success && (
        <div style={{ padding: '12px 16px', background: 'var(--success-dim)', border: '1px solid rgba(16, 185, 129, 0.4)', borderRadius: 'var(--radius-sm)', color: '#86efac', marginBottom: '16px', fontSize: '14px' }}>
          {success}
        </div>
      )}

      {/* Quota Reached Alert */}
      {isQuotaReached && (
        <div style={{
          padding: '14px 18px',
          background: 'rgba(245, 158, 11, 0.15)',
          border: '1px solid rgba(245, 158, 11, 0.4)',
          borderRadius: 'var(--radius-md, 8px)',
          color: '#fcd34d',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          fontSize: '13.5px'
        }}>
          <span style={{ fontSize: '20px' }}>⚡</span>
          <div style={{ flex: 1 }}>
            <strong>Early Access Capacity Reached ({enrolledDevices}/{maxDevices} devices):</strong> You have reached the 5-device Early Access limit. Once we reach GA, up to 50 devices will be supported. To connect more than 5 devices now, please activate your Enterprise license key below.
          </div>
        </div>
      )}

      {/* Early Access Preview Banner */}
      <div style={{
        padding: '16px 20px',
        background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.12) 0%, rgba(99, 102, 241, 0.08) 100%)',
        border: '1px solid rgba(59, 130, 246, 0.3)',
        borderRadius: 'var(--radius-md, 8px)',
        marginBottom: '20px',
        display: 'flex',
        alignItems: 'flex-start',
        gap: '14px'
      }}>
        <div style={{ fontSize: '24px', lineHeight: 1 }}>🚀</div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)' }}>
            Early Access Preview — Up to 5 Devices
          </div>
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '4px', lineHeight: 1.5 }}>
            Vexa Team Hub is currently in Early Access with a 5-device limit. Fleet governance, spend caps, and SSE sync are fully unlocked with no time restriction. Activating a license key is required only to connect more than 5 devices or once GA (up to 50 devices) ships.
          </div>
          <div style={{ display: 'flex', gap: '12px', marginTop: '8px', fontSize: '12.5px' }}>
            <a href="https://discord.gg/vexasec" target="_blank" rel="noreferrer" style={{ color: '#60a5fa', textDecoration: 'underline' }}>
              Join Community Discord ➔
            </a>
            <span style={{ color: 'var(--text-muted)' }}>•</span>
            <a href="mailto:early-access@vexasec.io" style={{ color: '#60a5fa', textDecoration: 'underline' }}>
              Request Quota Expansion (early-access@vexasec.io) ➔
            </a>
          </div>
        </div>
      </div>

      {/* Organization Details Card */}
      <div className="card soc-panel">
        <div className="soc-card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <div className="card-title">Organization Profile</div>
            <div className="soc-card-subtitle">Tenant identity and administrator contact coordinates</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span className="soc-badge">ID: {org?.id ? org.id.substring(0, 8) + '...' : 'default'}</span>
            {!editingOrg && (
              <button
                type="button"
                className="soc-btn-secondary"
                onClick={() => {
                  setOrgName(org?.name || 'Primary Organization')
                  setContactEmail(org?.contact_email || '')
                  setEditingOrg(true)
                }}
                style={{ fontSize: '12px', padding: '5px 12px', display: 'inline-flex', alignItems: 'center', gap: '6px' }}
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/>
                  <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>
                </svg>
                Change Name
              </button>
            )}
          </div>
        </div>

        {editingOrg ? (
          <form onSubmit={handleUpdateOrg} style={{ marginTop: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '16px', marginBottom: '16px' }}>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Organization Name <span style={{ color: 'var(--danger)' }}>*</span>
                </label>
                <input
                  type="text"
                  value={orgName}
                  onChange={(e) => setOrgName(e.target.value)}
                  placeholder="e.g. Acme Corp"
                  required
                  autoFocus
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    fontSize: '13.5px',
                    background: 'var(--bg-surface-1)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--text-primary)',
                    boxSizing: 'border-box',
                    outline: 'none',
                  }}
                />
              </div>
              <div>
                <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Contact Email
                </label>
                <input
                  type="email"
                  value={contactEmail}
                  onChange={(e) => setContactEmail(e.target.value)}
                  placeholder="admin@example.com"
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    fontSize: '13.5px',
                    background: 'var(--bg-surface-1)',
                    border: '1px solid var(--border-default)',
                    borderRadius: 'var(--radius-sm)',
                    color: 'var(--text-primary)',
                    boxSizing: 'border-box',
                    outline: 'none',
                  }}
                />
              </div>
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                type="button"
                className="soc-btn-secondary"
                onClick={() => setEditingOrg(false)}
                disabled={updatingOrg}
                style={{ fontSize: '12.5px', padding: '6px 14px' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="soc-btn-primary"
                disabled={updatingOrg || !orgName.trim()}
                style={{ fontSize: '12.5px', padding: '6px 16px' }}
              >
                {updatingOrg ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '20px' }}>
            <div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Organization Name</div>
              <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px' }}>{org?.name || 'Primary Organization'}</div>
            </div>
            <div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Organization Slug</div>
              <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>{org?.slug || 'default'}</div>
            </div>
            <div>
              <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Contact Email</div>
              <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px' }}>{org?.contact_email || '—'}</div>
            </div>
          </div>
        )}
      </div>

      {/* License Tier Card */}
      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Active License Tier</div>
            <div className="soc-card-subtitle">Zero-Trust entitlement enforcement and seat quota</div>
          </div>
          <span className={`soc-delta-badge ${tier === 'enterprise' ? 'delta-success' : tier === 'team' ? 'delta-warning' : 'delta-neutral'}`} style={{ padding: '4px 12px', fontSize: '12px', fontWeight: 700, textTransform: 'uppercase' }}>
            {tier}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '24px' }}>
          <div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Enrolled Devices</div>
            <div style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px' }}>
              {enrolledDevices} / {isUnlimited ? 'Unlimited' : maxDevices}
            </div>
            <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              {isUnlimited ? 'No device enrollment cap' : `${Math.max(0, maxDevices - enrolledDevices)} device slots remaining`}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>License Status</div>
            <div style={{
              fontSize: '16px',
              fontWeight: 600,
              marginTop: '6px',
              color: hasLicense ? '#10b981' : '#10b981',
              display: 'flex',
              alignItems: 'center',
              gap: '6px'
            }}>
              <span>●</span> {hasLicense ? 'Active (Licensed)' : 'Active (Early Access)'}
            </div>
            {org?.license_expires_at && (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {`License expires: ${new Date(org.license_expires_at).toLocaleDateString()}`}
              </div>
            )}
          </div>

          <div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Features Enabled</div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: 1.5 }}>
              {tier === 'enterprise'
                ? 'Unlimited Devices, OIDC SSO, Spend Caps, SIEM Streaming, Deep DLP'
                : tier === 'team'
                ? 'Up to 5 Devices (Early Access — Up to 50 at GA), Spend Caps, Real-Time SSE Policy Push, Vault Key Custody, Group Policies, OTET Enrollment, Aggregated Audit, Alerts'
                : 'Up to 5 Devices, Local Gateway, Prompt Redaction, Basic JSONL Logging'}
            </div>
          </div>
        </div>
      </div>

      {/* License Activation Form */}
      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Activate Design Partner / Enterprise License</div>
            <div className="soc-card-subtitle">Required to connect more than 5 devices. Paste your Ed25519 license JWT below to activate custom SLA and expanded fleet capacity</div>
          </div>
        </div>

        <form onSubmit={handleActivateLicense}>
          <textarea
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            placeholder="eyJhbGciOiJFZERTQSI..."
            rows={4}
            style={{
              width: '100%',
              padding: '12px',
              fontFamily: 'var(--font-mono)',
              fontSize: '12.5px',
              background: 'var(--bg-surface-1)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-sm)',
              color: 'var(--text-primary)',
              boxSizing: 'border-box',
              resize: 'vertical',
              outline: 'none',
            }}
          />
          <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              disabled={submitting || !licenseKey.trim()}
              className="soc-btn-primary"
            >
              {submitting ? 'Verifying...' : 'Activate License'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
export default LicenseSettings
