import React, { useState, useEffect } from 'react'

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
  status: string
  created_at: string
}

export const LicenseSettings: React.FC = () => {
  const [org, setOrg] = useState<OrgSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [licenseKey, setLicenseKey] = useState('')
  const [submitting, setSubmitting] = useState(false)

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

  if (loading) {
    return <div style={{ padding: '24px', color: '#94a3b8' }}>Loading license information...</div>
  }

  const tier = (org?.license_tier || 'developer').toLowerCase()
  const maxDevices = org?.max_devices ?? 1
  const enrolledDevices = org?.enrolled_devices ?? 0
  const isUnlimited = maxDevices === -1 || maxDevices >= 999999

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

      {/* Organization Details Card */}
      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Organization Profile</div>
            <div className="soc-card-subtitle">Tenant identity and administrator contact coordinates</div>
          </div>
          <span className="soc-badge">ID: {org?.id ? org.id.substring(0, 8) + '...' : 'default'}</span>
        </div>
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
            <div style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '4px' }}>{org?.contact_email || 'admin@agentcontrol.local'}</div>
          </div>
        </div>
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
            <div style={{ fontSize: '16px', fontWeight: 600, marginTop: '6px', color: '#10b981', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span>●</span> Active
            </div>
            {org?.days_remaining !== undefined && org.days_remaining > 0 && (
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
                {org.days_remaining} days remaining
              </div>
            )}
          </div>

          <div>
            <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Features Enabled</div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', marginTop: '6px', lineHeight: 1.5 }}>
              {tier === 'enterprise'
                ? 'Unlimited Devices, OIDC SSO, Spend Caps, SIEM Streaming, Deep DLP'
                : tier === 'team'
                ? 'Up to 25 Devices, Spend Caps, Group Policies, OTET Enrollment, Alerts'
                : '1 Device, Local Gateway, Prompt Redaction, Basic JSONL Logging'}
            </div>
          </div>
        </div>
      </div>

      {/* License Activation Form */}
      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Activate License Key</div>
            <div className="soc-card-subtitle">Paste your cryptographically-signed Ed25519 license JWT below to unlock Team or Enterprise capabilities</div>
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
