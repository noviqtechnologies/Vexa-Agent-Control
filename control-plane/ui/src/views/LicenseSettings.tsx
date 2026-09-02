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
    <div style={{ padding: '24px', maxWidth: '900px', margin: '0 auto', color: '#f8fafc' }}>
      <div style={{ marginBottom: '24px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, margin: '0 0 8px 0' }}>Organization & License</h1>
        <p style={{ fontSize: '14px', color: '#94a3b8', margin: 0 }}>
          Manage your organization profile, active license tier, and enrolled device capacity.
        </p>
      </div>

      {error && (
        <div style={{ padding: '12px 16px', background: '#ef444420', border: '1px solid #ef444460', borderRadius: '6px', color: '#fca5a5', marginBottom: '16px', fontSize: '14px' }}>
          {error}
        </div>
      )}

      {success && (
        <div style={{ padding: '12px 16px', background: '#22c55e20', border: '1px solid #22c55e60', borderRadius: '6px', color: '#86efac', marginBottom: '16px', fontSize: '14px' }}>
          {success}
        </div>
      )}

      {/* Organization Details Card */}
      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '20px', marginBottom: '20px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 600, margin: '0 0 16px 0', color: '#e2e8f0' }}>Organization Profile</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          <div>
            <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Organization Name</div>
            <div style={{ fontSize: '15px', fontWeight: 500, marginTop: '4px' }}>{org?.name || 'Primary Organization'}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Organization Slug</div>
            <div style={{ fontSize: '15px', fontWeight: 500, marginTop: '4px' }}>{org?.slug || 'default'}</div>
          </div>
          <div>
            <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Contact Email</div>
            <div style={{ fontSize: '15px', fontWeight: 500, marginTop: '4px' }}>{org?.contact_email || 'admin@agentcontrol.local'}</div>
          </div>
        </div>
      </div>

      {/* License Tier Card */}
      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '20px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
          <h2 style={{ fontSize: '16px', fontWeight: 600, margin: 0, color: '#e2e8f0' }}>Active License Tier</h2>
          <span style={{
            padding: '4px 10px',
            borderRadius: '12px',
            fontSize: '12px',
            fontWeight: 700,
            textTransform: 'uppercase',
            background: tier === 'enterprise' ? '#8b5cf630' : tier === 'team' ? '#3b82f630' : '#64748b30',
            color: tier === 'enterprise' ? '#c084fc' : tier === 'team' ? '#60a5fa' : '#cbd5e1',
            border: `1px solid ${tier === 'enterprise' ? '#8b5cf660' : tier === 'team' ? '#3b82f660' : '#64748b60'}`,
          }}>
            {tier}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px' }}>
          <div>
            <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Enrolled Devices</div>
            <div style={{ fontSize: '20px', fontWeight: 700, marginTop: '4px' }}>
              {enrolledDevices} / {isUnlimited ? 'Unlimited' : maxDevices}
            </div>
            <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>
              {isUnlimited ? 'No device enrollment cap' : `${Math.max(0, maxDevices - enrolledDevices)} device slots remaining`}
            </div>
          </div>

          <div>
            <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>License Status</div>
            <div style={{ fontSize: '15px', fontWeight: 500, marginTop: '4px', color: '#4ade80' }}>
              Active
            </div>
            {org?.days_remaining !== undefined && org.days_remaining > 0 && (
              <div style={{ fontSize: '12px', color: '#94a3b8', marginTop: '2px' }}>
                {org.days_remaining} days remaining
              </div>
            )}
          </div>

          <div>
            <div style={{ fontSize: '12px', color: '#94a3b8', textTransform: 'uppercase' }}>Features Enabled</div>
            <div style={{ fontSize: '13px', color: '#cbd5e1', marginTop: '4px' }}>
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
      <div style={{ background: '#1e293b', border: '1px solid #334155', borderRadius: '8px', padding: '20px' }}>
        <h2 style={{ fontSize: '16px', fontWeight: 600, margin: '0 0 8px 0', color: '#e2e8f0' }}>Activate License Key</h2>
        <p style={{ fontSize: '13px', color: '#94a3b8', margin: '0 0 16px 0' }}>
          Paste your cryptographically-signed Ed25519 license JWT below to unlock Team or Enterprise capabilities.
        </p>

        <form onSubmit={handleActivateLicense}>
          <textarea
            value={licenseKey}
            onChange={(e) => setLicenseKey(e.target.value)}
            placeholder="eyJhbGciOiJFZERTQSI..."
            rows={4}
            style={{
              width: '100%',
              padding: '10px',
              fontFamily: 'monospace',
              fontSize: '12px',
              background: '#0f172a',
              border: '1px solid #334155',
              borderRadius: '6px',
              color: '#f8fafc',
              boxSizing: 'border-box',
              resize: 'vertical',
            }}
          />
          <div style={{ marginTop: '12px', display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              disabled={submitting || !licenseKey.trim()}
              style={{
                padding: '8px 16px',
                background: submitting || !licenseKey.trim() ? '#475569' : '#2563eb',
                color: '#fff',
                border: 'none',
                borderRadius: '6px',
                fontWeight: 600,
                fontSize: '13px',
                cursor: submitting || !licenseKey.trim() ? 'not-allowed' : 'pointer',
              }}
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
