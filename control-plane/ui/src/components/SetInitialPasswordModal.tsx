import { useState, FormEvent } from 'react'
import { useAuth } from '../auth/AuthContext'
import './SetInitialPasswordModal.css'

export default function SetInitialPasswordModal() {
  const { user, checkSession } = useAuth()
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)

  const isMinLength = password.length >= 8
  const isMatch = password.length > 0 && password === confirmPassword
  const canSubmit = isMinLength && isMatch && !saving

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!canSubmit) return

    setSaving(true)
    setError(null)
    setSuccessMsg(null)

    try {
      const res = await fetch('/api/v1/auth/setup-initial-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password })
      })

      if (!res.ok) {
        const txt = await res.text()
        throw new Error(txt || 'Failed to save administrator password')
      }

      setSuccessMsg('Administrator password saved successfully! Unlocking console...')
      setTimeout(async () => {
        await checkSession()
      }, 1000)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Error setting password')
      setSaving(false)
    }
  }

  return (
    <div className="sip-overlay">
      <div className="sip-modal card glass">
        <div className="sip-header">
          <div className="sip-icon-badge">
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <rect x="9" y="11" width="6" height="5" rx="1" />
              <path d="M10 11V9a2 2 0 1 1 4 0v2" />
            </svg>
          </div>
          <div className="sip-title-wrap">
            <span className="sip-badge">INITIAL SECURITY SETUP REQUIRED</span>
            <h2 className="sip-title">Set Administrator Password</h2>
          </div>
        </div>

        <p className="sip-desc">
          You are authenticated as <strong>{user?.id}</strong> for workspace <strong>{user?.organization_name || 'Organization Workspace'}</strong> via a one-time bootstrap token. Create a permanent administrator password to secure this tenant and prevent lockout.
        </p>

        {error && (
          <div className="sip-alert sip-alert-error">
            <span className="alert-icon">⚠️</span>
            <span>{error}</span>
          </div>
        )}

        {successMsg && (
          <div className="sip-alert sip-alert-success">
            <span className="alert-icon">✅</span>
            <span>{successMsg}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="sip-form">
          <div className="form-group">
            <div className="label-row" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <label htmlFor="sip-password">New Administrator Password</label>
              <button
                type="button"
                className="toggle-pwd-btn"
                onClick={() => setShowPassword(p => !p)}
                tabIndex={-1}
                style={{ background: 'none', border: 'none', color: 'var(--accent)', cursor: 'pointer', fontSize: '12px' }}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
            <div className="soc-input-wrapper" style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                id="sip-password"
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Minimum 8 characters"
                required
                autoFocus
                className="form-input"
                style={{ width: '100%' }}
              />
            </div>
            <div className="sip-hint-row" style={{ marginTop: '6px', fontSize: '12px' }}>
              <span style={{ color: isMinLength ? 'var(--success, #10b981)' : 'var(--text-muted)' }}>
                {isMinLength ? '✓' : '○'} At least 8 characters
              </span>
            </div>
          </div>

          <div className="form-group" style={{ marginTop: '14px' }}>
            <label htmlFor="sip-confirm-password">Confirm Administrator Password</label>
            <div className="soc-input-wrapper" style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                id="sip-confirm-password"
                type={showPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                placeholder="Re-enter password"
                required
                className="form-input"
                style={{ width: '100%' }}
              />
            </div>
            {confirmPassword.length > 0 && (
              <div className="sip-hint-row" style={{ marginTop: '6px', fontSize: '12px' }}>
                <span style={{ color: isMatch ? 'var(--success, #10b981)' : 'var(--danger, #ef4444)' }}>
                  {isMatch ? '✓ Passwords match' : '✕ Passwords do not match'}
                </span>
              </div>
            )}
          </div>

          <div className="sip-actions" style={{ marginTop: '24px' }}>
            <button
              type="submit"
              className="btn-primary"
              disabled={!canSubmit}
              style={{ width: '100%', padding: '12px', fontSize: '14px', fontWeight: 600, display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px' }}
            >
              {saving ? (
                <>
                  <span className="spinner" style={{ width: '14px', height: '14px', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
                  Saving Administrator Password...
                </>
              ) : (
                <>
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                    <path d="M20 6L9 17l-5-5" />
                  </svg>
                  Save Administrator Password & Continue
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
