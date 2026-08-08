import { useState, useEffect } from 'react'
import { useAuth } from '../auth/AuthContext'
import './Login.css'

interface PublicProvider {
  id: string
  type: string
  name: string
}

export default function Login() {
  const { login, error: authError } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  
  const [providers, setProviders] = useState<PublicProvider[]>([])
  const [loadingProviders, setLoadingProviders] = useState(true)

  useEffect(() => {
    async function fetchProviders() {
      try {
        const res = await fetch('/api/v1/auth/providers')
        if (res.ok) {
          const data = await res.json()
          setProviders(Array.isArray(data) ? data : [])
        }
      } catch (err) {
        console.error('Failed to fetch providers', err)
      } finally {
        setLoadingProviders(false)
      }
    }
    fetchProviders()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    try {
      await login(email, password)
    } finally {
      setSubmitting(false)
    }
  }

  const oauthProviders = providers.filter(p => p.type !== 'local')
  const hasLocal = providers.some(p => p.type === 'local')
  const noProviders = providers.length === 0

  return (
    <div className="soc-login-viewport">
      {/* Background cyber grid and ambient glow */}
      <div className="soc-login-ambient-glow" />
      <div className="soc-login-grid-overlay" />

      <div className="soc-login-card-wrapper">
        {/* Brand Shield & Header */}
        <div className="soc-login-brand">
          <div className="soc-brand-icon-wrapper">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M9 12l2 2 4-4" />
            </svg>
          </div>
          <h1 className="soc-brand-title">Vexa <span>Agentwall</span></h1>
          <p className="soc-brand-tagline">Autonomous AI Security Gateway & Control Plane</p>
        </div>

        {/* Security Assurance Feature Pills */}
        <div className="soc-security-pills">
          <span className="sec-pill">
            <span className="pill-dot" /> Default-Deny Core
          </span>
          <span className="sec-pill">
            <span className="pill-dot" /> Hardware PKI
          </span>
          <span className="sec-pill">
            <span className="pill-dot" /> Dual-Pass DLP
          </span>
        </div>

        {/* Glassmorphic Login Card */}
        <div className="soc-login-card">
          <div className="soc-login-header">
            <h2>SOC Dashboard Access</h2>
            <p>Authenticate with workstation credentials or enterprise SSO</p>
          </div>

          {authError && (
            <div className="soc-login-error">
              <div className="error-icon">⚠️</div>
              <div className="error-text">{authError}</div>
            </div>
          )}

          {loadingProviders ? (
            <div className="soc-login-loading">
              <div className="soc-spinner" />
              <span>Verifying authentication providers...</span>
            </div>
          ) : (
            <div className="login-methods">
              {(hasLocal || noProviders) && (
                <form onSubmit={handleSubmit} className="local-login-form">
                  <div className="form-group">
                    <label htmlFor="login-email">Email or Operator Username</label>
                    <div className="soc-input-wrapper">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="input-icon">
                        <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                        <circle cx="12" cy="7" r="4" />
                      </svg>
                      <input
                        id="login-email"
                        type="text"
                        value={email}
                        onChange={e => setEmail(e.target.value)}
                        placeholder="admin or secops@enterprise.internal"
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="form-group">
                    <div className="label-row">
                      <label htmlFor="login-password">
                        {noProviders ? 'Password or Bootstrap Token' : 'Password'}
                      </label>
                      <button
                        type="button"
                        className="toggle-pwd-btn"
                        onClick={() => setShowPassword(prev => !prev)}
                        tabIndex={-1}
                      >
                        {showPassword ? 'Hide' : 'Show'}
                      </button>
                    </div>
                    <div className="soc-input-wrapper">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="input-icon">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      <input
                        id="login-password"
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={e => setPassword(e.target.value)}
                        placeholder="••••••••••••"
                        required
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    className="soc-login-submit-btn"
                    disabled={submitting}
                  >
                    {submitting ? 'Authenticating...' : 'Sign In to Control Plane →'}
                  </button>
                </form>
              )}

              {oauthProviders.length > 0 && (
                <>
                  {(hasLocal || noProviders) && (
                    <div className="soc-login-divider">
                      <span>OR ENTERPRISE SSO</span>
                    </div>
                  )}
                  <div className="oauth-buttons">
                    {oauthProviders.map(p => (
                      <button
                        key={p.id}
                        type="button"
                        className={`oauth-btn oauth-btn-${p.type}`}
                        onClick={() => { window.location.href = `/api/v1/auth/oauth/${p.id}/login` }}
                      >
                        <ProviderIcon type={p.type} />
                        <span>Continue with {p.name}</span>
                      </button>
                    ))}
                  </div>
                </>
              )}
            </div>
          )}
        </div>

        {/* Security Attestation Footer */}
        <div className="soc-login-footer">
          <span>🔒 FIPS / HMAC Audit Chain Verified</span>
          <span>&bull;</span>
          <span>Zero-Trust Control Plane v0.1.0</span>
        </div>
      </div>
    </div>
  )
}

function ProviderIcon({ type }: { type: string }) {
  if (type === 'github') {
    return (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
      </svg>
    )
  }
  if (type === 'google') {
    return (
      <svg width="18" height="18" viewBox="0 0 24 24">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
      </svg>
    )
  }
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  )
}
