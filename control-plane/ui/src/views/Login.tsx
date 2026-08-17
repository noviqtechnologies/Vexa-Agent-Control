import { useState, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'
import './Login.css'

interface PublicProvider {
  id: string
  type: string
  name: string
}

export default function Login() {
  const { login, error: authError } = useAuth()
  const location = useLocation()
  const queryParams = new URLSearchParams(location.search)
  const isIdleTimeout = queryParams.get('reason') === 'idle_timeout'

  // Default to operator portal if arriving at /operator or ?portal=operator
  const isInitialOperator = location.pathname.startsWith('/operator') || queryParams.get('portal') === 'operator'
  const [portalMode, setPortalMode] = useState<'tenant' | 'operator'>(isInitialOperator ? 'operator' : 'tenant')

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
          <h1 className="soc-brand-title">Vexa <span>Agent Control</span></h1>
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
          {/* Portal Selector Toggle Tabs */}
          <div className="soc-portal-toggle">
            <button
              type="button"
              className={`portal-tab ${portalMode === 'tenant' ? 'active' : ''}`}
              onClick={() => setPortalMode('tenant')}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 21h18M3 7v14M21 7v14M6 11h4M6 15h4M14 11h4M14 15h4M9 3l3-2 3 2v4H9V3z" />
              </svg>
              <span>Customer Portal</span>
            </button>
            <button
              type="button"
              className={`portal-tab ${portalMode === 'operator' ? 'active' : ''}`}
              onClick={() => setPortalMode('operator')}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10" />
                <path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20M2 12h20" />
              </svg>
              <span>SaaS Operator</span>
            </button>
          </div>

          <div className="soc-login-header">
            {portalMode === 'operator' ? (
              <>
                <div className="soc-portal-mode-badge operator">
                  <span>🌐 Platform Super-Admin Mode</span>
                </div>
                <h2>SaaS Platform Operator Portal</h2>
                <p>Multi-tenant infrastructure control, organization provisioning, license minting, and global fleet operations.</p>
              </>
            ) : (
              <>
                <div className="soc-portal-mode-badge tenant">
                  <span>🏢 Customer Workspace Mode</span>
                </div>
                <h2>Customer Organization Console</h2>
                <p>Sign in to govern your AI developers, IDE workstations, policies, and spend limits.</p>
              </>
            )}
          </div>

          {isIdleTimeout && !authError && (
            <div style={{
              background: 'rgba(245, 158, 11, 0.15)',
              border: '1px solid rgba(245, 158, 11, 0.35)',
              borderRadius: '8px',
              padding: '12px 14px',
              marginBottom: '16px',
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              color: '#fbbf24',
              fontSize: '0.88rem',
              lineHeight: 1.4,
            }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ flexShrink: 0 }}>
                <circle cx="12" cy="12" r="10" />
                <polyline points="12 6 12 12 16 14" />
              </svg>
              <span>Your session expired due to 15 minutes of inactivity. Please sign in again.</span>
            </div>
          )}

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
                    <label htmlFor="login-email">
                      {portalMode === 'operator' ? 'Platform Super-Admin Username / Email' : 'Organization Email or Username'}
                    </label>
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
                        placeholder={portalMode === 'operator' ? 'admin or operator@vexasec.io' : 'secops@yourcompany.com or admin'}
                        required
                        autoFocus
                      />
                    </div>
                  </div>

                  <div className="form-group">
                    <div className="label-row">
                      <label htmlFor="login-password">
                        {portalMode === 'operator' ? 'Master Password or Bootstrap Secret' : 'Password or SSO Token'}
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
                    {submitting ? 'Authenticating...' : portalMode === 'operator' ? 'Sign In as SaaS Super-Admin →' : 'Sign In to Customer Workspace →'}
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
          <span>Zero-Trust Control Plane v1.0.35</span>
        </div>
      </div>
    </div>
  )
}

function ProviderIcon({ type }: { type: string }) {
  if (type === 'entra') {
    return (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
        <path fill="#F25022" d="M1 1h10v10H1z"/>
        <path fill="#00A4EF" d="M1 13h10v10H1z"/>
        <path fill="#7FBA00" d="M13 1h10v10H13z"/>
        <path fill="#FFB900" d="M13 13h10v10H13z"/>
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
