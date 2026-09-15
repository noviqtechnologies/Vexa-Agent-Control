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

  const [authMode, setAuthMode] = useState<'password' | 'sso'>('password')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [rememberDevice, setRememberDevice] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [showHelpModal, setShowHelpModal] = useState(false)
  const [showSecurityModal, setShowSecurityModal] = useState(false)
  const [mobileCapOpen, setMobileCapOpen] = useState(false)
  
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
      const returnTo = queryParams.get('return_to')
      if (returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.includes('\\')) {
        window.location.href = returnTo
        return
      }
    } finally {
      setSubmitting(false)
    }
  }

  const returnTo = queryParams.get('return_to')
  const getOAuthLoginUrl = (providerId: string) => {
    if (returnTo && returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.includes('\\')) {
      return `/api/v1/auth/oauth/${providerId}/login?return_to=${encodeURIComponent(returnTo)}`
    }
    return `/api/v1/auth/oauth/${providerId}/login`
  }

  const oauthProviders = providers.filter(p => p.type !== 'local')

  return (
    <div className="soc-login-viewport">
      {/* Refined ambient atmosphere */}
      <div className="soc-login-ambient-glow" aria-hidden="true" />
      <div className="soc-login-ambient-secondary" aria-hidden="true" />
      <div className="soc-login-grid-overlay" aria-hidden="true" />

      <div className="soc-login-container">
        {/* Left Column: Brand Identity, Value Proposition & Capabilities (Desktop) */}
        <aside className="soc-brand-column">
          <div className="soc-brand-top">
            <a
              href="https://vexasec.io"
              target="_blank"
              rel="noopener noreferrer"
              className="soc-brand-pill"
              title="Visit Vexa Security Official Website"
            >
              <span className="soc-brand-pill-dot" />
              <span>vexasec.io</span>
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                <path d="M7 17L17 7M7 7h10v10" />
              </svg>
            </a>

            <div className="soc-brand-badge-row">
              <div className="soc-brand-icon-wrapper" aria-hidden="true">
                <svg width="34" height="34" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="soc-shield-svg">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" className="shield-outline" />
                  <path d="M9 12l2 2 4-4" className="shield-check" />
                </svg>
                <span className="soc-icon-glow" />
              </div>
              <div className="soc-brand-headings">
                <h1 className="soc-brand-title">
                  <span className="brand-accent">Vexa</span> <span>Agent Control</span>
                </h1>
                <p className="soc-brand-tagline">Autonomous AI Security Gateway &amp; Control Plane</p>
              </div>
            </div>

            <p className="soc-brand-mission">
              Secure access to your organization’s AI control plane. Real-time MCP firewalling, data loss prevention, and atomic spend controls for autonomous agents and developer workspaces.
            </p>
          </div>

          {/* Core AI Governance Capabilities Grid */}
          <section className="soc-capabilities-container" aria-label="Core Governance Capabilities">
            <div className="soc-capabilities-header">
              <span className="soc-cap-line" />
              <h2 className="soc-cap-title">CORE AI GOVERNANCE CAPABILITIES</h2>
              <span className="soc-cap-line" />
            </div>
            <div className="soc-capabilities-grid">
              <div className="soc-capability-item">
                <div className="soc-cap-icon-box" aria-hidden="true">🛡️</div>
                <div className="soc-cap-text">
                  <strong>Zero-Trust MCP Firewall</strong>
                  <p>Schema validation, loop defense &amp; tool parameter sanitization</p>
                </div>
              </div>
              <div className="soc-capability-item">
                <div className="soc-cap-icon-box" aria-hidden="true">🔒</div>
                <div className="soc-cap-text">
                  <strong>Dual-Pass Inline DLP</strong>
                  <p>21-pattern real-time credential, token &amp; private key redacting</p>
                </div>
              </div>
              <div className="soc-capability-item">
                <div className="soc-cap-icon-box" aria-hidden="true">🧠</div>
                <div className="soc-cap-text">
                  <strong>Prompt Injection Shield</strong>
                  <p>Multi-layer defense for jailbreaks, covert directives &amp; overrides</p>
                </div>
              </div>
              <div className="soc-capability-item">
                <div className="soc-cap-icon-box" aria-hidden="true">⚡</div>
                <div className="soc-cap-text">
                  <strong>Semantic Vector Cache</strong>
                  <p>Sub-3ms exact SHA-256 + cosine similarity token cost reduction</p>
                </div>
              </div>
              <div className="soc-capability-item">
                <div className="soc-cap-icon-box" aria-hidden="true">💰</div>
                <div className="soc-cap-text">
                  <strong>Fail-Closed Spend Caps</strong>
                  <p>Atomic balance preflight reservations &amp; exact stream settlements</p>
                </div>
              </div>
              <div className="soc-capability-item">
                <div className="soc-cap-icon-box" aria-hidden="true">👁️</div>
                <div className="soc-cap-text">
                  <strong>HMAC-SHA256 Forensics</strong>
                  <p>Cryptographically signed audit logs &amp; non-blocking SIEM export</p>
                </div>
              </div>
            </div>
          </section>

          {/* Left Column Security Reassurance */}
          <div className="soc-side-trust-banner">
            <div className="trust-pill">
              <span className="trust-dot" />
              <span>TLS 1.3 Strict</span>
            </div>
            <div className="trust-pill">
              <span className="trust-shield">🛡️</span>
              <span>FIPS 140-3 Cryptographic Integrity</span>
            </div>
          </div>
        </aside>

        {/* Right Column: Dominant Login Authentication Card */}
        <div className="soc-auth-column">
          {/* Compact brand header visible on smaller viewports */}
          <div className="soc-mobile-brand-header">
            <div className="soc-brand-icon-wrapper small" aria-hidden="true">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="soc-shield-svg">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" className="shield-outline" />
                <path d="M9 12l2 2 4-4" className="shield-check" />
              </svg>
            </div>
            <div>
              <span className="mobile-brand-title"><strong>Vexa</strong> Agent Control</span>
              <span className="mobile-brand-sub">Autonomous AI Security Gateway</span>
            </div>
          </div>

          <main className="soc-login-card" role="main" aria-labelledby="login-title">
            {/* Header with Mode Badge & High-Contrast Typography */}
            <div className="soc-login-header">
              <div className="soc-portal-mode-badge tenant">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <span>Dedicated Control Hub</span>
              </div>
              <h2 id="login-title" className="soc-card-title" aria-label="Control Hub Console: Sign in to your organization">
                <span>Sign in to your organization</span>
                <span className="soc-card-title-subtitle">Security Operations &amp; AI Governance</span>
              </h2>
              <p className="soc-card-desc">
                Sign in to manage AI developers, agent fleets, zero-trust policies, and spending limits.
              </p>
            </div>

            {/* Session Expired / Inactivity Banner */}
            {isIdleTimeout && !authError && (
              <div className="soc-login-idle-alert" role="alert">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <circle cx="12" cy="12" r="10" />
                  <polyline points="12 6 12 12 16 14" />
                </svg>
                <div className="alert-text-group">
                  <strong>Session Expired</strong>
                  <span>Your session expired due to 15 minutes of inactivity. Please sign in again.</span>
                </div>
              </div>
            )}

            {/* Authentication Failure Banner */}
            {authError && (
              <div className="soc-login-error" role="alert">
                <div className="error-icon" aria-hidden="true">⚠️</div>
                <div className="alert-text-group">
                  <strong>Authentication Failed</strong>
                  <span className="error-text">{authError}</span>
                </div>
              </div>
            )}

            {loadingProviders ? (
              <div className="soc-login-loading">
                <div className="soc-spinner" />
                <span>Verifying authentication providers...</span>
              </div>
            ) : (
              <div className="login-methods">
                {/* Method Navigation Tabs: Render only when SSO providers are actually configured */}
                {oauthProviders.length > 0 && (
                  <div className="soc-auth-nav" role="tablist" aria-label="Authentication Options">
                    <button
                      type="button"
                      role="tab"
                      id="tab-password"
                      aria-selected={authMode === 'password'}
                      aria-controls="panel-password"
                      className={`soc-tab-btn ${authMode === 'password' ? 'active' : ''}`}
                      onClick={() => setAuthMode('password')}
                    >
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                        <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                        <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                      </svg>
                      <span>Sign in with password</span>
                    </button>

                    <button
                      type="button"
                      role="tab"
                      id="tab-sso"
                      aria-selected={authMode === 'sso'}
                      aria-controls="panel-sso"
                      className={`soc-tab-btn ${authMode === 'sso' ? 'active' : ''}`}
                      onClick={() => setAuthMode('sso')}
                    >
                      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                        <path d="M16 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
                        <circle cx="8.5" cy="7" r="4" />
                        <line x1="20" y1="8" x2="20" y2="14" />
                        <line x1="23" y1="11" x2="17" y2="11" />
                      </svg>
                      <span>Continue with SSO</span>
                    </button>
                  </div>
                )}

                {/* TAB PANEL: Password Sign-in */}
                {authMode === 'password' && (
                  <form onSubmit={handleSubmit} className="local-login-form" id="panel-password" role="tabpanel" aria-labelledby="tab-password">
                    <div className="form-group">
                      <label htmlFor="login-email">
                        Work email or username
                      </label>
                      <div className="soc-input-wrapper">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="input-icon" aria-hidden="true">
                          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                          <circle cx="12" cy="7" r="4" />
                        </svg>
                        <input
                          id="login-email"
                          type="text"
                          value={email}
                          onChange={e => setEmail(e.target.value)}
                          placeholder="name@company.com or username"
                          required
                          autoFocus
                          autoComplete="username"
                          autoCapitalize="none"
                          spellCheck="false"
                        />
                      </div>
                    </div>

                    <div className="form-group">
                      <div className="label-row">
                        <label htmlFor="login-password">
                          Password
                        </label>
                        <button
                          type="button"
                          className="help-link-btn"
                          onClick={() => setShowHelpModal(true)}
                          aria-label="Need help? Forgot password?"
                        >
                          Forgot password? <span className="help-subtext">(Need help?)</span>
                        </button>
                      </div>
                      <div className="soc-input-wrapper">
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="input-icon" aria-hidden="true">
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
                          autoComplete="current-password"
                        />
                        <button
                          type="button"
                          className="soc-pwd-toggle"
                          onClick={() => setShowPassword(prev => !prev)}
                          title={showPassword ? 'Hide password' : 'Show password'}
                          aria-label={showPassword ? 'Hide password' : 'Show password'}
                        >
                          {showPassword ? (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                              <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                              <line x1="1" y1="1" x2="23" y2="23" />
                            </svg>
                          ) : (
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                              <circle cx="12" cy="12" r="3" />
                            </svg>
                          )}
                        </button>
                      </div>
                    </div>

                    {/* Trust Device Option - Unchecked by Default with Helper Guidance */}
                    <div className="soc-form-options">
                      <label className="soc-checkbox-label">
                        <input
                          type="checkbox"
                          checked={rememberDevice}
                          onChange={e => setRememberDevice(e.target.checked)}
                          className="soc-checkbox-input"
                        />
                        <div className="soc-checkbox-content">
                          <span className="soc-checkbox-text">Trust this device for 30 days</span>
                          <span className="soc-checkbox-hint">Do not select on shared or public computers.</span>
                        </div>
                      </label>
                    </div>

                    <button
                      type="submit"
                      className="soc-login-submit-btn"
                      disabled={submitting}
                    >
                      {submitting ? (
                        <span className="btn-loading-content">
                          <span className="btn-spinner" />
                          <span>Authenticating...</span>
                        </span>
                      ) : (
                        <span>Sign In to Control Hub →</span>
                      )}
                    </button>
                  </form>
                )}

                {/* TAB PANEL: Dedicated Enterprise SSO */}
                {authMode === 'sso' && oauthProviders.length > 0 && (
                  <div className="soc-sso-panel" id="panel-sso" role="tabpanel" aria-labelledby="tab-sso">
                    <div className="sso-panel-intro">
                      <p>
                        Federated enterprise single sign-on with multi-factor authentication (MFA) governed by your company IdP.
                      </p>
                    </div>

                    <div className="oauth-buttons">
                      {oauthProviders.map(p => (
                        <button
                          key={p.id}
                          type="button"
                          className={`oauth-btn oauth-btn-${p.type}`}
                          onClick={() => { window.location.href = getOAuthLoginUrl(p.id) }}
                        >
                          <ProviderIcon type={p.type} />
                          <span>Continue with {p.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Quick Enterprise SSO buttons visible below Password form for instant access */}
                {authMode === 'password' && oauthProviders.length > 0 && (
                  <div className="soc-quick-sso-section">
                    <div className="soc-login-divider">
                      <span>OR CONTINUE WITH ENTERPRISE SSO</span>
                    </div>
                    <div className="oauth-buttons">
                      {oauthProviders.map(p => (
                        <button
                          key={p.id}
                          type="button"
                          className={`oauth-btn oauth-btn-${p.type}`}
                          onClick={() => { window.location.href = getOAuthLoginUrl(p.id) }}
                        >
                          <ProviderIcon type={p.type} />
                          <span>Continue with {p.name}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Concise Security Reassurance Near Form */}
            <div className="soc-form-security-reassurance">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="reassurance-lock" aria-hidden="true">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              <span>Encrypted connection (TLS 1.3) &bull; Session activity is audit logged &bull; </span>
              <button
                type="button"
                className="reassurance-link"
                onClick={() => setShowSecurityModal(true)}
              >
                View security details
              </button>
            </div>
          </main>

          {/* Mobile Collapsible Capabilities Section */}
          <div className="soc-mobile-capabilities-wrapper">
            <button
              type="button"
              className="soc-mobile-cap-toggle"
              onClick={() => setMobileCapOpen(prev => !prev)}
              aria-expanded={mobileCapOpen}
            >
              <span>About Vexa Agent Control &bull; Core Capabilities</span>
              <span className={`toggle-arrow ${mobileCapOpen ? 'open' : ''}`}>▾</span>
            </button>

            {mobileCapOpen && (
              <div className="soc-mobile-cap-content">
                <div className="soc-capabilities-grid mobile">
                  <div className="soc-capability-item">
                    <div className="soc-cap-icon-box">🛡️</div>
                    <div className="soc-cap-text">
                      <strong>Zero-Trust MCP Firewall</strong>
                      <p>Schema validation, loop defense &amp; tool parameter sanitization</p>
                    </div>
                  </div>
                  <div className="soc-capability-item">
                    <div className="soc-cap-icon-box">🔒</div>
                    <div className="soc-cap-text">
                      <strong>Dual-Pass Inline DLP</strong>
                      <p>21-pattern real-time credential, token &amp; private key redacting</p>
                    </div>
                  </div>
                  <div className="soc-capability-item">
                    <div className="soc-cap-icon-box">🧠</div>
                    <div className="soc-cap-text">
                      <strong>Prompt Injection Shield</strong>
                      <p>Multi-layer defense for jailbreaks, covert directives &amp; overrides</p>
                    </div>
                  </div>
                  <div className="soc-capability-item">
                    <div className="soc-cap-icon-box">⚡</div>
                    <div className="soc-cap-text">
                      <strong>Semantic Vector Cache</strong>
                      <p>Sub-3ms exact SHA-256 + cosine similarity token cost reduction</p>
                    </div>
                  </div>
                  <div className="soc-capability-item">
                    <div className="soc-cap-icon-box">💰</div>
                    <div className="soc-cap-text">
                      <strong>Fail-Closed Spend Caps</strong>
                      <p>Atomic balance preflight reservations &amp; exact stream settlements</p>
                    </div>
                  </div>
                  <div className="soc-capability-item">
                    <div className="soc-cap-icon-box">👁️</div>
                    <div className="soc-cap-text">
                      <strong>HMAC-SHA256 Forensics</strong>
                      <p>Cryptographically signed audit logs &amp; non-blocking SIEM export</p>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Security Attestation & Enterprise Links Footer */}
          <footer className="soc-login-footer">
            <div className="footer-tier-primary">
              <div className="footer-status-badge">
                <span className="status-beacon" />
                <span className="status-text">Operational</span>
              </div>
              <span className="footer-divider">&bull;</span>
              <button
                type="button"
                className="footer-compliance-btn"
                onClick={() => setShowSecurityModal(true)}
                title="View compliance details"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" className="footer-lock-icon" aria-hidden="true">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
                <span>FIPS 140-3 &amp; HMAC Audit Chain Verified</span>
              </button>
              <span className="footer-divider">&bull;</span>
              <span className="footer-version">Control Plane v1.0.72</span>
            </div>

            <div className="footer-tier-secondary">
              <a
                href="https://vexasec.io/"
                target="_blank"
                rel="noopener noreferrer"
                className="footer-link"
                title="Vexa Security Official Website"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <circle cx="12" cy="12" r="10" />
                  <line x1="2" y1="12" x2="22" y2="12" />
                  <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
                </svg>
                <span>vexasec.io</span>
              </a>
              <span className="footer-divider">&bull;</span>
              <a
                href="mailto:contact@vexasec.io"
                className="footer-link"
                title="Contact Vexa Security Support & Inquiries"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
                  <rect x="2" y="4" width="20" height="16" rx="2" />
                  <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
                </svg>
                <span>contact@vexasec.io</span>
              </a>
              <span className="footer-divider">&bull;</span>
              <button
                type="button"
                className="footer-link-btn"
                onClick={() => setShowSecurityModal(true)}
              >
                Security Center
              </button>
              <span className="footer-divider">&bull;</span>
              <span className="footer-copyright">&copy; {new Date().getFullYear()} Vexa Security</span>
            </div>
          </footer>
        </div>
      </div>

      {/* Help & Credential Recovery Modal */}
      {showHelpModal && (
        <div className="soc-modal-backdrop" onClick={() => setShowHelpModal(false)} role="dialog" aria-modal="true" aria-labelledby="help-modal-title">
          <div className="soc-help-modal" onClick={e => e.stopPropagation()}>
            <div className="help-modal-header">
              <div className="help-modal-title-row">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent, #6366f1)" strokeWidth="2" aria-hidden="true">
                  <circle cx="12" cy="12" r="10" />
                  <path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <h3 id="help-modal-title">Console Access Assistance</h3>
              </div>
              <button
                type="button"
                className="help-modal-close"
                onClick={() => setShowHelpModal(false)}
                aria-label="Close help modal"
              >
                ✕
              </button>
            </div>
            <div className="help-modal-body">
              <p>
                Access to <strong>Vexa Agent Control</strong> is governed by enterprise zero-trust policy. If you cannot sign in, review the recovery channels below:
              </p>
              <div className="help-guidance-box">
                <div className="guidance-item">
                  <strong>🏢 Customer Workspace Administrators</strong>
                  <p>Contact your designated SecOps or Identity administrator to reset credentials, unlock your account, or verify your enterprise SSO federation.</p>
                </div>
                <div className="guidance-item">
                  <strong>🔑 Enterprise SSO &amp; IdP Issues</strong>
                  <p>If your organization uses Microsoft Entra ID, Okta, or Google Workspace, confirm your organizational account status with your IT identity provider team.</p>
                </div>
                <div className="guidance-item">
                  <strong>✉️ Enterprise Technical Support</strong>
                  <p>
                    For deployment issues, licensing, or onboarding assistance, email{' '}
                    <a href="mailto:contact@vexasec.io" className="help-link-text">contact@vexasec.io</a>{' '}
                    or review documentation at{' '}
                    <a href="https://vexasec.io/" target="_blank" rel="noopener noreferrer" className="help-link-text">vexasec.io ↗</a>.
                  </p>
                </div>
              </div>
            </div>
            <div className="help-modal-footer">
              <button type="button" className="soc-btn-secondary" onClick={() => setShowHelpModal(false)}>
                Return to Login
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Security Architecture & Trust Details Modal */}
      {showSecurityModal && (
        <div className="soc-modal-backdrop" onClick={() => setShowSecurityModal(false)} role="dialog" aria-modal="true" aria-labelledby="sec-modal-title">
          <div className="soc-help-modal" onClick={e => e.stopPropagation()}>
            <div className="help-modal-header">
              <div className="help-modal-title-row">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" aria-hidden="true">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
                <h3 id="sec-modal-title">Vexa Security &amp; Compliance Center</h3>
              </div>
              <button
                type="button"
                className="help-modal-close"
                onClick={() => setShowSecurityModal(false)}
                aria-label="Close security details modal"
              >
                ✕
              </button>
            </div>
            <div className="help-modal-body">
              <p>
                Vexa Agent Control enforces defense-in-depth protection across all authentication endpoints and telemetry pipelines:
              </p>
              <div className="help-guidance-box">
                <div className="guidance-item">
                  <strong>🔒 TLS 1.3 Strict Transport Encryption</strong>
                  <p>All ingress traffic is negotiated using modern cryptographic cipher suites with forward secrecy. Deprecated TLS 1.0/1.1 and insecure ciphers are rejected at gateway edge.</p>
                </div>
                <div className="guidance-item">
                  <strong>🛡️ FIPS 140-3 &amp; HMAC Audit Chain Forensics</strong>
                  <p>Audit entries are cryptographically chained using HMAC-SHA256 digests. Any log alteration is immediately detected and flagged across downstream SIEM collectors.</p>
                </div>
                <div className="guidance-item">
                  <strong>⚡ Fail-Closed Policy Engine</strong>
                  <p>In the event of network disruption or gateway evaluation timeout, agent transactions fail safely to prevent unauthorized execution or sensitive data leaks.</p>
                </div>
              </div>
            </div>
            <div className="help-modal-footer">
              <button type="button" className="soc-btn-secondary" onClick={() => setShowSecurityModal(false)}>
                Close Security Center
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function ProviderIcon({ type }: { type: string }) {
  if (type === 'entra') {
    return (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path fill="#F25022" d="M1 1h10v10H1z"/>
        <path fill="#00A4EF" d="M1 13h10v10H1z"/>
        <path fill="#7FBA00" d="M13 1h10v10H13z"/>
        <path fill="#FFB900" d="M13 13h10v10H13z"/>
      </svg>
    )
  }
  if (type === 'google') {
    return (
      <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
      </svg>
    )
  }
  if (type === 'okta') {
    return (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="12" cy="12" r="10" stroke="#007dc1" strokeWidth="3" />
      </svg>
    )
  }
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  )
}
