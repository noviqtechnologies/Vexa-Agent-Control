import { useState, useEffect, useRef, KeyboardEvent } from 'react'
import './AuthProviders.css'

interface AuthProvider {
  id: string
  type: string
  name: string
  client_id?: string
  client_secret?: string
  issuer_url?: string
  enabled: boolean
  email_domains: string[]
  token_refresh_duration?: string
  allowed_org?: string
  allowed_users?: string[]
  enable_logging?: boolean
}

type ModalStep = 'setup' | 'configure'

const PROVIDER_META: Record<string, { label: string; description: string; isOAuth: boolean; isEnterprise?: boolean }> = {
  local: {
    label: 'Local',
    description: 'Email/password stored in AgentWall. Best for development.',
    isOAuth: false,
  },
  github: {
    label: 'GitHub',
    description: 'Authenticate users via GitHub OAuth application.',
    isOAuth: true,
  },
  google: {
    label: 'Google',
    description: 'Authenticate users via Google OAuth 2.0.',
    isOAuth: true,
  },
  okta: {
    label: 'Okta',
    description: 'Authenticate users via Okta SSO.',
    isOAuth: true,
    isEnterprise: true,
  },
  auth0: {
    label: 'Auth0',
    description: 'Authenticate users via Auth0.',
    isOAuth: true,
    isEnterprise: true,
  },
  jumpcloud: {
    label: 'JumpCloud',
    description: 'Authenticate users via JumpCloud.',
    isOAuth: true,
    isEnterprise: true,
  },
  entra: {
    label: 'Microsoft Entra',
    description: 'Authenticate users via Microsoft Entra ID.',
    isOAuth: true,
    isEnterprise: true,
  }
}

function LocalIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  )
}

function GitHubIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
    </svg>
  )
}

function GoogleIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <path d="M12 22C6.477 22 2 17.523 2 12S6.477 2 12 2s10 4.477 10 10-4.477 10-10 10z" />
      <path d="M17 12h-5v5m0-5V7" />
    </svg>
  )
}

function OktaIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <circle cx="12" cy="12" r="10" />
      <circle cx="12" cy="12" r="4" fill="currentColor" />
    </svg>
  )
}

function Auth0Icon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <path d="M12 2l4.5 9h-9z" />
      <path d="M12 22l-4.5-9h9z" />
    </svg>
  )
}

function JumpCloudIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <path d="M17.5 19c2.5 0 4.5-2 4.5-4.5S20 10 17.5 10c-.3 0-.6 0-.8.1C15.8 7.1 13.1 5 10 5 6.1 5 3 8.1 3 12s3.1 7 7 7h7.5z" />
    </svg>
  )
}

function EntraIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <path d="M4 12l8-8 8 8-8 8z" fill="currentColor"/>
    </svg>
  )
}

function ProviderIcon({ type }: { type: string }) {
  if (type === 'github') return <GitHubIcon />
  if (type === 'google') return <GoogleIcon />
  if (type === 'okta') return <OktaIcon />
  if (type === 'auth0') return <Auth0Icon />
  if (type === 'jumpcloud') return <JumpCloudIcon />
  if (type === 'entra') return <EntraIcon />
  return <LocalIcon />
}

// Tag input component for email domains
function TagInput({
  tags,
  onChange,
  placeholder = 'Hit "Enter" to insert',
}: {
  tags: string[]
  onChange: (tags: string[]) => void
  placeholder?: string
}) {
  const [inputValue, setInputValue] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  function addTag(value: string) {
    const trimmed = value.trim()
    if (trimmed && !tags.includes(trimmed)) {
      onChange([...tags, trimmed])
    }
    setInputValue('')
  }

  function removeTag(tag: string) {
    onChange(tags.filter(t => t !== tag))
  }

  function handleKeyDown(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault()
      addTag(inputValue)
    }
    if (e.key === 'Backspace' && !inputValue && tags.length > 0) {
      removeTag(tags[tags.length - 1])
    }
  }

  return (
    <div className="ap-tag-input" onClick={() => inputRef.current?.focus()}>
      {tags.map(tag => (
        <span key={tag} className="ap-tag">
          {tag}
          <button type="button" className="ap-tag-remove" onClick={() => removeTag(tag)} aria-label={`Remove ${tag}`}>
            ✕
          </button>
        </span>
      ))}
      <input
        ref={inputRef}
        value={inputValue}
        onChange={e => setInputValue(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={() => { if (inputValue.trim()) addTag(inputValue) }}
        placeholder={tags.length === 0 ? placeholder : ''}
        className="ap-tag-input-field"
      />
    </div>
  )
}

export default function AuthProviders() {
  const [providers, setProviders] = useState<AuthProvider[]>([])
  const [editingProvider, setEditingProvider] = useState<AuthProvider | null>(null)
  const [modalStep, setModalStep] = useState<ModalStep>('setup')
  const [saving, setSaving] = useState(false)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

  async function fetchProviders() {
    try {
      const res = await fetch('/api/v1/auth_providers')
      if (res.ok) {
        const data = await res.json()
        setProviders(Array.isArray(data) ? data : [])
      }
    } catch {
      setProviders([])
    }
  }

  useEffect(() => {
    fetchProviders()
  }, [])

  function openModal(type: string) {
    const existing = providers.find(p => p.type === type)
    const meta = PROVIDER_META[type]
    if (existing) {
      setEditingProvider({ ...existing, enabled: type === 'local' ? true : existing.enabled })
    } else {
      setEditingProvider({
        id: '',
        type,
        name: meta?.label ?? type,
        enabled: true,
        email_domains: type === 'local' ? ['*'] : ['*'], // Default to * for all new ones
        token_refresh_duration: '',
        allowed_org: '',
        allowed_users: [],
        enable_logging: false,
      })
    }
    setModalStep(type === 'local' ? 'setup' : 'configure')
    setSuccessMsg(null)
    setError(null)
  }

  function closeModal() {
    setEditingProvider(null)
    setSuccessMsg(null)
    setError(null)
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault()
    if (!editingProvider) return
    setSaving(true)
    setError(null)
    const payload = {
      ...editingProvider,
      enabled: editingProvider.type === 'local' ? true : editingProvider.enabled,
    }
    try {
      const res = await fetch('/api/v1/auth_providers', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) throw new Error(await res.text())
      setSuccessMsg(`${editingProvider.name} configured successfully.`)
      await fetchProviders()
      setTimeout(closeModal, 1200)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Save failed')
    } finally {
      setSaving(false)
    }
  }

  function isConfigured(type: string): boolean {
    const p = providers.find(p => p.type === type)
    return !!p?.enabled
  }

  const noProvidersConfigured = providers.filter(p => p.enabled).length === 0;

  return (
    <div className="ap-page">
      <div className="page-header">
        <h1>Auth Providers</h1>
        <p>
          Authentication providers allow users to sign in to AgentWall. Configure at least one
          provider before inviting users.
        </p>
      </div>

      {noProvidersConfigured && (
        <div className="ap-global-warning-banner">
          <div className="ap-global-warning-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          </div>
          <div className="ap-global-warning-content">
            <strong>No Auth Providers Configured!</strong>
            <p>To finish setting up AgentWall, you'll need to configure an Auth Provider. Select one below to get started!</p>
          </div>
        </div>
      )}

      <div className="ap-grid">
        {Object.entries(PROVIDER_META).map(([type, meta]) => {
          const configured = isConfigured(type)
          return (
            <div key={type} className={`ap-card card ${configured ? 'ap-card--active' : ''}`}>
              <div className="ap-card-header">
                <div className={`ap-icon ${configured ? 'ap-icon--active' : ''}`}>
                  <ProviderIcon type={type} />
                </div>
                <div className="ap-card-badge">
                  {meta.isEnterprise ? (
                    <span className="badge ap-badge-license">
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> License Required
                    </span>
                  ) : configured ? (
                    <span className="badge badge-success">
                      <span className="ap-badge-dot" /> Configured
                    </span>
                  ) : (
                    <span className="badge ap-badge-unconfigured">
                      <span className="ap-badge-dot ap-badge-dot--off" /> Not Configured
                    </span>
                  )}
                </div>
              </div>
              <h3 className="ap-card-title">{meta.label}</h3>
              <p className="ap-card-desc">{meta.description}</p>
              <div className="ap-card-footer">
                <button className="btn-secondary ap-configure-btn" onClick={() => openModal(type)} disabled={meta.isEnterprise}>
                  {configured ? 'Reconfigure' : 'Configure'}
                </button>
              </div>
            </div>
          )
        })}
      </div>

      {/* Modal */}
      {editingProvider && (
        <div className="ap-overlay" onClick={e => e.target === e.currentTarget && closeModal()}>
          <div className="ap-modal card glass" role="dialog" aria-modal="true">
            {/* Header */}
            <div className="ap-modal-header">
              <div className="ap-modal-title-row">
                <div className="ap-icon ap-icon--sm ap-icon--active">
                  <ProviderIcon type={editingProvider.type} />
                </div>
                <h2 className="ap-modal-title">
                  {editingProvider.id ? 'Reconfigure' : 'Set Up'} {editingProvider.name}
                </h2>
              </div>
              <button className="ap-modal-close" onClick={closeModal} aria-label="Close">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            {/* Local warning banner */}
            {editingProvider.type === 'local' && modalStep === 'setup' && (
              <div className="ap-warning-banner">
                <svg className="ap-warning-icon" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <p>
                  Local authentication stores passwords in AgentWall and is intended for{' '}
                  <strong>development or testing</strong>. For production, use an SSO provider
                  such as Google or GitHub.
                </p>
              </div>
            )}

            <form onSubmit={handleSave} className="ap-modal-form">
              {/* Local setup step — only domain configuration */}
              {editingProvider.type === 'local' && modalStep === 'setup' && (
                <>
                  <div className="form-group">
                    <label className="form-label">Allowed E-Mail Domains</label>
                    <p className="form-hint">
                      Local users must have an email address in one of these domains. Use{' '}
                      <code>*</code> to allow any domain.
                    </p>
                    <TagInput
                      tags={editingProvider.email_domains}
                      onChange={domains =>
                        setEditingProvider({ ...editingProvider, email_domains: domains })
                      }
                    />
                  </div>

                  {error && <div className="ap-error">{error}</div>}
                  {successMsg && <div className="ap-success">{successMsg}</div>}

                  <div className="ap-modal-actions">
                    <button
                      type="submit"
                      className="btn-primary"
                      disabled={saving || editingProvider.email_domains.length === 0}
                    >
                      {saving ? 'Saving…' : 'Confirm'}
                    </button>
                  </div>
                </>
              )}

              {/* OAuth provider fields */}
              {editingProvider.type !== 'local' && (
                <>
                  {/* Info Box */}
                  <div className="ap-info-box" style={{ background: 'rgba(37, 99, 235, 0.1)', border: '1px solid rgba(37, 99, 235, 0.3)', borderRadius: '6px', padding: '12px', display: 'flex', gap: '10px', alignItems: 'center' }}>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#60A5FA" strokeWidth="2">
                      <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
                    </svg>
                    <span style={{ fontSize: '13px', color: '#E8E8ED' }}>
                      Note: the callback URL for this auth provider is <code style={{ background: '#111827', padding: '4px 8px', borderRadius: '4px', border: '1px solid #374151' }}>{window.location.origin}/ <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ verticalAlign: 'middle', cursor: 'pointer', marginLeft: '4px' }} onClick={() => navigator.clipboard.writeText(window.location.origin + '/')}><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></code>
                    </span>
                  </div>

                  {/* Docs Box */}
                  <div className="ap-docs-box" style={{ border: '1px solid #374151', borderRadius: '6px', padding: '12px', fontSize: '13px', color: '#E8E8ED' }}>
                    For more details, please review <a href={
                      editingProvider.type === 'github' ? 'https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app' :
                      editingProvider.type === 'google' ? 'https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred' :
                      `https://docs.obot.ai/configuration/auth-providers/#${editingProvider.type}`
                    } target="_blank" rel="noreferrer" style={{ color: '#60A5FA', textDecoration: 'none' }}>the documentation</a> for configuring this auth provider.
                  </div>

                  <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#F9FAFB', margin: '8px 0 0 0' }}>Required Configuration</h3>

                  <div className="form-group">
                    <label className="form-label">Client ID</label>
                    <p className="form-hint">
                      {editingProvider.type === 'google' 
                        ? "Unique identifier for the application when using Google's OAuth. Can typically be found in Google Cloud Console > Credentials"
                        : editingProvider.type === 'github'
                        ? "Client ID for your GitHub OAuth app. Can be found in GitHub Developer Settings > OAuth Apps"
                        : `Client ID for your ${editingProvider.name} OAuth app.`}
                    </p>
                    <input
                      className="form-input"
                      value={editingProvider.client_id || ''}
                      onChange={e =>
                        setEditingProvider({ ...editingProvider, client_id: e.target.value })
                      }
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Client Secret</label>
                    <p className="form-hint">
                      {editingProvider.type === 'google' 
                        ? "Password or key that app uses to authenticate with Google's OAuth. Can typically be found in Google Cloud Console > Credentials"
                        : editingProvider.type === 'github'
                        ? "Client secret for your GitHub OAuth app. Can be found in GitHub Developer Settings > OAuth Apps"
                        : `Client secret for your ${editingProvider.name} OAuth app.`}
                    </p>
                    <div style={{ position: 'relative' }}>
                      <input
                        className="form-input"
                        type="password"
                        value={editingProvider.client_secret || ''}
                        onChange={e =>
                          setEditingProvider({ ...editingProvider, client_secret: e.target.value })
                        }
                      />
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ position: 'absolute', right: '12px', top: '12px', color: '#9CA3AF', cursor: 'pointer' }}>
                        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
                      </svg>
                    </div>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Allowed E-Mail Domains</label>
                    <p className="form-hint">
                      A list of email domains that are allowed to authenticate with this provider. <code>*</code> is a special value that allows all domains.
                    </p>
                    <TagInput
                      tags={editingProvider.email_domains}
                      onChange={domains =>
                        setEditingProvider({ ...editingProvider, email_domains: domains })
                      }
                    />
                  </div>

                  <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#F9FAFB', margin: '8px 0 0 0' }}>Optional Configuration</h3>

                  <div className="form-group">
                    <label className="form-label">Token Refresh Duration</label>
                    <p className="form-hint">Time to wait before attempting to refresh auth tokens. Should be in a format like 1h1m1s. Default: 1h</p>
                    <input
                      className="form-input"
                      value={editingProvider.token_refresh_duration || ''}
                      onChange={e =>
                        setEditingProvider({ ...editingProvider, token_refresh_duration: e.target.value })
                      }
                    />
                  </div>

                  {editingProvider.type === 'github' && (
                    <>
                      <div className="form-group">
                        <label className="form-label">Allowed {editingProvider.name} Organization</label>
                        <p className="form-hint">Restrict logins to members of this {editingProvider.name} organization.</p>
                        <input
                          className="form-input"
                          value={editingProvider.allowed_org || ''}
                          onChange={e =>
                            setEditingProvider({ ...editingProvider, allowed_org: e.target.value })
                          }
                        />
                      </div>

                      <div className="form-group">
                        <label className="form-label">Allowed {editingProvider.name} Users</label>
                        <p className="form-hint">A list of {editingProvider.name} users allowed to log in, even if they do not belong to the specified org.</p>
                        <TagInput
                          tags={editingProvider.allowed_users || []}
                          onChange={users =>
                            setEditingProvider({ ...editingProvider, allowed_users: users })
                          }
                        />
                      </div>
                    </>
                  )}

                  <div className="form-group ap-toggle-row" style={{ marginTop: '4px' }}>
                    <div style={{ flex: 1 }}>
                      <label className="form-label">Enable Logging</label>
                      <p className="form-hint" style={{ margin: 0 }}>Set to true to enable request, auth, and standard logging for the auth provider. Default: false</p>
                    </div>
                    <div
                      className={`ap-toggle ${editingProvider.enable_logging ? 'ap-toggle--on' : ''}`}
                      onClick={() =>
                        setEditingProvider({ ...editingProvider, enable_logging: !editingProvider.enable_logging })
                      }
                      role="switch"
                      aria-checked={editingProvider.enable_logging}
                      tabIndex={0}
                      onKeyDown={e => e.key === ' ' && setEditingProvider({ ...editingProvider, enable_logging: !editingProvider.enable_logging })}
                    >
                      <div className="ap-toggle-knob" />
                    </div>
                  </div>

                  {error && <div className="ap-error">{error}</div>}
                  {successMsg && <div className="ap-success">{successMsg}</div>}

                  <div className="ap-modal-actions" style={{ marginTop: '12px' }}>
                    <button type="submit" className="btn-primary" disabled={saving}>
                      {saving ? 'Saving…' : 'Confirm'}
                    </button>
                  </div>
                </>
              )}
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
