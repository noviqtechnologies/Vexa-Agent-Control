import { useState, useEffect, useRef, KeyboardEvent } from 'react'
import { useAuth } from '../auth/AuthContext'
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
    label: 'Local Authentication',
    description: 'Email and password managed directly in Agent Control. Ideal for development & initial setup.',
    isOAuth: false,
  },
  google: {
    label: 'Google Workspace',
    description: 'Authenticate team members via Google Cloud OAuth 2.0 & Google Workspace SSO.',
    isOAuth: true,
  },
  entra: {
    label: 'Microsoft Entra ID',
    description: 'Authenticate enterprise team members via Microsoft Entra ID (Azure Active Directory).',
    isOAuth: true,
  },
}

function LocalIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  )
}

function GoogleIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24">
      <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
      <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
      <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
      <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
    </svg>
  )
}

function EntraIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
      <path fill="#F25022" d="M1 1h10v10H1z"/>
      <path fill="#00A4EF" d="M1 13h10v10H1z"/>
      <path fill="#7FBA00" d="M13 1h10v10H13z"/>
      <path fill="#FFB900" d="M13 13h10v10H13z"/>
    </svg>
  )
}

function ProviderIcon({ type }: { type: string }) {
  if (type === 'google') return <GoogleIcon />
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
  const { user, checkSession } = useAuth()
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
      if (!res.ok) {
        const text = await res.text()
        let errMsg = text || `Request failed (${res.status})`
        try {
          const errData = JSON.parse(text)
          if (errData && typeof errData === 'object' && errData.error) {
            errMsg = errData.error
          }
        } catch {
          // not JSON, keep text
        }
        throw new Error(errMsg)
      }
      setSuccessMsg(`${editingProvider.name} configured successfully.`)
      await fetchProviders()
      if (checkSession) {
        await checkSession()
      }
      setTimeout(closeModal, 1200)
    } catch (err: unknown) {
      if (err instanceof TypeError && err.message.toLowerCase().includes('failed to fetch')) {
        setError('Network error: Unable to reach the Control Hub API service. Please verify your connection or session.')
      } else {
        setError(err instanceof Error ? err.message : 'Save failed')
      }
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
          Authentication providers allow users to sign in to Agent Control. Configure at least one
          provider before inviting users.
        </p>
      </div>

      {noProvidersConfigured && !user?.is_saas_operator && (
        <div className="ap-enforcement-banner">
          <div className="ap-enforcement-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" strokeWidth="2.2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="M12 8v4" />
              <path d="M12 16h.01" />
            </svg>
          </div>
          <div className="ap-enforcement-body">
            <div className="ap-enforcement-title-row">
              <h3>Mandatory Initial Setup: Configure Authentication Method</h3>
              <span className="ap-enforcement-badge">Action Required • Other Tabs Locked</span>
            </div>
            <p>
              To complete customer onboarding and protect your organization workspace, you must enable at least one authentication provider below (Local Authentication or Enterprise SSO). Once configured, full access to Fleet Overview, Policy Governance, Spend Limits, and Devices will unlock automatically.
            </p>
            <div className="ap-enforcement-steps">
              <span className="ap-step-pill">1. Select Local Auth or Enterprise SSO below</span>
              <span className="ap-step-pill">2. Click "Setup" and Save Configuration</span>
              <span className="ap-step-pill">3. Console Unlocks Immediately</span>
            </div>
          </div>
        </div>
      )}

      {user?.is_saas_operator && (
        <div style={{
          background: 'rgba(99, 102, 241, 0.12)',
          border: '1px solid rgba(99, 102, 241, 0.3)',
          borderRadius: '8px',
          padding: '14px 18px',
          marginBottom: '20px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          color: '#c7d2fe',
          fontSize: '13px',
          lineHeight: 1.5
        }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2" style={{ flexShrink: 0 }}>
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="16" x2="12" y2="12"/>
            <line x1="12" y1="8" x2="12.01" y2="8"/>
          </svg>
          <div>
            <strong style={{ color: '#ffffff' }}>Platform Operator Notice:</strong> SSO providers configured here apply to platform administrators. Single-tenant customer organizations manage their own isolated SSO providers independently.
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
                  Local authentication manages credentials directly within your organization workspace. For enterprise deployments with centralized identity governance, configuring an SSO provider such as <strong>Google Workspace</strong> or <strong>Microsoft Entra ID</strong> is recommended.
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
                      editingProvider.type === 'google' ? 'https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred' :
                      editingProvider.type === 'entra' ? 'https://learn.microsoft.com/en-us/entra/identity-platform/quickstart-register-app' :
                      '#'
                    } target="_blank" rel="noreferrer" style={{ color: '#60A5FA', textDecoration: 'none' }}>the documentation</a> for configuring this auth provider.
                  </div>

                  <h3 style={{ fontSize: '16px', fontWeight: 600, color: '#F9FAFB', margin: '8px 0 0 0' }}>Required Configuration</h3>

                  <div className="form-group">
                    <label className="form-label">Client ID (Application ID)</label>
                    <p className="form-hint">
                      {editingProvider.type === 'google' 
                        ? "OAuth 2.0 Client ID from Google Cloud Console > APIs & Services > Credentials"
                        : "Application (client) ID from Microsoft Entra admin center > App registrations"}
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
                        ? "OAuth Client Secret from Google Cloud Console"
                        : "Client secret value from Microsoft Entra admin center > Certificates & secrets"}
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

                  {editingProvider.type === 'entra' && (
                    <div className="form-group">
                      <label className="form-label">Directory (Tenant) ID or Issuer URL</label>
                      <p className="form-hint">
                        Your Microsoft Entra Tenant ID (GUID) or <code>common</code> for multi-tenant organizations.
                      </p>
                      <input
                        className="form-input"
                        placeholder="common or 00000000-0000-0000-0000-000000000000"
                        value={editingProvider.issuer_url || ''}
                        onChange={e =>
                          setEditingProvider({ ...editingProvider, issuer_url: e.target.value })
                        }
                      />
                    </div>
                  )}

                  <div className="form-group">
                    <label className="form-label">Allowed E-Mail Domains</label>
                    <p className="form-hint">
                      A list of email domains allowed to authenticate (e.g. <code>company.com</code>). Use <code>*</code> to allow any domain.
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
