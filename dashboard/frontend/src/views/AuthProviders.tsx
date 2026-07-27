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
}

type ModalStep = 'setup' | 'configure'

const PROVIDER_META: Record<string, { label: string; description: string; isOAuth: boolean }> = {
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

function ProviderIcon({ type }: { type: string }) {
  if (type === 'github') return <GitHubIcon />
  if (type === 'google') return <GoogleIcon />
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
        email_domains: type === 'local' ? ['*'] : [],
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

  return (
    <div className="ap-page">
      <div className="page-header">
        <h1>Auth Providers</h1>
        <p>
          Authentication providers allow users to sign in to AgentWall. Configure at least one
          provider before inviting users.
        </p>
      </div>

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
                  {configured ? (
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
                <button className="btn-secondary ap-configure-btn" onClick={() => openModal(type)}>
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
                    <label className="form-label">Allowed Email Domains</label>
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
                      {saving ? 'Saving…' : 'Continue'}
                    </button>
                  </div>
                </>
              )}

              {/* OAuth provider fields */}
              {editingProvider.type !== 'local' && (
                <>
                  <div className="form-group">
                    <label className="form-label">Client ID</label>
                    <input
                      className="form-input"
                      value={editingProvider.client_id || ''}
                      onChange={e =>
                        setEditingProvider({ ...editingProvider, client_id: e.target.value })
                      }
                      placeholder="Paste your OAuth client ID"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Client Secret</label>
                    <input
                      className="form-input"
                      type="password"
                      value={editingProvider.client_secret || ''}
                      onChange={e =>
                        setEditingProvider({ ...editingProvider, client_secret: e.target.value })
                      }
                      placeholder={editingProvider.id ? 'Leave blank to keep existing' : 'Paste your OAuth client secret'}
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Allowed Email Domains</label>
                    <p className="form-hint">
                      Restrict sign-in to these domains. Use <code>*</code> to allow any.
                    </p>
                    <TagInput
                      tags={editingProvider.email_domains}
                      onChange={domains =>
                        setEditingProvider({ ...editingProvider, email_domains: domains })
                      }
                    />
                  </div>
                  <div className="form-group ap-toggle-row">
                    <label className="ap-toggle-label">
                      <span>Enable this provider</span>
                      <div
                        className={`ap-toggle ${editingProvider.enabled ? 'ap-toggle--on' : ''}`}
                        onClick={() =>
                          setEditingProvider({ ...editingProvider, enabled: !editingProvider.enabled })
                        }
                        role="switch"
                        aria-checked={editingProvider.enabled}
                        tabIndex={0}
                        onKeyDown={e => e.key === ' ' && setEditingProvider({ ...editingProvider, enabled: !editingProvider.enabled })}
                      >
                        <div className="ap-toggle-knob" />
                      </div>
                    </label>
                  </div>

                  {error && <div className="ap-error">{error}</div>}
                  {successMsg && <div className="ap-success">{successMsg}</div>}

                  <div className="ap-modal-actions">
                    <button type="button" className="btn-secondary" onClick={closeModal}>
                      Cancel
                    </button>
                    <button type="submit" className="btn-primary" disabled={saving}>
                      {saving ? 'Saving…' : 'Save'}
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
