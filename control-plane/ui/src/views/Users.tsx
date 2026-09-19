import { useState, useEffect } from 'react'
import './Users.css'

interface AuthProvider {
  id: string
  type: string
  name: string
  enabled: boolean
}

interface User {
  id: string
  auth_provider_id: string
  email: string
  is_admin: boolean
  is_saas_operator?: boolean
  created_at?: string
  updated_at?: string
}

interface CreateUserForm {
  auth_provider_id: string
  email: string
  password: string
  is_admin: boolean
}

function timeAgo(iso?: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function Users() {
  const [users, setUsers] = useState<User[]>([])
  const [providers, setProviders] = useState<AuthProvider[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [passwordModalUser, setPasswordModalUser] = useState<User | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [form, setForm] = useState<CreateUserForm>({
    auth_provider_id: '',
    email: '',
    password: '',
    is_admin: false,
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)

  async function fetchData() {
    try {
      const [usersRes, providersRes] = await Promise.all([
        fetch('/api/v1/users'),
        fetch('/api/v1/auth_providers'),
      ])
      if (usersRes.ok) {
        setUsers(await usersRes.json())
      } else {
        const txt = await usersRes.text()
        if (txt) setError(txt)
      }
      if (providersRes.ok) {
        const p = await providersRes.json()
        setProviders(Array.isArray(p) ? p : [])
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  function getProviderName(id: string): string {
    if (!id) return 'Local Password Authentication'
    const found = providers.find(p => p.id === id)
    if (found) return found.name
    return 'Local Password Authentication'
  }

  function getProviderType(id: string): string {
    if (!id) return 'local'
    return providers.find(p => p.id === id)?.type ?? 'local'
  }

  function openModal() {
    const localProvider = providers.find(p => p.type === 'local')
    setForm({
      auth_provider_id: localProvider?.id ?? '',
      email: '',
      password: '',
      is_admin: false,
    })
    setError(null)
    setSuccessMsg(null)
    setShowModal(true)
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    const payload = {
      ...form,
      email: form.email.trim().toLowerCase(),
    }
    try {
      const res = await fetch('/api/v1/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (!res.ok) throw new Error(await res.text())
      setSuccessMsg('User created successfully.')
      await fetchData()
      setTimeout(() => { setShowModal(false); setSuccessMsg(null) }, 1000)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Create failed')
    } finally {
      setSaving(false)
    }
  }

  async function handleUpdatePassword(e: React.FormEvent) {
    e.preventDefault()
    if (!passwordModalUser || !newPassword) return
    setSaving(true)
    setError(null)
    try {
      const res = await fetch(`/api/v1/users/${passwordModalUser.id}/password`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: newPassword }),
      })
      if (!res.ok) throw new Error(await res.text())
      setSuccessMsg('Password updated successfully.')
      await fetchData()
      setTimeout(() => { setPasswordModalUser(null); setNewPassword(''); setSuccessMsg(null) }, 1000)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update password')
    } finally {
      setSaving(false)
    }
  }

  async function handleToggleAdmin(u: User) {
    setSaving(true)
    setError(null)
    const newIsAdmin = !u.is_admin
    try {
      const res = await fetch(`/api/v1/users/${u.id}/role`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ is_admin: newIsAdmin, role: newIsAdmin ? 'ADMIN' : 'MEMBER' }),
      })
      if (!res.ok) throw new Error(await res.text())
      setUsers(prev => prev.map(item => item.id === u.id ? { ...item, is_admin: newIsAdmin } : item))
      setSuccessMsg(`User ${u.email} ${newIsAdmin ? 'promoted to Admin' : 'demoted to User'}.`)
      setTimeout(() => setSuccessMsg(null), 2500)
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update user role')
    } finally {
      setSaving(false)
    }
  }

  async function handleDelete(id: string) {
    const target = users.find(x => x.id === id)
    if (target?.is_admin || target?.is_saas_operator) {
      setError('Admin role accounts are protected and cannot be deleted.')
      setDeleteConfirm(null)
      return
    }
    try {
      const res = await fetch(`/api/v1/users/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(await res.text())
      setUsers(u => u.filter(x => x.id !== id))
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete user')
    } finally {
      setDeleteConfirm(null)
    }
  }

  const selectedProviderType = getProviderType(form.auth_provider_id)

  return (
    <div className="soc-users-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Users & Access Control</h1>
          <p>Manage local operator credentials, role-based access control, and enterprise identity federation.</p>
        </div>
        <div className="soc-header-controls">
          <button className="soc-btn-primary" onClick={openModal}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Add User
          </button>
        </div>
      </div>

      {/* Identity & Provisioning Guidance Card */}
      <div
        style={{
          marginBottom: '20px',
          padding: '14px 18px',
          borderRadius: 'var(--radius-md, 8px)',
          background: 'rgba(99, 102, 241, 0.05)',
          border: '1px solid rgba(99, 102, 241, 0.2)',
          display: 'flex',
          gap: '16px',
          alignItems: 'flex-start',
        }}
      >
        <div style={{ fontSize: '20px', marginTop: '2px' }}>ℹ️</div>
        <div style={{ fontSize: '13px', lineHeight: 1.6, color: 'var(--text-secondary, #a1a1aa)' }}>
          <strong style={{ color: '#c7d2fe' }}>SSO &amp; Access Control Architecture:</strong>
          <ul style={{ margin: '6px 0 0 0', paddingLeft: '18px' }}>
            <li>
              <strong style={{ color: 'var(--text-primary, #fff)' }}>Just-in-Time (JIT) SSO Onboarding:</strong> Team members in configured identity providers (Microsoft Entra ID, Google Workspace) do <em>not</em> need manual invitations. They can sign in directly at <code style={{ color: '#818cf8', background: 'rgba(99,102,241,0.1)', padding: '1px 5px', borderRadius: '4px' }}>/login</code> and are automatically registered with standard Member permissions.
            </li>
            <li>
              <strong style={{ color: 'var(--text-primary, #fff)' }}>Role Governance:</strong> Elevate any user to <strong>Admin</strong> with one click using the <code style={{ color: '#818cf8', background: 'rgba(99,102,241,0.1)', padding: '1px 5px', borderRadius: '4px' }}>Make Admin</code> action or the <code style={{ color: '#818cf8', background: 'rgba(99,102,241,0.1)', padding: '1px 5px', borderRadius: '4px' }}>Admin ⇄</code> badge in the directory below.
            </li>
            <li>
              <strong style={{ color: 'var(--text-primary, #fff)' }}>Pre-provisioning &amp; Local Accounts:</strong> Use <strong style={{ color: '#818cf8' }}>+ Add User</strong> to pre-assign the Admin role to an SSO user before their first login, or to create local emergency password accounts.
            </li>
          </ul>
        </div>
      </div>

      {error && (
        <div
          style={{
            marginBottom: '16px',
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm, 6px)',
            backgroundColor: 'rgba(239, 68, 68, 0.15)',
            border: '1px solid rgba(239, 68, 68, 0.35)',
            color: '#f87171',
            fontSize: '13px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>⚠ {error}</span>
          <button
            type="button"
            onClick={() => setError(null)}
            style={{ background: 'none', border: 'none', color: 'currentColor', cursor: 'pointer', fontSize: '15px' }}
          >
            ✕
          </button>
        </div>
      )}

      {successMsg && (
        <div
          style={{
            marginBottom: '16px',
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm, 6px)',
            backgroundColor: 'rgba(16, 185, 129, 0.15)',
            border: '1px solid rgba(16, 185, 129, 0.35)',
            color: '#34d399',
            fontSize: '13px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>✓ {successMsg}</span>
          <button
            type="button"
            onClick={() => setSuccessMsg(null)}
            style={{ background: 'none', border: 'none', color: 'currentColor', cursor: 'pointer', fontSize: '15px' }}
          >
            ✕
          </button>
        </div>
      )}

      {loading ? (
        <div className="loading">Loading users</div>
      ) : (
        <div className="card soc-panel">
          <div className="soc-card-header">
            <div>
              <div className="card-title">Organization Directory</div>
              <div className="soc-card-subtitle">{users.length} registered tenant user accounts</div>
            </div>
            <span className="soc-badge">{users.length} Users</span>
          </div>
          <div className="table-wrap">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Email / Account</th>
                  <th>Auth Provider</th>
                  <th>Role</th>
                  <th>Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {users.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="empty-state">No users found. Add the first one.</td>
                  </tr>
                ) : users.map(u => {
                  const isLocal = !u.auth_provider_id || getProviderType(u.auth_provider_id) === 'local'
                  return (
                    <tr key={u.id} className="soc-table-row">
                      <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{u.email}</td>
                      <td>
                        <span className="users-provider-badge">
                          {getProviderName(u.auth_provider_id)}
                        </span>
                      </td>
                      <td>
                        <button
                          type="button"
                          className={`badge ${u.is_admin ? 'badge-info' : 'users-badge-user'}`}
                          style={{
                            cursor: 'pointer',
                            border: 'none',
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: 4,
                            padding: '3px 8px',
                          }}
                          onClick={() => handleToggleAdmin(u)}
                          title={`Click to ${u.is_admin ? 'demote to User' : 'promote to Admin'}`}
                        >
                          <span>{u.is_admin ? 'Admin' : 'User'}</span>
                          <span style={{ fontSize: 10, opacity: 0.7 }}>⇄</span>
                        </button>
                      </td>
                      <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>{timeAgo(u.created_at)}</td>
                      <td>
                        <div className="users-actions" style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                          {/* Role Promotion / Demotion Action */}
                          {u.is_admin ? (
                            <button
                              className="btn-secondary"
                              style={{ padding: '4px 10px', fontSize: '12px', color: '#f87171' }}
                              onClick={() => handleToggleAdmin(u)}
                              title="Demote this user to standard Member role"
                            >
                              Revoke Admin
                            </button>
                          ) : (
                            <button
                              className="btn-secondary"
                              style={{ padding: '4px 10px', fontSize: '12px', color: '#818cf8', borderColor: 'rgba(99, 102, 241, 0.4)' }}
                              onClick={() => handleToggleAdmin(u)}
                              title="Promote this user to Administrator role"
                            >
                              Make Admin
                            </button>
                          )}

                          {/* Set Password - ONLY for local accounts */}
                          {isLocal ? (
                            <button
                              className="btn-secondary"
                              style={{ padding: '4px 10px', fontSize: '12px' }}
                              onClick={() => {
                                setPasswordModalUser(u)
                                setNewPassword('')
                                setError(null)
                                setSuccessMsg(null)
                              }}
                            >
                              Set Password
                            </button>
                          ) : (
                            <span
                              style={{
                                fontSize: '11px',
                                color: 'var(--text-muted, #71717a)',
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: 'rgba(255, 255, 255, 0.04)',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                userSelect: 'none',
                              }}
                              title="Password is authenticated and managed directly by your SSO Identity Provider"
                            >
                              SSO Managed
                            </span>
                          )}

                          {/* Delete Action */}
                          {u.is_admin ? (
                            <span
                              style={{
                                fontSize: '11px',
                                color: 'var(--text-muted, #71717a)',
                                padding: '3px 8px',
                                borderRadius: '4px',
                                background: 'rgba(255, 255, 255, 0.04)',
                                border: '1px solid rgba(255, 255, 255, 0.08)',
                                userSelect: 'none',
                                display: 'inline-flex',
                                alignItems: 'center',
                                gap: '4px',
                              }}
                              title="Admin role accounts are protected against direct deletion"
                            >
                              <span>🔒</span> Protected
                            </span>
                          ) : deleteConfirm === u.id ? (
                            <>
                              <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Confirm?</span>
                              <button className="btn-danger-text" onClick={() => handleDelete(u.id)}>Yes, Delete</button>
                              <button className="btn-secondary" style={{ padding: '3px 10px', fontSize: 12 }} onClick={() => setDeleteConfirm(null)}>Cancel</button>
                            </>
                          ) : (
                            <button className="btn-danger-text" onClick={() => setDeleteConfirm(u.id)}>Delete</button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Set / Change Password Modal */}
      {passwordModalUser && (
        <div className="ap-overlay" onClick={e => e.target === e.currentTarget && setPasswordModalUser(null)}>
          <div className="ap-modal card glass" role="dialog">
            <div className="ap-modal-header">
              <h2 className="ap-modal-title">Set Password for {passwordModalUser.email}</h2>
              <button className="ap-modal-close" onClick={() => setPasswordModalUser(null)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            <form onSubmit={handleUpdatePassword} className="ap-modal-form">
              <div className="form-group">
                <label className="form-label">New Password</label>
                <input
                  className="form-input"
                  type="password"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  placeholder="Enter new password (min 8 characters)"
                  minLength={8}
                  required
                  autoFocus
                />
              </div>

              {error && <div className="ap-error">{error}</div>}
              {successMsg && <div className="ap-success">{successMsg}</div>}

              <div className="ap-modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setPasswordModalUser(null)}>Cancel</button>
                <button type="submit" className="btn-primary" disabled={saving || !newPassword}>
                  {saving ? 'Updating…' : 'Save Password'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Add User Modal */}
      {showModal && (
        <div className="ap-overlay" onClick={e => e.target === e.currentTarget && setShowModal(false)}>
          <div className="ap-modal card glass" role="dialog">
            <div className="ap-modal-header">
              <h2 className="ap-modal-title">Add User</h2>
              <button className="ap-modal-close" onClick={() => setShowModal(false)}>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            <form onSubmit={handleCreate} className="ap-modal-form">
              <div className="form-group">
                <label className="form-label">Auth Provider</label>
                <select
                  className="form-input"
                  value={form.auth_provider_id}
                  onChange={e => setForm({ ...form, auth_provider_id: e.target.value })}
                >
                  {!providers.some(p => p.type === 'local') && (
                    <option value="">Local Password Authentication</option>
                  )}
                  {providers.map(p => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label className="form-label">Email Address</label>
                <input
                  className="form-input"
                  type="email"
                  value={form.email}
                  onChange={e => setForm({ ...form, email: e.target.value })}
                  placeholder="user@example.com"
                  required
                />
              </div>

              {selectedProviderType !== 'local' && form.auth_provider_id ? (
                <div
                  style={{
                    padding: '10px 12px',
                    borderRadius: '6px',
                    background: 'rgba(99, 102, 241, 0.08)',
                    border: '1px solid rgba(99, 102, 241, 0.25)',
                    color: '#c7d2fe',
                    fontSize: '12px',
                    lineHeight: 1.5,
                    marginBottom: '14px',
                  }}
                >
                  <strong>⚡ SSO Pre-provisioning:</strong> Users in your {getProviderName(form.auth_provider_id)} directory can already sign in automatically at <code>/login</code> via JIT provisioning. Use this form to pre-assign the <strong>Admin role</strong> to this user before their first login.
                </div>
              ) : (
                <div className="form-group">
                  <label className="form-label">Initial Password</label>
                  <p className="form-hint">Set the local credentials for this user.</p>
                  <input
                    className="form-input"
                    type="password"
                    value={form.password}
                    onChange={e => setForm({ ...form, password: e.target.value })}
                    placeholder="Minimum 8 characters"
                    minLength={8}
                    required
                  />
                </div>
              )}

              <div className="form-group ap-toggle-row">
                <label className="ap-toggle-label">
                  <span>Grant Admin Role</span>
                  <div
                    className={`ap-toggle ${form.is_admin ? 'ap-toggle--on' : ''}`}
                    onClick={() => setForm({ ...form, is_admin: !form.is_admin })}
                    role="switch"
                    aria-checked={form.is_admin}
                    tabIndex={0}
                    onKeyDown={e => e.key === ' ' && setForm({ ...form, is_admin: !form.is_admin })}
                  >
                    <div className="ap-toggle-knob" />
                  </div>
                </label>
              </div>

              {error && <div className="ap-error">{error}</div>}
              {successMsg && <div className="ap-success">{successMsg}</div>}

              <div className="ap-modal-actions">
                <button type="button" className="btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary" disabled={saving}>
                  {saving ? 'Creating…' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
