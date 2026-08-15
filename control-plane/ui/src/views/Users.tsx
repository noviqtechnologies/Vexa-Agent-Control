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
      if (usersRes.ok) setUsers(await usersRes.json())
      if (providersRes.ok) {
        const p = await providersRes.json()
        setProviders(Array.isArray(p) ? p : [])
      }
    } catch {
      // silently fail
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchData() }, [])

  function getProviderName(id: string): string {
    return providers.find(p => p.id === id)?.name ?? id
  }

  function getProviderType(id: string): string {
    return providers.find(p => p.id === id)?.type ?? ''
  }

  function openModal() {
    const localProvider = providers.find(p => p.type === 'local')
    setForm({
      auth_provider_id: localProvider?.id ?? (providers[0]?.id ?? ''),
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
    if (!form.auth_provider_id) {
      setError('Please select a valid Auth Provider.')
      return
    }
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

  async function handleDelete(id: string) {
    try {
      const res = await fetch(`/api/v1/users/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(await res.text())
      setUsers(u => u.filter(x => x.id !== id))
    } catch {
      // ignore for now
    } finally {
      setDeleteConfirm(null)
    }
  }

  const selectedProviderType = getProviderType(form.auth_provider_id)

  return (
    <div className="users-page">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Users</h1>
          <p>Manage local and identity-provider users for Agent Control access.</p>
        </div>
        <button className="btn-primary" onClick={openModal}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Add User
        </button>
      </div>

      {loading ? (
        <div className="loading">Loading users</div>
      ) : (
        <div className="card">
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Email</th>
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
                ) : users.map(u => (
                  <tr key={u.id}>
                    <td style={{ fontWeight: 500, color: 'var(--text-primary)' }}>{u.email}</td>
                    <td>
                      <span className="users-provider-badge">
                        {getProviderName(u.auth_provider_id)}
                      </span>
                    </td>
                    <td>
                      {u.is_admin ? (
                        <span className="badge badge-info">Admin</span>
                      ) : (
                        <span className="badge users-badge-user">User</span>
                      )}
                    </td>
                    <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>{timeAgo(u.created_at)}</td>
                    <td>
                      <div className="users-actions">
                        {deleteConfirm === u.id ? (
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
                ))}
              </tbody>
            </table>
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
                  required
                >
                  {providers.length === 0 && <option value="">No providers configured</option>}
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

              {selectedProviderType === 'local' && (
                <div className="form-group">
                  <label className="form-label">Temporary Password</label>
                  <p className="form-hint">Share this with the user over a secure channel.</p>
                  <input
                    className="form-input"
                    type="password"
                    value={form.password}
                    onChange={e => setForm({ ...form, password: e.target.value })}
                    placeholder="Minimum 8 characters"
                    minLength={8}
                    required={selectedProviderType === 'local'}
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
                <button type="submit" className="btn-primary" disabled={saving || providers.length === 0}>
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
