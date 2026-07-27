import { useState, useEffect } from 'react'
import { api, type Policy } from '../api/client'
import './PolicyEditor.css'

export default function PolicyEditor() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [content, setContent] = useState('')
  const [version, setVersion] = useState('')
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{type: 'success'|'error', text: string} | null>(null)

  useEffect(() => {
    fetchPolicy()
  }, [])

  const fetchPolicy = async () => {
    try {
      setLoading(true)
      const p = await api.getActivePolicy()
      if (p && p.id) {
        setPolicy(p)
        setContent(p.content)
        setVersion(p.version)
      } else {
        // Provide a valid AgentWall Schema v2 default template if none exists in DB
        setContent(`version: "2"
default_action: deny

session:
  max_calls_per_second: 10

tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        required: true

  - name: "list_directory"
    action: allow
    parameters:
      - name: "directory"
        type: string
        required: true

  - name: "exec_shell"
    action: allow
    parameters:
      - name: "command"
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`)
        setVersion('v1.0.0')
      }
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    try {
      setSaving(true)
      setMessage(null)
      const res = await api.savePolicy({
        version,
        content,
        is_active: true
      })
      setPolicy(res)
      setMessage({ type: 'success', text: 'Policy saved successfully!' })
      setTimeout(() => setMessage(null), 3000)
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return <div className="loading">Loading policy...</div>
  }

  return (
    <div className="policy-editor-page">
      <header className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Policy Editor</h1>
          <p>Edit the global AgentWall YAML policy for runtime evaluation.</p>
        </div>
        <button className="btn-primary" onClick={handleSave} disabled={saving}>
          {saving ? 'Saving...' : 'Save & Apply'}
        </button>
      </header>
      
      {message && (
        <div className={`message-banner ${message.type}`}>
          {message.text}
        </div>
      )}

      <div className="editor-layout">
        <div className="editor-sidebar card">
          <h3>Metadata</h3>
          <div className="form-group">
            <label>Policy Revision</label>
            <input 
              type="text" 
              value={version} 
              onChange={e => setVersion(e.target.value)} 
              placeholder="e.g. v1.0.0" 
            />
            <small style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 4, display: 'block' }}>
              Tracks revisions in database. Inside the YAML, <code>version: "2"</code> specifies the gateway engine schema version.
            </small>
          </div>
          <div className="info-block">
            <p><strong>Note:</strong> Applying a new policy revision will instantly affect all active agent sessions connected to the gateway.</p>
            {policy && policy.updated_at && (
              <p className="text-muted" style={{ marginTop: 16 }}>
                Last updated: {new Date(policy.updated_at).toLocaleString()}
              </p>
            )}
          </div>
        </div>

        <div className="editor-main card">
          <div className="editor-header">
            <h3>YAML Content</h3>
          </div>
          <textarea 
            className="code-editor"
            value={content}
            onChange={e => setContent(e.target.value)}
            spellCheck={false}
          />
        </div>
      </div>
    </div>
  )
}
