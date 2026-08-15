import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type Policy, type PolicyTemplate } from '../api/client'
import { BUILTIN_TEMPLATES } from './PolicyMarketplace'
import './PolicyEditor.css'

const DEFAULT_POLICY_CONTENT = `version: "2"
default_action: deny

session:
  max_calls_per_second: 10

# LLM Governance & Prompt DLP
llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-3.5-turbo"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"

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
    action: pivot_error`

export default function PolicyEditor() {
  const [policy, setPolicy] = useState<Policy | null>(null)
  const [history, setHistory] = useState<Policy[]>([])
  const [templates, setTemplates] = useState<PolicyTemplate[]>(BUILTIN_TEMPLATES)
  const [content, setContent] = useState(DEFAULT_POLICY_CONTENT)
  const [version, setVersion] = useState('v1.0.0')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{type: 'success'|'error', text: string} | null>(null)

  const navigate = useNavigate()

  useEffect(() => {
    fetchPolicy()
    fetchTemplates()
  }, [])

  const fetchTemplates = async () => {
    try {
      const tList = await api.listTemplates()
      if (Array.isArray(tList) && tList.length > 0) {
        const serverIds = new Set(tList.map(t => t.id))
        const unlistedBuiltins = BUILTIN_TEMPLATES.filter(b => !serverIds.has(b.id))
        setTemplates([...tList, ...unlistedBuiltins])
      } else {
        setTemplates(BUILTIN_TEMPLATES)
      }
    } catch {
      setTemplates(BUILTIN_TEMPLATES)
    }
  }

  const fetchPolicy = async () => {
    try {
      setLoading(true)
      const pList = await api.listPolicies().catch(() => [])
      setHistory(Array.isArray(pList) ? pList : [])
      
      const p = await api.getActivePolicy().catch(() => null)
      if (p && (p.id || p.content)) {
        setPolicy(p)
        setContent(p.content || DEFAULT_POLICY_CONTENT)
        setVersion(p.version || 'v1.0.0')
      } else {
        setContent(DEFAULT_POLICY_CONTENT)
        setVersion('v1.0.0')
      }
    } catch (e: any) {
      setContent(DEFAULT_POLICY_CONTENT)
      setVersion('v1.0.0')
      setMessage({ type: 'error', text: e?.message || 'Failed to load policy' })
    } finally {
      setLoading(false)
    }
  }

  const handleSave = async () => {
    try {
      setSaving(true)
      setMessage(null)
      const res = await api.savePolicy({
        version: version || `v-${Date.now().toString().slice(-4)}`,
        content,
        is_active: true
      })
      if (res && res.id) {
        setPolicy(res)
      }
      setMessage({ type: 'success', text: 'Policy saved and applied successfully!' })
      // Refresh history
      const pList = await api.listPolicies().catch(() => [])
      setHistory(Array.isArray(pList) ? pList : [])
      setTimeout(() => setMessage(null), 3000)
    } catch (e: any) {
      setMessage({ type: 'error', text: e?.message || 'Save failed' })
    } finally {
      setSaving(false)
    }
  }

  const handleHistorySelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selId = e.target.value
    if (!selId) return
    const selPolicy = (Array.isArray(history) ? history : []).find(p => p && p.id === selId)
    if (selPolicy) {
      setContent(selPolicy.content || '')
      setVersion(selPolicy.version || '')
    }
  }

  const handleTemplateSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const tplId = e.target.value
    if (!tplId) return
    const selTpl = (Array.isArray(templates) ? templates : []).find(t => t && t.id === tplId)
    if (selTpl) {
      setContent(selTpl.content || '')
      setVersion(`v-${selTpl.id}`)
      setMessage({ type: 'success', text: `Loaded "${selTpl.name || selTpl.id}" template into editor.` })
      setTimeout(() => setMessage(null), 3000)
    }
  }

  if (loading) {
    return <div className="loading" style={{ padding: 40, color: '#94a3b8' }}>Loading policy editor...</div>
  }

  return (
    <div className="policy-editor-page">
      <header className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Policy Editor</h1>
          <p>Edit the global Agent Control YAML policy for runtime evaluation.</p>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button 
            id="btn-goto-marketplace"
            className="btn-secondary" 
            onClick={() => navigate('/policy/marketplace')}
            style={{ padding: '10px 16px', background: 'rgba(56, 189, 248, 0.15)', border: '1px solid rgba(56, 189, 248, 0.4)', color: '#38bdf8', borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontWeight: 600 }}
          >
            🏪 Browse Marketplace
          </button>
          <button className="btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save & Apply'}
          </button>
        </div>
      </header>
      
      {message && (
        <div className={`message-banner ${message.type}`}>
          {message.text}
        </div>
      )}

      <div className="editor-layout">
        <div className="editor-sidebar card">
          <h3>Metadata & Presets</h3>

          <div className="form-group">
            <label style={{ color: '#38bdf8', fontWeight: 600 }}>Load One-Click Template</label>
            <select 
              id="select-policy-template"
              onChange={handleTemplateSelect}
              style={{ width: '100%', padding: '10px', background: 'var(--bg-elevated)', border: '1px solid #38bdf8', borderRadius: 'var(--radius-sm)', color: '#fff' }}
            >
              <option value="">-- Pick Security Posture Template --</option>
              {(Array.isArray(templates) ? templates : []).map(t => (
                <option key={t.id} value={t.id}>
                  {t.name || t.id} ({t.category || 'General'})
                </option>
              ))}
            </select>
          </div>
          
          <div className="form-group" style={{ marginTop: 20 }}>
            <label>Load Historical Version</label>
            <select 
              onChange={handleHistorySelect}
              style={{ width: '100%', padding: '10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}
            >
              <option value="">-- Select past version to load --</option>
              {(Array.isArray(history) ? history : []).map(h => (
                <option key={h.id} value={h.id}>
                  {h.version || 'v1'} {h.is_active ? '(ACTIVE)' : ''} {h.created_at ? `- ${new Date(h.created_at).toLocaleString()}` : ''}
                </option>
              ))}
            </select>
          </div>

          <div className="form-group" style={{ marginTop: 20 }}>
            <label>Policy Revision (for new save)</label>
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
            {policy && policy.updated_at && !isNaN(new Date(policy.updated_at).getTime()) && (
              <p className="text-muted" style={{ marginTop: 16 }}>
                Active policy last updated: {new Date(policy.updated_at).toLocaleString()}
              </p>
            )}
          </div>
        </div>

        <div className="editor-main card">
          <div className="editor-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h3>YAML Content</h3>
            {policy?.content !== content && (
              <span className="badge badge-warning" style={{ fontSize: 11 }}>UNSAVED DRAFT / HISTORICAL VIEW</span>
            )}
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
