import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type Policy, type PolicyTemplate } from '../api/client'
import { BUILTIN_TEMPLATES } from './PolicyMarketplace'
import './PolicyEditor.css'

const DEFAULT_POLICY_CONTENT = `version: "2"
default_action: deny

session:
  max_calls_per_second: 15

# LLM Governance, Centralized BYOK & Prompt DLP
llm:
  cursor_mode: byok            # "byok" (centralized keys) or "passthrough" (monitor-only)
  model_enforcement: restrict  # "restrict" (block unapproved models) or "fallback"
  default_model: "gpt-4o"
  allowed_models:
    # Frontier & Latest Generation
    - "claude-fable-5*"
    - "claude-fable-5-1*"
    - "claude-sonnet-5*"
    - "claude-opus-5*"
    - "claude-haiku-4-5*"
    - "gpt-6-astra*"
    - "gpt-5*"
    - "o3*"
    - "o4-mini*"
    - "gemini-3.8-flash*"
    - "gemini-3.8-flash-cyber*"
    - "gemini-2.5-pro*"
    - "gemini-2.5-flash*"
    - "deepseek-v4-pro*"
    - "deepseek-v4-flash*"
    # Supported Previous Generations
    - "claude-3-7-sonnet*"
    - "claude-3-5-sonnet*"
    - "claude-3-5-haiku*"
    - "gpt-4o*"
    - "gpt-4o-mini*"
    - "o1*"
    - "o3-mini*"
    - "gemini-2.0-flash*"
    - "gemini-1.5-pro*"
    - "deepseek-chat*"
    - "deepseek-reasoner*"
  providers:
    - name: "anthropic"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "claude-fable-5*"
        - "claude-fable-5-1*"
        - "claude-sonnet-5*"
        - "claude-opus-5*"
        - "claude-haiku-4-5*"
        # Supported Previous Generations
        - "claude-3-7-sonnet*"
        - "claude-3-5-sonnet*"
        - "claude-3-5-haiku*"
      dlp_tier: "strict"

    - name: "openai"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gpt-6-astra*"
        - "gpt-5*"
        - "o3*"
        - "o4-mini*"
        # Supported Previous Generations
        - "gpt-4o*"
        - "gpt-4o-mini*"
        - "o1*"
        - "o3-mini*"
      dlp_tier: "strict"

    - name: "google"
      action: "allow"
      models:
        # Frontier & Latest Generation
        - "gemini-3.8-flash*"
        - "gemini-3.8-flash-cyber*"
        - "gemini-2.5-pro*"
        - "gemini-2.5-flash*"
        # Supported Previous Generations
        - "gemini-2.0-flash*"
        - "gemini-1.5-pro*"
      dlp_tier: "strict"

    - name: "deepseek"
      action: "allow"
      models:
        # Core API Routing Aliases
        - "deepseek-chat*"
        - "deepseek-reasoner*"
        # Specific V4 Generation Endpoints
        - "deepseek-v4-pro*"
        - "deepseek-v4-flash*"
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "SSN"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"

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
  const [activePolicy, setActivePolicy] = useState<Policy | null>(null)
  const [history, setHistory] = useState<Policy[]>([])
  const [templates, setTemplates] = useState<PolicyTemplate[]>(BUILTIN_TEMPLATES)
  const [content, setContent] = useState(DEFAULT_POLICY_CONTENT)
  const [version, setVersion] = useState('v1.0.0')
  const [selectedHistoryId, setSelectedHistoryId] = useState<string>('')
  const [selectedTemplateId, setSelectedTemplateId] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

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
      const [pList, pActive] = await Promise.all([
        api.listPolicies().catch(() => []),
        api.getActivePolicy().catch(() => null)
      ])
      const policies = Array.isArray(pList) ? pList : []
      setHistory(policies)

      // Find active policy: prioritize getActivePolicy result, fallback to active item in history list
      let active: Policy | null = (pActive && (pActive.id || pActive.content)) ? pActive : null
      if (!active && policies.length > 0) {
        active = policies.find(p => p.is_active) || policies[0]
      }

      if (active) {
        setActivePolicy(active)
        setContent(active.content || DEFAULT_POLICY_CONTENT)
        setVersion(active.version || 'v1.0.0')
        setSelectedHistoryId(active.id || '')
      } else {
        setActivePolicy(null)
        setContent(DEFAULT_POLICY_CONTENT)
        setVersion('v1.0.0')
        setSelectedHistoryId('')
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
      const targetVersion = version || `v-${Date.now().toString().slice(-4)}`
      const res = await api.savePolicy({
        version: targetVersion,
        content,
        is_active: true
      })
      const savedPolicy: Policy = res && res.id ? res : {
        id: res?.id || `pol-${Date.now()}`,
        version: targetVersion,
        content,
        is_active: true,
        updated_at: new Date().toISOString()
      } as Policy

      setActivePolicy(savedPolicy)
      setSelectedHistoryId(savedPolicy.id || '')
      setSelectedTemplateId('')
      setMessage({ type: 'success', text: `Policy revision "${targetVersion}" saved and applied as active policy!` })

      // Refresh history
      const pList = await api.listPolicies().catch(() => [])
      if (Array.isArray(pList) && pList.length > 0) {
        setHistory(pList)
      }
      setTimeout(() => setMessage(null), 3500)
    } catch (e: any) {
      setMessage({ type: 'error', text: e?.message || 'Save failed' })
    } finally {
      setSaving(false)
    }
  }

  const handleHistorySelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const selId = e.target.value
    setSelectedHistoryId(selId)
    setSelectedTemplateId('')
    if (!selId) return
    const selPolicy = history.find(p => p && p.id === selId)
    if (selPolicy) {
      setContent(selPolicy.content || '')
      setVersion(selPolicy.version || '')
    }
  }

  const handleTemplateSelect = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const tplId = e.target.value
    setSelectedTemplateId(tplId)
    if (!tplId) return
    const selTpl = templates.find(t => t && t.id === tplId)
    if (selTpl) {
      setContent(selTpl.content || '')
      setVersion(`v-${selTpl.id}`)
      setSelectedHistoryId('')
      setMessage({ type: 'success', text: `Loaded "${selTpl.name || selTpl.id}" template into editor.` })
      setTimeout(() => setMessage(null), 3000)
    }
  }

  const handleResetToActive = () => {
    if (activePolicy) {
      setContent(activePolicy.content || DEFAULT_POLICY_CONTENT)
      setVersion(activePolicy.version || 'v1.0.0')
      setSelectedHistoryId(activePolicy.id || '')
      setSelectedTemplateId('')
      setMessage({ type: 'success', text: `Restored editor to active policy revision: ${activePolicy.version || 'v1.0.0'}` })
      setTimeout(() => setMessage(null), 3000)
    } else {
      setContent(DEFAULT_POLICY_CONTENT)
      setVersion('v1.0.0')
      setSelectedHistoryId('')
      setSelectedTemplateId('')
    }
  }

  const isViewingActive = activePolicy
    ? (content === (activePolicy.content || DEFAULT_POLICY_CONTENT) && version === (activePolicy.version || 'v1.0.0'))
    : false

  if (loading) {
    return <div className="loading" style={{ padding: 40, color: '#94a3b8' }}>Loading policy editor...</div>
  }

  const activeRevisionDisplay = activePolicy?.version || 'v1.0.0'

  return (
    <div className="policy-editor-page">
      <header className="page-header soc-page-header">
        <div className="policy-header-left">
          <div className="policy-title-row">
            <h1>Policy Editor</h1>
            <div className="active-policy-status-pill" title="Currently active runtime policy revision">
              <span className="live-dot">●</span>
              <span className="pill-label">Active Revision:</span>
              <span className="pill-revision">{activeRevisionDisplay}</span>
            </div>
          </div>
          <p>Edit the global Agent Control YAML policy for runtime evaluation.</p>
        </div>
        <div className="soc-header-controls">
          <button 
            id="btn-goto-marketplace"
            type="button"
            className="soc-btn-secondary" 
            onClick={() => navigate('/policy/marketplace')}
          >
            🏪 Browse Marketplace
          </button>
          <button type="button" className="soc-btn-primary" onClick={handleSave} disabled={saving}>
            {saving ? 'Saving...' : 'Save & Apply'}
          </button>
        </div>
      </header>
      
      {message && (
        <div className={`message-banner ${message.type}`}>
          {message.text}
        </div>
      )}

      {/* Top Banner Notice */}
      <div className="policy-top-banner">
        <div className="policy-top-banner-content">
          <span className="policy-top-banner-icon">⚡</span>
          <span className="policy-top-banner-text">
            <strong>Note:</strong> Applying a new policy revision will instantly affect all active agent sessions connected to the gateway.
          </span>
        </div>
        {activePolicy?.updated_at && !isNaN(new Date(activePolicy.updated_at).getTime()) && (
          <div className="policy-top-banner-meta">
            <span className="meta-label">Active policy last updated:</span>
            <span className="meta-time">{new Date(activePolicy.updated_at).toLocaleString()}</span>
          </div>
        )}
      </div>

      <div className="editor-layout">
        <div className="editor-sidebar card">
          {/* Current Active Policy Card */}
          <div className="active-policy-summary-card">
            <div className="active-summary-header">
              <span className="active-badge">
                <span className="pulse-dot">●</span> Active Policy
              </span>
              <span className="active-revision-tag">{activeRevisionDisplay}</span>
            </div>
            <div className="active-summary-body">
              <div className="summary-row">
                <span className="summary-label">Revision:</span>
                <span className="summary-val font-mono font-bold text-highlight">{activeRevisionDisplay}</span>
              </div>
              <div className="summary-row">
                <span className="summary-label">Status:</span>
                <span className="summary-val text-success font-semibold">● Enforcing at Runtime</span>
              </div>
              {activePolicy?.updated_at && !isNaN(new Date(activePolicy.updated_at).getTime()) && (
                <div className="summary-row">
                  <span className="summary-label">Updated:</span>
                  <span className="summary-val">{new Date(activePolicy.updated_at).toLocaleString()}</span>
                </div>
              )}
            </div>
            {!isViewingActive && (
              <button 
                type="button" 
                className="btn-restore-active"
                onClick={handleResetToActive}
                title="Discard unapplied changes and reload the live active policy"
              >
                ↺ Reload Active Policy ({activeRevisionDisplay})
              </button>
            )}
          </div>

          <h3 style={{ marginTop: 20 }}>Metadata & Presets</h3>

          <div className="form-group">
            <label htmlFor="select-policy-template" style={{ color: '#38bdf8', fontWeight: 600 }}>Load One-Click Template</label>
            <select 
              id="select-policy-template"
              value={selectedTemplateId}
              onChange={handleTemplateSelect}
              style={{ width: '100%', padding: '10px', background: 'var(--bg-elevated)', border: '1px solid #38bdf8', borderRadius: 'var(--radius-sm)', color: '#fff' }}
            >
              <option value="">-- Pick Security Posture Template --</option>
              {templates.map(t => (
                <option key={t.id} value={t.id}>
                  {t.name || t.id} ({t.category || 'General'})
                </option>
              ))}
            </select>
          </div>
          
          <div className="form-group" style={{ marginTop: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <label htmlFor="select-historical-version" style={{ margin: 0 }}>Load Historical Version</label>
              {selectedHistoryId && activePolicy && selectedHistoryId === activePolicy.id && (
                <span className="badge-active-tag">Active</span>
              )}
            </div>
            <select 
              id="select-historical-version"
              value={selectedHistoryId}
              onChange={handleHistorySelect}
              style={{ width: '100%', padding: '10px', background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: '#fff' }}
            >
              <option value="">-- Select past version to load --</option>
              {history.map(h => {
                const isActive = h.is_active || (activePolicy && h.id === activePolicy.id)
                return (
                  <option key={h.id} value={h.id}>
                    {h.version || 'v1'} {isActive ? '★ (CURRENT ACTIVE)' : ''} {h.created_at ? `- ${new Date(h.created_at).toLocaleString()}` : ''}
                  </option>
                )
              })}
            </select>
          </div>

          <div className="form-group" style={{ marginTop: 20 }}>
            <label htmlFor="input-policy-revision">Policy Revision (for new save)</label>
            <input 
              id="input-policy-revision"
              type="text" 
              value={version} 
              onChange={e => setVersion(e.target.value)} 
              placeholder="e.g. v1.0.0" 
            />
            <small style={{ color: 'var(--text-muted)', fontSize: 11, marginTop: 4, display: 'block' }}>
              Tracks revisions in database. Current active revision: <strong style={{ color: '#38bdf8' }}>{activeRevisionDisplay}</strong>.
            </small>
          </div>
        </div>

        <div className="editor-main card">
          <div className="editor-header">
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <h3>YAML Content</h3>
              {isViewingActive ? (
                <span className="badge badge-success" style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span style={{ color: '#10b981' }}>●</span> Active Policy (Revision: {activeRevisionDisplay})
                </span>
              ) : (
                <span className="badge badge-warning" style={{ fontSize: 11 }}>
                  ✏️ Working Revision: {version || 'Draft'} (Active: {activeRevisionDisplay})
                </span>
              )}
            </div>
            {!isViewingActive && (
              <button 
                type="button"
                className="soc-btn-secondary"
                onClick={handleResetToActive}
                style={{ fontSize: 11, padding: '4px 10px', height: 'auto' }}
                title="Discard unapplied changes and reload the active policy"
              >
                ↺ Revert to Active ({activeRevisionDisplay})
              </button>
            )}
          </div>
          <textarea 
            id="textarea-policy-content"
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
