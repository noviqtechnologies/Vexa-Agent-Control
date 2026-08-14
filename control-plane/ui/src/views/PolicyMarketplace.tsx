import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type PolicyTemplate } from '../api/client'
import './PolicyMarketplace.css'

export const BUILTIN_TEMPLATES: PolicyTemplate[] = [
  {
    id: 'safe-cursor',
    name: 'Safe Cursor Workstation',
    category: 'Developer Security',
    description: 'Blocks destructive shell operations (rm -rf, mkfs, dd), shields .env, id_rsa, and credentials, and stops post-read secret exfiltration.',
    tags: ['IDE', 'Cursor', 'Developer', 'Filesystem'],
    icon: 'shield-check',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2.1"
default_action: deny

session:
  max_calls_per_second: 10

sequence_rules:
  - name: block_exfiltration_after_reading_secrets
    window_size: 5
    antecedent_tools:
      - read_file
      - view_file
    antecedent_param_regex: ".*(\\.env|id_rsa|aws/credentials|secrets|token).*"
    consequent_tools:
      - http_post
      - fetch_url
      - exec_shell
    action: block
    message: "Security Violation: Blocked outbound call after reading sensitive credential file."

tools:
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "^(?!.*(rm\\\\s+-rf|mkfs|dd\\\\s+if|chmod\\\\s+-R\\\\s+777|sudo\\\\s+rm)).*$"

  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.env|id_rsa|\\.aws/credentials|id_ed25519|\\.pem)).*$"
        validators:
          - path_traversal

  - name: list_directory
    action: allow
    parameters:
      - name: directory
        type: string
        required: true

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
  },
  {
    id: 'production-data',
    name: 'Production Egress & Drift Control',
    category: 'Production Governance',
    description: 'Prevents data exfiltration by locking outbound requests to company domains, enforces cycle detection, and blocks MCP schema drift.',
    tags: ['Production', 'Egress', 'Firewall', 'Schema Drift'],
    icon: 'server',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2.2"
default_action: deny

session:
  max_calls_per_second: 15

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        validators:
          - path_traversal

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true

  - name: http_request
    action: allow
    parameters:
      - name: url
        type: string
        required: true
        pattern: "^https://([a-zA-Z0-9-]+\\\\.)*company\\\\.internal(/.*)?$"

  - name: query_db
    action: allow
    parameters:
      - name: query
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error

schema_drift:
  enabled: true
  action: block
  baseline_path: "./schema_baselines.json"`,
  },
  {
    id: 'hipaa-compliance',
    name: 'HIPAA & Medical PII Protection',
    category: 'Healthcare & Compliance',
    description: 'Auto-redacts PHI, SSNs, Medical Record Numbers (MRN), and PII across LLM requests and agent responses.',
    tags: ['HIPAA', 'DLP', 'PHI', 'Healthcare', 'PII'],
    icon: 'heart-pulse',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2.1"
default_action: deny

session:
  max_calls_per_second: 10

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-4-turbo"]
      dlp_tier: "strict"
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-5-sonnet"]
      dlp_tier: "strict"
  dlp:
    actions:
      - entity: "SSN"
        action: "deny"
      - entity: "CREDIT_CARD"
        action: "deny"
      - entity: "EMAIL_ADDRESS"
        action: "redact"
      - entity: "PHONE_NUMBER"
        action: "redact"
      - entity: "MEDICAL_RECORD_NUMBER"
        action: "deny"
      - entity: "HEALTH_INFO"
        action: "redact"

response_scanning:
  enabled: true
  scan_level: "deep"
  patterns:
    - name: "ssn_pattern"
      regex: "\\\\b\\\\d{3}-\\\\d{2}-\\\\d{4}\\\\b"
      action: "redact"
    - name: "mrn_pattern"
      regex: "\\\\bMRN-\\\\d{6,8}\\\\b"
      action: "redact"

tools:
  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error`,
  },
  {
    id: 'defense-in-depth',
    name: 'Full Defense in Depth',
    category: 'Enterprise Security',
    description: 'Comprehensive posture combining workstation shell protection, egress controls, and full LLM DLP redaction.',
    tags: ['Enterprise', 'Full Protection', 'DLP', 'Firewall'],
    icon: 'lock',
    is_custom: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    content: `version: "2.2"
default_action: deny

session:
  max_calls_per_second: 20

sequence_rules:
  - name: block_exfiltration_after_reading_secrets
    window_size: 5
    antecedent_tools:
      - read_file
      - view_file
    antecedent_param_regex: ".*(\\.env|id_rsa|aws/credentials|secrets|token).*"
    consequent_tools:
      - http_post
      - fetch_url
      - exec_shell
    action: block
    message: "Security Violation: Blocked outbound call after reading sensitive credential file."

llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o", "gpt-4-turbo"]
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
  - name: exec_shell
    action: allow
    parameters:
      - name: command
        type: string
        required: true
        pattern: "^(?!.*(rm\\\\s+-rf|mkfs|dd\\\\s+if|chmod\\\\s+-R\\\\s+777)).*$"

  - name: read_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
        pattern: "^(?!.*(\\.env|id_rsa|\\.aws/credentials)).*$"
        validators:
          - path_traversal

  - name: write_file
    action: allow
    parameters:
      - name: path
        type: string
        required: true
      - name: content
        type: string
        required: true

firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error

schema_drift:
  enabled: true
  action: block
  baseline_path: "./schema_baselines.json"`,
  },
]

export default function PolicyMarketplace() {
  const [templates, setTemplates] = useState<PolicyTemplate[]>(BUILTIN_TEMPLATES)
  const [loading, setLoading] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('All')
  const [previewTemplate, setPreviewTemplate] = useState<PolicyTemplate | null>(null)
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)
  const [applyingId, setApplyingId] = useState<string | null>(null)
  
  // Custom Template Creation Modal State
  const [showCustomModal, setShowCustomModal] = useState(false)
  const [customName, setCustomName] = useState('')
  const [customCategory, setCustomCategory] = useState('Developer Security')
  const [customDesc, setCustomDesc] = useState('')
  const [customYaml, setCustomYaml] = useState('')
  const [savingCustom, setSavingCustom] = useState(false)

  const navigate = useNavigate()

  useEffect(() => {
    fetchTemplates()
  }, [])

  const fetchTemplates = async () => {
    try {
      const list = await api.listTemplates()
      if (Array.isArray(list) && list.length > 0) {
        // Merge list with builtin templates, preferring server templates
        const serverIds = new Set(list.map(t => t.id))
        const unlistedBuiltins = BUILTIN_TEMPLATES.filter(b => !serverIds.has(b.id))
        setTemplates([...list, ...unlistedBuiltins])
      } else {
        setTemplates(BUILTIN_TEMPLATES)
      }
    } catch {
      setTemplates(BUILTIN_TEMPLATES)
    }
  }

  const categories = ['All', 'Developer Security', 'Production Governance', 'Healthcare & Compliance', 'Enterprise Security', 'Custom']

  const filteredTemplates = (Array.isArray(templates) ? templates : []).filter(t => {
    if (!t) return false
    const cat = t.category || ''
    const name = t.name || ''
    const desc = t.description || ''
    const tags = Array.isArray(t.tags) ? t.tags : []

    const matchesCategory = selectedCategory === 'All' || 
      (selectedCategory === 'Custom' ? Boolean(t.is_custom) : cat.toLowerCase().includes(selectedCategory.toLowerCase()))
    
    const matchesSearch = name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      desc.toLowerCase().includes(searchQuery.toLowerCase()) ||
      tags.some(tag => (tag || '').toLowerCase().includes(searchQuery.toLowerCase()))

    return matchesCategory && matchesSearch
  })

  const handleApplyTemplate = async (template: PolicyTemplate) => {
    if (!template) return
    try {
      setApplyingId(template.id)
      setMessage(null)
      const version = `v-${template.id}-${Date.now().toString().slice(-4)}`
      await api.savePolicy({
        version,
        content: template.content || '',
        is_active: true
      })
      setMessage({
        type: 'success',
        text: `Successfully applied "${template.name || template.id}" posture! Active policy updated.`
      })
      setTimeout(() => setMessage(null), 4000)
    } catch (err: any) {
      setMessage({ type: 'error', text: `Failed to apply template: ${err?.message || 'Unknown error'}` })
    } finally {
      setApplyingId(null)
      if (previewTemplate) setPreviewTemplate(null)
    }
  }

  const handleCreateCustom = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!customName || !customYaml) return

    try {
      setSavingCustom(true)
      const id = customName.toLowerCase().replace(/[^a-z0-9]+/g, '-') + '-' + Date.now().toString().slice(-4)
      await api.createCustomTemplate({
        id,
        name: customName,
        category: customCategory,
        description: customDesc,
        tags: ['Custom', customCategory],
        icon: 'shield',
        content: customYaml
      })
      setShowCustomModal(false)
      setCustomName('')
      setCustomDesc('')
      setCustomYaml('')
      setMessage({ type: 'success', text: 'Custom team template saved to marketplace!' })
      fetchTemplates()
    } catch (err: any) {
      setMessage({ type: 'error', text: `Failed to save custom template: ${err?.message || 'Unknown error'}` })
    } finally {
      setSavingCustom(false)
    }
  }

  const getBadgeClass = (category = '', isCustom = false) => {
    if (isCustom) return 'badge-custom'
    const cat = category || ''
    if (cat.includes('Developer')) return 'badge-dev'
    if (cat.includes('Production')) return 'badge-prod'
    if (cat.includes('Healthcare') || cat.includes('HIPAA')) return 'badge-hipaa'
    return 'badge-dev'
  }

  return (
    <div className="marketplace-container">
      <header className="marketplace-header">
        <div className="marketplace-title-section">
          <h1>Policy Marketplace</h1>
          <p>Instant One-Click Security Postures. Select a battle-tested template or build team presets.</p>
        </div>
        <div style={{ display: 'flex', gap: 12 }}>
          <button 
            id="btn-create-custom-template"
            className="btn-preview" 
            onClick={() => setShowCustomModal(true)}
            style={{ background: 'rgba(99, 102, 241, 0.15)', borderColor: 'rgba(99, 102, 241, 0.4)', color: '#818cf8' }}
          >
            + Save Custom Template
          </button>
          <button 
            id="btn-open-editor"
            className="btn-preview" 
            onClick={() => navigate('/policy/edit')}
          >
            Open YAML Editor
          </button>
        </div>
      </header>

      {message && (
        <div className={`message-banner ${message.type}`} style={{ marginBottom: 20 }}>
          {message.text}
        </div>
      )}

      <div className="marketplace-controls">
        <div className="search-box">
          <span className="search-icon">🔍</span>
          <input 
            id="marketplace-search-input"
            type="text" 
            placeholder="Search templates by posture, tags, or rules (e.g., Safe Cursor, HIPAA, rm -rf)..." 
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
        </div>
        <div className="category-tabs">
          {categories.map(cat => (
            <button
              key={cat}
              id={`cat-btn-${cat.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}
              className={`category-btn ${selectedCategory === cat ? 'active' : ''}`}
              onClick={() => setSelectedCategory(cat)}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '60px 0', color: '#94a3b8' }}>
          Loading security posture marketplace...
        </div>
      ) : (
        <div className="templates-grid">
          {filteredTemplates.map(tpl => (
            <div key={tpl.id} className="template-card" id={`template-card-${tpl.id}`}>
              <div>
                <div className="template-card-header">
                  <span className={`template-badge ${getBadgeClass(tpl.category, tpl.is_custom)}`}>
                    {tpl.is_custom ? 'CUSTOM PRESET' : tpl.category}
                  </span>
                </div>
                <h3 className="template-title">{tpl.name}</h3>
                <p className="template-desc">{tpl.description}</p>
                
                <div className="template-tags">
                  {(Array.isArray(tpl.tags) ? tpl.tags : []).map((t, idx) => (
                    <span key={idx} className="tag-pill">#{t}</span>
                  ))}
                </div>
              </div>

              <div className="template-actions">
                <button 
                  id={`btn-preview-${tpl.id}`}
                  className="btn-preview" 
                  onClick={() => setPreviewTemplate(tpl)}
                >
                  Preview YAML
                </button>
                <button 
                  id={`btn-apply-${tpl.id}`}
                  className="btn-apply" 
                  disabled={applyingId === tpl.id}
                  onClick={() => handleApplyTemplate(tpl)}
                >
                  {applyingId === tpl.id ? 'Applying...' : 'Apply Posture'}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Preview YAML Modal */}
      {previewTemplate && (
        <div className="modal-overlay" onClick={() => setPreviewTemplate(null)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <div>
                <h2>{previewTemplate.name}</h2>
                <span style={{ fontSize: 12, color: '#94a3b8' }}>{previewTemplate.category}</span>
              </div>
              <button className="close-btn" onClick={() => setPreviewTemplate(null)}>✕</button>
            </div>
            <div className="modal-body">
              <p style={{ color: '#cbd5e1', fontSize: 14, marginBottom: 16 }}>{previewTemplate.description}</p>
              <h4 style={{ color: '#f8fafc', marginBottom: 8, fontSize: 13 }}>YAML Policy Configuration:</h4>
              <pre className="yaml-viewer">{previewTemplate.content}</pre>
            </div>
            <div className="modal-footer">
              <button className="btn-preview" onClick={() => setPreviewTemplate(null)}>Cancel</button>
              <button 
                className="btn-apply" 
                disabled={applyingId === previewTemplate.id}
                onClick={() => handleApplyTemplate(previewTemplate)}
              >
                {applyingId === previewTemplate.id ? 'Applying...' : 'Apply This Posture'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Create Custom Template Modal */}
      {showCustomModal && (
        <div className="modal-overlay" onClick={() => setShowCustomModal(false)}>
          <div className="modal-card" onClick={e => e.stopPropagation()}>
            <form onSubmit={handleCreateCustom}>
              <div className="modal-header">
                <h2>Save Custom Team Template</h2>
                <button className="close-btn" type="button" onClick={() => setShowCustomModal(false)}>✕</button>
              </div>
              <div className="modal-body">
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Template Name</label>
                    <input 
                      id="custom-template-name-input"
                      type="text" 
                      required
                      placeholder="e.g. Finance Team Strict Workstation"
                      value={customName}
                      onChange={e => setCustomName(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Category</label>
                    <select 
                      id="custom-template-category-select"
                      value={customCategory}
                      onChange={e => setCustomCategory(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                    >
                      <option value="Developer Security">Developer Security</option>
                      <option value="Production Governance">Production Governance</option>
                      <option value="Healthcare & Compliance">Healthcare & Compliance</option>
                      <option value="Enterprise Security">Enterprise Security</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Description</label>
                    <input 
                      id="custom-template-desc-input"
                      type="text" 
                      placeholder="Brief description of security rules..."
                      value={customDesc}
                      onChange={e => setCustomDesc(e.target.value)}
                      style={{ width: '100%', padding: '10px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#fff' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', marginBottom: 6, fontSize: 13, color: '#cbd5e1' }}>Policy YAML Configuration</label>
                    <textarea 
                      id="custom-template-yaml-textarea"
                      required
                      rows={10}
                      placeholder={`version: "2.1"\ndefault_action: deny...`}
                      value={customYaml}
                      onChange={e => setCustomYaml(e.target.value)}
                      style={{ width: '100%', padding: '12px', background: '#020617', border: '1px solid rgba(148,163,184,0.2)', borderRadius: 6, color: '#38bdf8', fontFamily: 'monospace', fontSize: 13 }}
                    />
                  </div>
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn-preview" onClick={() => setShowCustomModal(false)}>Cancel</button>
                <button type="submit" className="btn-apply" disabled={savingCustom}>
                  {savingCustom ? 'Saving...' : 'Save Template'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
