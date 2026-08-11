import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type PolicyTemplate } from '../api/client'
import './PolicyMarketplace.css'

export default function PolicyMarketplace() {
  const [templates, setTemplates] = useState<PolicyTemplate[]>([])
  const [loading, setLoading] = useState(true)
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
      setLoading(true)
      const list = await api.listTemplates()
      setTemplates(list || [])
    } catch (err: any) {
      setMessage({ type: 'error', text: err.message || 'Failed to load policy templates' })
    } finally {
      setLoading(false)
    }
  }

  const categories = ['All', 'Developer Security', 'Production Governance', 'Healthcare & Compliance', 'Enterprise Security', 'Custom']

  const filteredTemplates = templates.filter(t => {
    const matchesCategory = selectedCategory === 'All' || 
      (selectedCategory === 'Custom' ? t.is_custom : t.category.toLowerCase().includes(selectedCategory.toLowerCase()))
    
    const matchesSearch = t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      t.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))

    return matchesCategory && matchesSearch
  })

  const handleApplyTemplate = async (template: PolicyTemplate) => {
    try {
      setApplyingId(template.id)
      setMessage(null)
      const version = `v-${template.id}-${Date.now().toString().slice(-4)}`
      await api.savePolicy({
        version,
        content: template.content,
        is_active: true
      })
      setMessage({
        type: 'success',
        text: `Successfully applied "${template.name}" posture! Active policy updated.`
      })
      setTimeout(() => setMessage(null), 4000)
    } catch (err: any) {
      setMessage({ type: 'error', text: `Failed to apply template: ${err.message}` })
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
      setMessage({ type: 'error', text: `Failed to save custom template: ${err.message}` })
    } finally {
      setSavingCustom(false)
    }
  }

  const getBadgeClass = (category: string, isCustom: boolean) => {
    if (isCustom) return 'badge-custom'
    if (category.includes('Developer')) return 'badge-dev'
    if (category.includes('Production')) return 'badge-prod'
    if (category.includes('Healthcare') || category.includes('HIPAA')) return 'badge-hipaa'
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
            onClick={() => navigate('/policy-editor')}
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
                  {tpl.tags.map((t, idx) => (
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
