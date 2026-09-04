import { useState, useEffect } from 'react'
import { api, type GroupPolicy } from '../api/client'

export default function GroupPolicyEditor() {
  const [policies, setPolicies] = useState<GroupPolicy[]>([])
  const [selectedGroupId, setSelectedGroupId] = useState<string | null>(null)
  
  const [groupId, setGroupId] = useState('')
  const [claims, setClaims] = useState('{\n  "groups": ["engineering"]\n}')
  const [tools, setTools] = useState('[\n  {\n    "name": "read_file",\n    "action": "allow"\n  }\n]')
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState<{type: 'success'|'error', text: string} | null>(null)

  useEffect(() => {
    fetchPolicies()
  }, [])

  const fetchPolicies = async () => {
    try {
      const data: any = await api.listGroupPolicies()
      const list = Array.isArray(data) ? data : (data?.policies || [])
      setPolicies(list)
    } catch (e: any) {
      console.error(e)
    }
  }

  const handleSelect = (p: GroupPolicy) => {
    setSelectedGroupId(p.group_id)
    setGroupId(p.group_id)
    setClaims(JSON.stringify(p.claims, null, 2))
    setTools(JSON.stringify(p.tools, null, 2))
    setMessage(null)
  }

  const handleNew = () => {
    setSelectedGroupId(null)
    setGroupId('')
    setClaims('{\n  "groups": []\n}')
    setTools('[]')
    setMessage(null)
  }

  const handleSave = async () => {
    try {
      setSaving(true)
      setMessage(null)
      
      let parsedClaims, parsedTools
      try {
        parsedClaims = JSON.parse(claims)
        parsedTools = JSON.parse(tools)
      } catch (e) {
        throw new Error("Invalid JSON in claims or tools configuration")
      }

      await api.publishGroupPolicy({
        group_id: groupId,
        claims: parsedClaims,
        tools: parsedTools
      })
      
      setMessage({ type: 'success', text: 'Group policy published successfully!' })
      fetchPolicies()
    } catch (e: any) {
      setMessage({ type: 'error', text: e.message })
    } finally {
      setSaving(false)
    }
  }

  return (
    <div className="soc-grouppolicy-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Group Policies</h1>
          <p>Define role and group-level tool permissions, claim verifications, and scoped security guardrails.</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', height: 'calc(100vh - 220px)', minHeight: '520px', gap: 20 }}>
        {/* Sidebar List */}
        <div className="card soc-panel" style={{ display: 'flex', flexDirection: 'column', padding: '20px 16px', margin: 0 }}>
          <div className="soc-card-header" style={{ marginBottom: 12 }}>
            <div className="card-title">Active Group Policies</div>
            <span className="soc-badge">{policies.length} Policies</span>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '4px 0' }}>
            {policies.length === 0 && <p style={{ color: 'var(--text-muted)', fontSize: 13, padding: 8 }}>No group policies found.</p>}
            {policies.map(p => (
              <button
                key={p.group_id}
                onClick={() => handleSelect(p)}
                style={{
                  width: '100%', textAlign: 'left', padding: '10px 12px',
                  background: selectedGroupId === p.group_id ? 'var(--accent-dim)' : 'transparent',
                  border: selectedGroupId === p.group_id ? '1px solid var(--accent)' : '1px solid transparent',
                  borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                  color: selectedGroupId === p.group_id ? '#ffffff' : 'var(--text-primary)',
                  marginBottom: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  transition: 'all 0.15s ease',
                }}
              >
                <span style={{ fontWeight: 600, fontSize: 13 }}>{p.group_id}</span>
                <span className="soc-badge" style={{ fontSize: 11 }}>v{p.version}</span>
              </button>
            ))}
          </div>
          <div style={{ paddingTop: '12px', borderTop: '1px solid var(--border-subtle)' }}>
            <button className="soc-btn-secondary" style={{ width: '100%', justifyContent: 'center' }} onClick={handleNew}>
              + New Policy
            </button>
          </div>
        </div>

        {/* Editor */}
        <div className="card soc-panel" style={{ display: 'flex', flexDirection: 'column', padding: 24, margin: 0 }}>
          <div className="soc-card-header" style={{ marginBottom: 20 }}>
            <div>
              <div className="card-title">{selectedGroupId ? `Edit Policy: ${selectedGroupId}` : 'Create New Group Policy'}</div>
              <div className="soc-card-subtitle">Configure claims assertions and tool access overrides</div>
            </div>
            <button className="soc-btn-primary" onClick={handleSave} disabled={saving || !groupId}>
              {saving ? 'Publishing...' : 'Publish Version'}
            </button>
          </div>

          {message && (
            <div style={{ padding: '10px 14px', borderRadius: 'var(--radius-sm)', marginBottom: 16, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)', fontSize: '13px' }}>
              {message.text}
            </div>
          )}

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Target Group ID</label>
            <input 
              type="text" 
              value={groupId} 
              onChange={e => setGroupId(e.target.value)}
              disabled={!!selectedGroupId}
              className="soc-filter-input"
              style={{ width: '100%', padding: '9px 12px' }}
              placeholder="e.g. engineering"
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, flex: 1 }}>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <label style={{ display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Required Claims (JSON)</label>
              <textarea 
                value={claims}
                onChange={e => setClaims(e.target.value)}
                style={{ flex: 1, padding: 14, background: 'var(--bg-surface-0)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)', color: '#e2e8f0', fontFamily: 'var(--font-mono)', fontSize: 13, resize: 'none', outline: 'none' }}
              />
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <label style={{ display: 'block', marginBottom: 6, fontWeight: 600, fontSize: 12, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>Tool Overrides (JSON)</label>
              <textarea 
                value={tools}
                onChange={e => setTools(e.target.value)}
                style={{ flex: 1, padding: 14, background: 'var(--bg-surface-0)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius-sm)', color: '#e2e8f0', fontFamily: 'var(--font-mono)', fontSize: 13, resize: 'none', outline: 'none' }}
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
