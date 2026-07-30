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
    <div className="page-container" style={{ display: 'flex', height: 'calc(100vh - 40px)', gap: 20 }}>
      {/* Sidebar List */}
      <div className="card" style={{ width: 280, display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '16px', borderBottom: '1px solid var(--border)' }}>
          <h3 style={{ margin: 0, fontSize: 14 }}>Active Group Policies</h3>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: 8 }}>
          {policies.length === 0 && <p style={{ color: 'var(--text-muted)', fontSize: 13, padding: 8 }}>No group policies found.</p>}
          {policies.map(p => (
            <button
              key={p.group_id}
              onClick={() => handleSelect(p)}
              style={{
                width: '100%', textAlign: 'left', padding: '10px 12px',
                background: selectedGroupId === p.group_id ? 'var(--bg-card-hover)' : 'transparent',
                border: 'none', borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                color: 'var(--text-primary)', marginBottom: 4, display: 'flex', justifyContent: 'space-between'
              }}
            >
              <span>{p.group_id}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>v{p.version}</span>
            </button>
          ))}
        </div>
        <div style={{ padding: '12px' }}>
          <button className="btn-primary" style={{ width: '100%' }} onClick={handleNew}>+ New Policy</button>
        </div>
      </div>

      {/* Editor */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
          <h2>{selectedGroupId ? `Edit Policy: ${selectedGroupId}` : 'Create New Group Policy'}</h2>
          <button className="btn-primary" onClick={handleSave} disabled={saving || !groupId}>
            {saving ? 'Publishing...' : 'Publish Version'}
          </button>
        </div>

        {message && (
          <div style={{ padding: 12, borderRadius: 'var(--radius-sm)', marginBottom: 20, background: message.type === 'success' ? 'var(--success-dim)' : 'var(--danger-dim)', color: message.type === 'success' ? 'var(--success)' : 'var(--danger)' }}>
            {message.text}
          </div>
        )}

        <div style={{ marginBottom: 16 }}>
          <label style={{ display: 'block', marginBottom: 8, fontWeight: 600, fontSize: 13, color: 'var(--text-muted)' }}>Target Group ID</label>
          <input 
            type="text" 
            value={groupId} 
            onChange={e => setGroupId(e.target.value)}
            disabled={!!selectedGroupId}
            style={{ width: '100%', padding: '10px 12px', background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)' }}
            placeholder="e.g. engineering"
          />
        </div>

        <div style={{ display: 'flex', gap: 20, flex: 1 }}>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 600, fontSize: 13, color: 'var(--text-muted)' }}>Required Claims (JSON)</label>
            <textarea 
              value={claims}
              onChange={e => setClaims(e.target.value)}
              style={{ flex: 1, padding: 16, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 13, resize: 'none' }}
            />
          </div>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <label style={{ display: 'block', marginBottom: 8, fontWeight: 600, fontSize: 13, color: 'var(--text-muted)' }}>Tool Overrides (JSON)</label>
            <textarea 
              value={tools}
              onChange={e => setTools(e.target.value)}
              style={{ flex: 1, padding: 16, background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 13, resize: 'none' }}
            />
          </div>
        </div>
      </div>
    </div>
  )
}
