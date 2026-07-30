import { useState, useEffect } from 'react'
import { api, type SpendSnapshot } from '../api/client'

export default function SpendVisualization() {
  const [snapshots, setSnapshots] = useState<SpendSnapshot[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const res = await api.listSnapshots()
      setSnapshots(res || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  // Calculate totals
  const totalSpend = snapshots.reduce((acc, s) => acc + s.spent_cents, 0)
  const maxSpend = Math.max(...snapshots.map(s => s.spent_cents), 1)

  return (
    <div>
      <div className="page-header">
        <h1>Spend Visualization</h1>
        <p>Global analytics of fleet-wide agent spend.</p>
      </div>

      <div className="card" style={{ padding: 24, marginBottom: 24, display: 'flex', alignItems: 'center', gap: 32 }}>
        <div>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>TOTAL FLEET SPEND (ESTIMATED)</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: 'var(--warning)' }}>
            ${(totalSpend / 100).toFixed(2)}
          </div>
        </div>
        <div style={{ height: 60, width: 1, background: 'var(--border)' }} />
        <div>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>ACTIVE TRACKED AGENTS</p>
          <div style={{ fontSize: 36, fontWeight: 300 }}>
            {snapshots.length}
          </div>
        </div>
      </div>

      <div className="card" style={{ padding: 24 }}>
        <h3 style={{ marginBottom: 24 }}>Top Spenders</h3>
        
        {loading ? (
          <div className="loading" style={{ height: 200 }}>Loading analytics...</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {snapshots.sort((a,b) => b.spent_cents - a.spent_cents).map((s, idx) => {
              const width = Math.max(1, (s.spent_cents / maxSpend) * 100)
              
              return (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{ width: 150, fontFamily: 'var(--font-mono)', fontSize: 13, textOverflow: 'ellipsis', overflow: 'hidden', whiteSpace: 'nowrap' }}>
                    {s.agent_id}
                  </div>
                  <div style={{ flex: 1, height: 24, background: 'rgba(255,255,255,0.05)', borderRadius: 4, position: 'relative' }}>
                    <div style={{ 
                      position: 'absolute', top: 0, left: 0, bottom: 0, 
                      width: `${width}%`, 
                      background: 'var(--warning)', 
                      borderRadius: 4,
                      opacity: 0.8
                    }} />
                  </div>
                  <div style={{ width: 60, textAlign: 'right', fontSize: 13, fontWeight: 600 }}>
                    ${(s.spent_cents / 100).toFixed(2)}
                  </div>
                </div>
              )
            })}
            
            {snapshots.length === 0 && <p style={{ color: 'var(--text-muted)' }}>No active spend data to visualize.</p>}
          </div>
        )}
      </div>
    </div>
  )
}
