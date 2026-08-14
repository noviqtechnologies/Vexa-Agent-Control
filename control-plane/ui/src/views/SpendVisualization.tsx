import { useState, useEffect } from 'react'
import { api, type BudgetWindowV2, type SpendEventV2, type SpendSnapshot } from '../api/client'

function microcentsToUSD(microcents: number): number {
  return microcents / 100_000_000
}

function formatScopeLabel(scopeType: string, scopeId: string): string {
  if (scopeType === 'organization' || scopeId === '00000000-0000-0000-0000-000000000001' || scopeId === 'global') {
    return 'Organization (Global Fleet)'
  }
  if (scopeType === 'project') {
    return `Project: ${scopeId}`
  }
  return `${scopeType}: ${scopeId}`
}

interface SpenderItem {
  id: string
  label: string
  settledUSD: number
  reservedUSD: number
  totalUSD: number
  limitUSD?: number
}

export default function SpendVisualization() {
  const [windows, setWindows] = useState<BudgetWindowV2[]>([])
  const [events, setEvents] = useState<SpendEventV2[]>([])
  const [legacySnapshots, setLegacySnapshots] = useState<SpendSnapshot[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [winRes, evRes, snapRes] = await Promise.allSettled([
        api.getEffectiveSpendV2(),
        api.listSpendEventsV2(200),
        api.listSnapshots()
      ])

      if (winRes.status === 'fulfilled') {
        setWindows(winRes.value.windows || [])
      }
      if (evRes.status === 'fulfilled') {
        setEvents(evRes.value.events || [])
      }
      if (snapRes.status === 'fulfilled') {
        setLegacySnapshots(snapRes.value || [])
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  // Aggregate spend by scope/project/agent
  const spenderMap = new Map<string, SpenderItem>()

  // 1. From PostgreSQL Budget Windows
  windows.forEach(w => {
    const displayLabel = formatScopeLabel(w.scope_type, w.scope_id)
    const settled = microcentsToUSD(w.settled_microcents)
    const reserved = microcentsToUSD(w.reserved_microcents)
    const limit = microcentsToUSD(w.limit_microcents)
    
    spenderMap.set(displayLabel, {
      id: displayLabel,
      label: w.scope_id,
      settledUSD: settled,
      reservedUSD: reserved,
      totalUSD: settled + reserved,
      limitUSD: limit
    })
  })

  // 2. From Spend Events (settled amounts by actor / gateway)
  events.forEach(e => {
    if (e.actor) {
      const key = `actor:${e.actor}`
      const amt = microcentsToUSD(e.amount_microcents)
      const existing = spenderMap.get(key) || {
        id: key,
        label: e.actor,
        settledUSD: 0,
        reservedUSD: 0,
        totalUSD: 0
      }
      if (e.event_type === 'SETTLED') {
        existing.settledUSD += amt
        existing.totalUSD += amt
      }
      if (e.event_type === 'AUTHORIZED' && !events.some(r => r.event_type === 'RELEASED' && r.reservation_id === e.reservation_id)) {
        existing.reservedUSD += amt
        existing.totalUSD += amt
      }
      spenderMap.set(key, existing)
    }
  })

  // 3. Fallback to legacy snapshots if present
  legacySnapshots.forEach(s => {
    const key = `agent:${s.agent_id}`
    if (!spenderMap.has(key)) {
      const spent = s.spent_cents / 100
      spenderMap.set(key, {
        id: key,
        label: s.agent_id,
        settledUSD: spent,
        reservedUSD: 0,
        totalUSD: spent,
        limitUSD: s.cap_cents ? s.cap_cents / 100 : undefined
      })
    }
  })

  const spenders = Array.from(spenderMap.values()).sort((a, b) => b.totalUSD - a.totalUSD)

  // Calculate totals from both windows and events
  const totalSettledFromEvents = events
    .filter(e => e.event_type === 'SETTLED')
    .reduce((acc, e) => acc + microcentsToUSD(e.amount_microcents), 0)

  const totalSettledFromWindows = windows.reduce((acc, w) => acc + microcentsToUSD(w.settled_microcents), 0)
  const totalSettledUSD = Math.max(totalSettledFromWindows, totalSettledFromEvents)

  const totalReservedUSD = windows.reduce((acc, w) => acc + microcentsToUSD(w.reserved_microcents), 0)
  const totalHistoricalAuthorizedUSD = events
    .filter(e => e.event_type === 'AUTHORIZED')
    .reduce((acc, e) => acc + microcentsToUSD(e.amount_microcents), 0)

  const totalFleetSpendUSD = totalSettledUSD + totalReservedUSD
  const maxSpend = Math.max(...spenders.map(s => s.totalUSD), 0.01)

  return (
    <div>
      <div className="page-header">
        <h1>Spend Visualization</h1>
        <p>Real-time analytics of fleet-wide LLM spend, active budget windows, and resource allocation.</p>
      </div>

      <div className="card" style={{ padding: 24, marginBottom: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 24 }}>
        <div>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>CURRENT FLEET SPEND</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: totalFleetSpendUSD > 0 ? 'var(--warning)' : 'var(--text-main)' }}>
            ${totalFleetSpendUSD.toFixed(4)}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Settled: ${totalSettledUSD.toFixed(4)}</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 24 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>ACTIVE RESERVATIONS</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: totalReservedUSD > 0 ? 'var(--info, #38bdf8)' : 'var(--text-muted)' }}>
            ${totalReservedUSD.toFixed(4)}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>In-flight preflight locks</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 24 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>HISTORICAL AUTHORIZATIONS</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: '#a78bfa' }}>
            ${totalHistoricalAuthorizedUSD.toFixed(4)}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{events.length} total ledger transactions</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 24 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>BUDGET SCOPES & WORKLOADS</p>
          <div style={{ fontSize: 36, fontWeight: 300 }}>
            {windows.length > 0 ? windows.length : spenders.length}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Active governance windows</span>
        </div>
      </div>

      <div className="card" style={{ padding: 24, marginBottom: 24 }}>
        <h3 style={{ marginBottom: 20 }}>Top Spenders & Budget Allocation</h3>
        
        {loading ? (
          <div className="loading" style={{ height: 160 }}>Loading spend analytics...</div>
        ) : spenders.length === 0 ? (
          <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>
            <p>No active spend data to visualize currently.</p>
            <p style={{ fontSize: 12, marginTop: 4 }}>Outbound LLM completions will automatically populate budget windows and settled costs.</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {spenders.map((s, idx) => {
              const barWidth = Math.min(100, Math.max(2, (s.totalUSD / maxSpend) * 100))
              const budgetPercent = s.limitUSD ? Math.min(100, Math.max(0, (s.totalUSD / s.limitUSD) * 100)) : null
              
              return (
                <div key={idx} style={{ padding: 16, background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                    <div>
                      <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 14 }}>{s.id}</strong>
                      {s.limitUSD && (
                        <span style={{ fontSize: 12, marginLeft: 10, color: 'var(--text-muted)' }}>
                          Cap: ${s.limitUSD.toFixed(2)} ({budgetPercent?.toFixed(1)}% used)
                        </span>
                      )}
                    </div>
                    <div style={{ textAlign: 'right' }}>
                      <strong style={{ fontSize: 15, color: s.totalUSD > 0 ? 'var(--warning)' : 'var(--text-muted)' }}>
                        ${s.totalUSD.toFixed(4)}
                      </strong>
                    </div>
                  </div>

                  <div style={{ height: 12, background: 'rgba(255,255,255,0.06)', borderRadius: 6, position: 'relative', overflow: 'hidden', marginBottom: 8 }}>
                    <div style={{ 
                      position: 'absolute', top: 0, left: 0, bottom: 0, 
                      width: `${s.totalUSD > 0 ? barWidth : 0}%`, 
                      background: 'linear-gradient(90deg, #f59e0b 0%, #eab308 100%)', 
                      borderRadius: 6,
                      transition: 'width 0.5s ease'
                    }} />
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)' }}>
                    <span>Settled: <strong style={{ color: '#fff' }}>${s.settledUSD.toFixed(4)}</strong></span>
                    {s.reservedUSD > 0 && <span>Reserved: <strong style={{ color: '#38bdf8' }}>${s.reservedUSD.toFixed(4)}</strong></span>}
                    {s.limitUSD && <span>Available: <strong style={{ color: 'var(--success)' }}>${Math.max(0, s.limitUSD - s.totalUSD).toFixed(4)}</strong></span>}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Recent Ledger Events */}
      <div className="card">
        <div style={{ padding: '20px 24px', borderBottom: '1px solid var(--border)' }}>
          <h3 style={{ fontSize: 16, margin: 0 }}>Recent Financial Ledger Transactions</h3>
        </div>
        {loading ? (
          <div className="loading">Loading transactions...</div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Type</th>
                  <th>Amount (USD)</th>
                  <th>Actor / Workload</th>
                  <th>Status / Reason</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No ledger events recorded yet.</td></tr>
                )}
                {events.slice(0, 10).map((e, idx) => (
                  <tr key={idx}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.event_id.substring(0, 8)}...</td>
                    <td>
                      <span className={`badge ${e.event_type === 'SETTLED' ? 'badge-success' : e.event_type === 'AUTHORIZED' ? 'badge-warning' : 'badge-info'}`}>
                        {e.event_type}
                      </span>
                    </td>
                    <td><strong style={{ color: 'var(--warning)' }}>${(e.amount_microcents / 100_000_000).toFixed(4)}</strong></td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.actor}</td>
                    <td style={{ fontSize: 13 }}>{e.reason_code}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{new Date(e.occurred_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
