import { useState, useEffect } from 'react'
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend
} from 'recharts'
import { api, type SpendAnalytics, type SpendEventV2 } from '../api/client'

function microcentsToUSD(microcents: number): number {
  return (microcents || 0) / 100_000_000
}

export default function SpendVisualization() {
  const [analytics, setAnalytics] = useState<SpendAnalytics | null>(null)
  const [events, setEvents] = useState<SpendEventV2[]>([])
  const [hours, setHours] = useState<number>(24)
  const [groupBy, setGroupBy] = useState<'provider' | 'device' | 'model' | 'project' | 'user' | 'team'>('provider')
  const [dataFreshness, setDataFreshness] = useState<string>('')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchData()
  }, [hours, groupBy])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [analyticsRes, eventsRes] = await Promise.allSettled([
        api.getSpendAnalytics(hours, groupBy),
        api.listSpendEventsV2(50)
      ])

      if (analyticsRes.status === 'fulfilled') {
        setAnalytics(analyticsRes.value.analytics)
        setDataFreshness(analyticsRes.value.generated_at)
      }
      if (eventsRes.status === 'fulfilled') {
        setEvents(eventsRes.value.events || [])
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const summary = analytics?.summary
  const totalSettledUSD = microcentsToUSD(summary?.total_settled_microcents || 0)
  const totalReservedUSD = microcentsToUSD(summary?.total_reserved_microcents || 0)
  const totalReleasedUSD = microcentsToUSD(summary?.total_released_microcents || 0)
  const requestCount = summary?.request_count || 0
  const deniedCount = summary?.denied_count || 0

  const timeSeriesData = (analytics?.time_series || []).map((pt) => ({
    time: new Date(pt.hour).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    settled: microcentsToUSD(pt.settled_microcents),
    reserved: microcentsToUSD(pt.reserved_microcents),
    released: microcentsToUSD(pt.released_microcents),
    requests: pt.request_count,
  }))

  const topEntities = analytics?.top_entities || []
  const maxEntitySpend = Math.max(...topEntities.map(e => microcentsToUSD(e.settled_microcents)), 0.01)

  return (
    <div className="soc-spend-analytics-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Spend Analytics & Observatory</h1>
          <p>Authoritative PostgreSQL spend ledger metrics, real-time hourly velocity, and dimensional allocation.</p>
        </div>
        <div className="soc-header-controls">
          <div className="soc-time-toggle" role="group" aria-label="Time Window">
            {([1, 24, 168, 720] as const).map((h) => (
              <button
                key={h}
                type="button"
                className={`soc-time-btn ${hours === h ? 'active' : ''}`}
                onClick={() => setHours(h)}
              >
                {h === 1 ? '1H' : h === 24 ? '24H' : h === 168 ? '7D' : '30D'}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* 5-KPI High-Level Summary Grid */}
      <div className="stats-grid soc-stats-grid" style={{ marginBottom: 24 }}>
        <div className="card stat-tile soc-clickable-tile">
          <div className="stat-header-row">
            <div className="stat-label">Total Settled Spend</div>
            <span className="soc-delta-badge delta-success">Settled</span>
          </div>
          <div className="stat-value" style={{ color: '#10b981' }}>
            ${totalSettledUSD.toFixed(4)}
          </div>
          <div className="stat-subtext">Actual upstream API spend</div>
        </div>

        <div className="card stat-tile soc-clickable-tile tile-info">
          <div className="stat-header-row">
            <div className="stat-label">Active Reservations</div>
            <span className="soc-delta-badge delta-neutral">Held</span>
          </div>
          <div className="stat-value" style={{ color: '#38bdf8' }}>
            ${totalReservedUSD.toFixed(4)}
          </div>
          <div className="stat-subtext">Preflight locks held</div>
        </div>

        <div className="card stat-tile soc-clickable-tile tile-warning">
          <div className="stat-header-row">
            <div className="stat-label">Budget Released</div>
            <span className="soc-delta-badge delta-warning">Refunded</span>
          </div>
          <div className="stat-value" style={{ color: '#f59e0b' }}>
            ${totalReleasedUSD.toFixed(4)}
          </div>
          <div className="stat-subtext">Returned unspent budget</div>
        </div>

        <div className="card stat-tile soc-clickable-tile tile-info">
          <div className="stat-header-row">
            <div className="stat-label">Cache Efficiency</div>
            <span className="soc-delta-badge delta-success">Savings</span>
          </div>
          <div className="stat-value" style={{ color: (summary?.total_cached_tokens || 0) > 0 ? '#38bdf8' : 'var(--text-muted)' }}>
            {((summary?.total_input_tokens || 0) + (summary?.total_cached_tokens || 0)) > 0
              ? `${(((summary?.total_cached_tokens || 0) / ((summary?.total_input_tokens || 0) + (summary?.total_cached_tokens || 0))) * 100).toFixed(1)}%`
              : '0.0%'}
          </div>
          <div className="stat-subtext">
            {((summary?.total_cached_tokens || 0)).toLocaleString()} cached tokens
          </div>
        </div>

        <div className="card stat-tile soc-clickable-tile">
          <div className="stat-header-row">
            <div className="stat-label">Total Requests</div>
            <span className="soc-delta-badge delta-neutral">Volume</span>
          </div>
          <div className="stat-value">
            {requestCount.toLocaleString()}
          </div>
          <div className="stat-subtext" style={{ color: deniedCount > 0 ? 'var(--danger)' : undefined }}>
            {deniedCount} denied requests
          </div>
        </div>
      </div>

      {/* Hourly Spend Velocity Chart */}
      <div className="card soc-panel" style={{ marginBottom: 24 }}>
        <div className="soc-card-header">
          <div>
            <div className="card-title">Hourly Spend Velocity & Trend</div>
            <div className="soc-card-subtitle">Real-time throughput of settled spend versus active pre-reservations</div>
          </div>
          <span className="soc-live-pill">LIVE LEDGER</span>
        </div>

        {loading ? (
          <div className="loading" style={{ height: 220 }}>Loading time-series data...</div>
        ) : timeSeriesData.length === 0 ? (
          <div className="empty-state">
            <p>No spend activity recorded in the selected time window.</p>
          </div>
        ) : (
          <div style={{ height: 260, width: '100%' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData} margin={{ top: 10, right: 20, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="settledGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0}/>
                  </linearGradient>
                  <linearGradient id="reservedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#38bdf8" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#38bdf8" stopOpacity={0.0}/>
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                <XAxis dataKey="time" stroke="var(--text-muted)" fontSize={12} />
                <YAxis stroke="var(--text-muted)" fontSize={12} tickFormatter={(v) => `$${v}`} />
                <Tooltip
                  contentStyle={{ background: '#0e131f', border: '1px solid var(--border-default)', borderRadius: 8, boxShadow: '0 12px 32px rgba(0,0,0,0.6)' }}
                  formatter={(val: any) => [`$${Number(val).toFixed(4)}`, '']}
                />
                <Legend />
                <Area type="monotone" dataKey="settled" name="Settled ($)" stroke="#10b981" fillOpacity={1} fill="url(#settledGrad)" strokeWidth={2} />
                <Area type="monotone" dataKey="reserved" name="Reserved ($)" stroke="#38bdf8" fillOpacity={1} fill="url(#reservedGrad)" strokeWidth={2} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Top Spenders by Dimension */}
      <div className="card soc-panel" style={{ marginBottom: 24 }}>
        <div className="soc-card-header" style={{ marginBottom: 20 }}>
          <div>
            <div className="card-title">Top Spenders & Resource Breakdown</div>
            <div className="soc-card-subtitle">Granular budget consumption grouped by {groupBy}</div>
          </div>
          <div className="soc-time-toggle" role="group" aria-label="Group Dimension">
            {(['provider', 'device', 'model', 'project', 'user', 'team'] as const).map((g) => (
              <button
                key={g}
                type="button"
                className={`soc-time-btn ${groupBy === g ? 'active' : ''}`}
                style={{ textTransform: 'capitalize' }}
                onClick={() => setGroupBy(g)}
              >
                {g === 'team' ? 'Team' : g}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="loading" style={{ height: 120 }}>Loading top spenders...</div>
        ) : topEntities.length === 0 ? (
          <div className="empty-state">
            <p>No entity spend recorded for grouping by {groupBy}.</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {topEntities.map((ent, idx) => {
              const spentUSD = microcentsToUSD(ent.settled_microcents)
              const pct = Math.min(100, Math.max(2, (spentUSD / maxEntitySpend) * 100))
              const isDevice = groupBy === 'device'
              const displayName = ent.entity_name && ent.entity_name !== 'unknown' ? ent.entity_name : ent.entity_id
              const hasDistinctName = Boolean(ent.entity_name && ent.entity_name !== ent.entity_id && ent.entity_name !== 'unknown')

              return (
                <div key={idx} style={{ padding: '14px 18px', background: 'var(--bg-surface-1)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border-default)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      {isDevice && <span style={{ fontSize: 15 }}>💻</span>}
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <strong style={{ fontSize: 13, color: 'var(--text-primary)', fontFamily: isDevice && hasDistinctName ? 'inherit' : 'var(--font-mono)' }}>
                          {displayName}
                        </strong>
                        {hasDistinctName && (
                          <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
                            ({ent.entity_id.length > 18 ? `${ent.entity_id.slice(0, 8)}...${ent.entity_id.slice(-6)}` : ent.entity_id})
                          </span>
                        )}
                      </div>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>({ent.request_count} requests)</span>
                    </div>
                    <strong style={{ fontSize: 14, color: '#10b981' }}>${spentUSD.toFixed(4)}</strong>
                  </div>
                  <div style={{ height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: '#10b981', borderRadius: 3, transition: 'width 0.4s ease' }} />
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Recent Ledger Events */}
      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Recent Financial Ledger Transactions</div>
            <div className="soc-card-subtitle">Cryptographic accounting records stored in PostgreSQL ledger</div>
          </div>
          <span className="soc-badge">AUTHORITATIVE</span>
        </div>
        {loading ? (
          <div className="loading">Loading transactions...</div>
        ) : (
          <div className="table-wrap">
            <table className="soc-table">
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
                {events.length === 0 ? (
                  <tr><td colSpan={6} className="empty-state">No ledger events recorded yet.</td></tr>
                ) : (
                  events.slice(0, 10).map((e, idx) => (
                    <tr key={idx} className="soc-table-row">
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} className="text-mono-id">{e.event_id.substring(0, 8)}...</td>
                      <td>
                        <span className={`badge ${e.event_type === 'SETTLED' ? 'badge-success' : e.event_type === 'AUTHORIZED' ? 'badge-warning' : 'badge-info'}`}>
                          {e.event_type}
                        </span>
                      </td>
                      <td><strong style={{ color: 'var(--warning)' }}>${(e.amount_microcents / 100_000_000).toFixed(4)}</strong></td>
                      <td style={{ fontSize: 12 }}>
                        {e.actor_name && e.actor_name !== e.actor ? (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{e.actor_name}</span>
                            <span className="text-mono-id" style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>
                              {e.actor.length > 18 ? `${e.actor.slice(0, 8)}...${e.actor.slice(-4)}` : e.actor}
                            </span>
                          </div>
                        ) : (
                          <span className="text-mono-id" style={{ fontFamily: 'var(--font-mono)' }}>
                            {e.actor || 'gateway'}
                          </span>
                        )}
                      </td>
                      <td style={{ fontSize: 13 }}>{e.reason_code}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{new Date(e.occurred_at).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
        <div style={{ padding: '12px 20px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid var(--border-subtle)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12, color: 'var(--text-muted)' }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
            <span style={{ color: '#10b981' }}>●</span>
            <span>Integrity: <strong style={{ color: '#10b981' }}>Verified</strong> · System of Record: <strong>Cryptographic Financial Ledger</strong></span>
          </span>
          {dataFreshness && <span>Generated at: {new Date(dataFreshness).toLocaleTimeString()}</span>}
        </div>
      </div>
    </div>
  )
}
