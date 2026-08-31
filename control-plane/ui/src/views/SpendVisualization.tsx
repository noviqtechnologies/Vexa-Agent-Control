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
  const [groupBy, setGroupBy] = useState<'provider' | 'device' | 'model' | 'project'>('provider')
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
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1>Spend Analytics & Observatory</h1>
          <p>Authoritative PostgreSQL spend ledger metrics, real-time hourly velocity, and dimensional allocation.</p>
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
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

      {/* Summary KPI Cards */}
      <div className="card" style={{ padding: 24, marginBottom: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 24 }}>
        <div>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>TOTAL SETTLED</p>
          <div style={{ fontSize: 32, fontWeight: 600, color: '#10b981' }}>
            ${totalSettledUSD.toFixed(4)}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Actual upstream API spend</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 20 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>ACTIVE RESERVATIONS</p>
          <div style={{ fontSize: 32, fontWeight: 600, color: '#38bdf8' }}>
            ${totalReservedUSD.toFixed(4)}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Preflight locks held</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 20 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>BUDGET RELEASED</p>
          <div style={{ fontSize: 32, fontWeight: 600, color: '#f59e0b' }}>
            ${totalReleasedUSD.toFixed(4)}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Returned unspent budget</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 20 }}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>TOTAL REQUESTS</p>
          <div style={{ fontSize: 32, fontWeight: 600 }}>
            {requestCount.toLocaleString()}
          </div>
          <span style={{ fontSize: 12, color: deniedCount > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
            {deniedCount} denied requests
          </span>
        </div>
      </div>

      {/* Hourly Spend Velocity Chart */}
      <div className="card" style={{ padding: 24, marginBottom: 24 }}>
        <h3 style={{ marginBottom: 16 }}>Hourly Spend Velocity & Trend</h3>
        {loading ? (
          <div className="loading" style={{ height: 220 }}>Loading time-series data...</div>
        ) : timeSeriesData.length === 0 ? (
          <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)' }}>
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
                  contentStyle={{ background: '#0f172a', border: '1px solid var(--border)', borderRadius: 6 }}
                  formatter={(val: any) => [`$${Number(val).toFixed(4)}`, '']}
                />
                <Legend />
                <Area type="monotone" dataKey="settled" name="Settled ($)" stroke="#10b981" fillOpacity={1} fill="url(#settledGrad)" />
                <Area type="monotone" dataKey="reserved" name="Reserved ($)" stroke="#38bdf8" fillOpacity={1} fill="url(#reservedGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Top Spenders by Dimension */}
      <div className="card" style={{ padding: 24, marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h3 style={{ margin: 0 }}>Top Spenders & Resource Breakdown</h3>
          <div style={{ display: 'flex', gap: 8 }}>
            {(['provider', 'device', 'model', 'project'] as const).map((g) => (
              <button
                key={g}
                type="button"
                className={`soc-time-btn ${groupBy === g ? 'active' : ''}`}
                style={{ textTransform: 'capitalize' }}
                onClick={() => setGroupBy(g)}
              >
                {g}
              </button>
            ))}
          </div>
        </div>

        {loading ? (
          <div className="loading" style={{ height: 120 }}>Loading top spenders...</div>
        ) : topEntities.length === 0 ? (
          <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>
            <p>No entity spend recorded for grouping by {groupBy}.</p>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {topEntities.map((ent, idx) => {
              const spentUSD = microcentsToUSD(ent.settled_microcents)
              const pct = Math.min(100, Math.max(2, (spentUSD / maxEntitySpend) * 100))
              return (
                <div key={idx} style={{ padding: 14, background: 'rgba(255,255,255,0.02)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <strong style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{ent.entity_id}</strong>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>({ent.request_count} requests)</span>
                    </div>
                    <strong style={{ fontSize: 14, color: '#10b981' }}>${spentUSD.toFixed(4)}</strong>
                  </div>
                  <div style={{ height: 8, background: 'rgba(255,255,255,0.06)', borderRadius: 4, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: '#10b981', borderRadius: 4, transition: 'width 0.4s ease' }} />
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
                {events.length === 0 ? (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)' }}>No ledger events recorded yet.</td></tr>
                ) : (
                  events.slice(0, 10).map((e, idx) => (
                    <tr key={idx}>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.event_id.substring(0, 8)}...</td>
                      <td>
                        <span className={`badge ${e.event_type === 'SETTLED' ? 'badge-success' : e.event_type === 'AUTHORIZED' ? 'badge-warning' : 'badge-info'}`}>
                          {e.event_type}
                        </span>
                      </td>
                      <td><strong style={{ color: 'var(--warning)' }}>${(e.amount_microcents / 100_000_000).toFixed(4)}</strong></td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{e.actor || 'gateway'}</td>
                      <td style={{ fontSize: 13 }}>{e.reason_code}</td>
                      <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{new Date(e.occurred_at).toLocaleString()}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
        <div style={{ padding: '12px 24px', background: 'rgba(0,0,0,0.2)', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', fontSize: 12, color: 'var(--text-muted)' }}>
          <span>Evidence source: <strong>PostgreSQL spend ledger (server-aggregated)</strong></span>
          {dataFreshness && <span>Generated at: {new Date(dataFreshness).toLocaleTimeString()}</span>}
        </div>
      </div>
    </div>
  )
}
