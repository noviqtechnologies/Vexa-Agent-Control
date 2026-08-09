import { useEffect, useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
} from 'recharts'
import {
  api,
  type ThreatSummary, type ThreatTimelinePoint, type ThreatPattern,
} from '../api/client'

const THREAT_COLORS: Record<string, string> = {
  dlp: '#6366f1',
  injection: '#ef4444',
  semantic: '#f59e0b',
}

export default function ThreatIntelligence() {
  const [summary, setSummary] = useState<ThreatSummary | null>(null)
  const [timeline, setTimeline] = useState<ThreatTimelinePoint[]>([])
  const [patterns, setPatterns] = useState<ThreatPattern[]>([])
  const [loading, setLoading] = useState(true)
  const [hours, setHours] = useState(24)

  useEffect(() => {
    setLoading(true)
    Promise.all([
      api.getThreatSummary(hours),
      api.getThreatTimeline(hours),
      api.getTopThreatPatterns(hours),
    ]).then(([s, t, p]) => {
      setSummary(s)
      setTimeline(t || [])
      setPatterns(p || [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [hours])

  if (loading) return <div className="loading">Loading threat data</div>

  const totalFindings = summary
    ? summary.dlp_total + summary.injection_total + summary.semantic_total
    : 0

  return (
    <>
      <div className="page-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div>
            <h1>Threat Intelligence</h1>
            <p>DLP violations, injection attempts, and semantic anomalies</p>
          </div>
          <div className="soc-time-toggle" role="group" aria-label="Telemetry Time Range">
            {[
              { label: '6H', val: 6 },
              { label: '24H', val: 24 },
              { label: '7D', val: 168 },
              { label: '30D', val: 720 },
            ].map((r) => (
              <button
                key={r.val}
                type="button"
                className={`soc-time-btn ${hours === r.val ? 'active' : ''}`}
                onClick={() => setHours(r.val)}
              >
                {r.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {summary && (
        <div className="stats-grid">
          <div className="card stat-tile">
            <div className="stat-value">{totalFindings.toLocaleString()}</div>
            <div className="stat-label">Total Findings</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: THREAT_COLORS.dlp }}>{summary.dlp_total.toLocaleString()}</div>
            <div className="stat-label">DLP Violations</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: THREAT_COLORS.injection }}>{summary.injection_total.toLocaleString()}</div>
            <div className="stat-label">Injection Attempts</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value" style={{ color: THREAT_COLORS.semantic }}>{summary.semantic_total.toLocaleString()}</div>
            <div className="stat-label">Semantic Anomalies</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value">{summary.events_with_dlp.toLocaleString()}</div>
            <div className="stat-label">Events with DLP</div>
          </div>
          <div className="card stat-tile">
            <div className="stat-value">{(summary.events_with_injection + summary.events_with_semantic).toLocaleString()}</div>
            <div className="stat-label">Events with Inj/Sem</div>
          </div>
        </div>
      )}

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-title">Threat Timeline ({hours}h)</div>
        {timeline.length > 0 ? (
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="gradDlp" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={THREAT_COLORS.dlp} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={THREAT_COLORS.dlp} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradInj" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={THREAT_COLORS.injection} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={THREAT_COLORS.injection} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gradSem" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={THREAT_COLORS.semantic} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={THREAT_COLORS.semantic} stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis
                dataKey="hour"
                tick={{ fill: '#5a5a6e', fontSize: 11 }}
                tickFormatter={(v: string) => v.split(' ')[1] || v}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#5a5a6e', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: '#1a1a24',
                  border: '1px solid rgba(255,255,255,0.1)',
                  borderRadius: 8,
                  fontSize: 13,
                }}
              />
              <Area type="monotone" dataKey="dlp" stroke={THREAT_COLORS.dlp} fill="url(#gradDlp)" strokeWidth={2} />
              <Area type="monotone" dataKey="injection" stroke={THREAT_COLORS.injection} fill="url(#gradInj)" strokeWidth={2} />
              <Area type="monotone" dataKey="semantic" stroke={THREAT_COLORS.semantic} fill="url(#gradSem)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state">No threat data in this period</div>
        )}
      </div>

      <div className="card">
        <div className="card-title">Top Threat Patterns</div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Type</th>
                <th>Pattern</th>
                <th>Category</th>
                <th>Total Hits</th>
                <th>Events</th>
              </tr>
            </thead>
            <tbody>
              {patterns.length === 0 ? (
                <tr><td colSpan={5} className="empty-state">No patterns detected</td></tr>
              ) : patterns.map((p, i) => (
                <tr key={`${p.type}-${p.pattern_name}-${i}`}>
                  <td>
                    <span className={`badge badge-${p.type === 'injection' ? 'danger' : p.type === 'dlp' ? 'info' : 'warning'}`}>
                      {p.type}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{p.pattern_name}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{p.category || '—'}</td>
                  <td>{p.total_count.toLocaleString()}</td>
                  <td>{p.event_count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  )
}
