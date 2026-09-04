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
    <div className="soc-threat-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Threat Intelligence</h1>
          <p>DLP violations, injection attempts, and semantic anomalies</p>
        </div>
        <div className="soc-header-controls">
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
        <div className="stats-grid soc-stats-grid">
          <div className="card stat-tile soc-clickable-tile">
            <div className="stat-header-row">
              <div className="stat-label">Total Findings</div>
              <span className="soc-delta-badge delta-neutral">{hours}h</span>
            </div>
            <div className="stat-value">{totalFindings.toLocaleString()}</div>
            <div className="stat-subtext">Security violations detected</div>
          </div>
          <div className="card stat-tile soc-clickable-tile tile-info">
            <div className="stat-header-row">
              <div className="stat-label">DLP Violations</div>
              <span className="soc-delta-badge delta-neutral">Data</span>
            </div>
            <div className="stat-value" style={{ color: THREAT_COLORS.dlp }}>{summary.dlp_total.toLocaleString()}</div>
            <div className="stat-subtext">Redacted / blocked secrets</div>
          </div>
          <div className="card stat-tile soc-clickable-tile tile-danger">
            <div className="stat-header-row">
              <div className="stat-label">Injection Attempts</div>
              <span className="soc-delta-badge delta-danger">{summary.injection_total > 0 ? 'Critical' : '0'}</span>
            </div>
            <div className="stat-value" style={{ color: THREAT_COLORS.injection }}>{summary.injection_total.toLocaleString()}</div>
            <div className="stat-subtext">Prompt jailbreaks blocked</div>
          </div>
          <div className="card stat-tile soc-clickable-tile tile-warning">
            <div className="stat-header-row">
              <div className="stat-label">Semantic Anomalies</div>
              <span className="soc-delta-badge delta-warning">{summary.semantic_total > 0 ? 'Review' : '0'}</span>
            </div>
            <div className="stat-value" style={{ color: THREAT_COLORS.semantic }}>{summary.semantic_total.toLocaleString()}</div>
            <div className="stat-subtext">Tool loop / jailbreak drifts</div>
          </div>
          <div className="card stat-tile soc-clickable-tile">
            <div className="stat-header-row">
              <div className="stat-label">Events with DLP</div>
              <span className="soc-delta-badge delta-neutral">Fleet</span>
            </div>
            <div className="stat-value">{summary.events_with_dlp.toLocaleString()}</div>
            <div className="stat-subtext">Requests containing PII/keys</div>
          </div>
          <div className="card stat-tile soc-clickable-tile">
            <div className="stat-header-row">
              <div className="stat-label">Events with Inj/Sem</div>
              <span className="soc-delta-badge delta-neutral">Payloads</span>
            </div>
            <div className="stat-value">{(summary.events_with_injection + summary.events_with_semantic).toLocaleString()}</div>
            <div className="stat-subtext">Compromise attempts caught</div>
          </div>
        </div>
      )}

      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Threat Timeline ({hours}h)</div>
            <div className="soc-card-subtitle">Telemetry trajectory of DLP violations, prompt injections, and semantic threats</div>
          </div>
          <span className="soc-live-pill">LIVE STREAM</span>
        </div>

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
                tick={{ fill: '#64748b', fontSize: 11 }}
                tickFormatter={(v: string) => v.split(' ')[1] || v}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#64748b', fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  background: '#0e131f',
                  border: '1px solid rgba(255,255,255,0.12)',
                  borderRadius: 8,
                  fontSize: 13,
                  boxShadow: '0 12px 32px rgba(0,0,0,0.6)',
                  color: '#f8fafc',
                }}
              />
              <Area type="monotone" dataKey="dlp" name="DLP Violations" stroke={THREAT_COLORS.dlp} fill="url(#gradDlp)" strokeWidth={2} />
              <Area type="monotone" dataKey="injection" name="Injection Attempts" stroke={THREAT_COLORS.injection} fill="url(#gradInj)" strokeWidth={2} />
              <Area type="monotone" dataKey="semantic" name="Semantic Anomalies" stroke={THREAT_COLORS.semantic} fill="url(#gradSem)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="empty-state">No threat data in this period</div>
        )}
      </div>

      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Top Threat Patterns</div>
            <div className="soc-card-subtitle">Most frequently triggered signatures, DLP entities, and injection heuristics</div>
          </div>
          <span className="soc-badge">{patterns.length} Signatures</span>
        </div>

        <div className="table-wrap">
          <table className="soc-table">
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
                <tr key={`${p.type}-${p.pattern_name}-${i}`} className="soc-table-row">
                  <td>
                    <span className={`badge badge-${p.type === 'injection' ? 'danger' : p.type === 'dlp' ? 'info' : 'warning'}`}>
                      {p.type}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }} className="text-mono-id">{p.pattern_name}</td>
                  <td style={{ color: 'var(--text-secondary)' }}>{p.category || '—'}</td>
                  <td><strong>{p.total_count.toLocaleString()}</strong></td>
                  <td>{p.event_count.toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
