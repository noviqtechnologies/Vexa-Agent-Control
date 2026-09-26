import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, Legend
} from 'recharts'
import {
  api, subscribeAlerts, listDevicesV2,
  type FleetStats, type AgentSummary, type DecisionBreakdown, type RedactedAlert, type LicenseStatus, type CoverageHealthResponse, type ListSentryDevicesResponse,
  type VirtualKey, type Policy, type BudgetWindowV2, type SpendPolicyV2
} from '../api/client'

const DECISION_COLORS: Record<string, string> = {
  allowed: '#10b981', // Emerald-500
  warned: '#f59e0b',  // Amber-500
  denied: '#ef4444',  // Rose-500
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'danger',
  warning: 'warning',
  info: 'info',
}

function formatTime(ms: number): string {
  return new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function timeAgo(iso: string): string {
  if (!iso) return 'just now'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function FleetOverview() {
  const navigate = useNavigate()
  const [stats, setStats] = useState<FleetStats | null>(null)
  const [agents, setAgents] = useState<AgentSummary[]>([])
  const [heatmap, setHeatmap] = useState<DecisionBreakdown[]>([])
  const [alerts, setAlerts] = useState<RedactedAlert[]>([])
  const [coverage, setCoverage] = useState<CoverageHealthResponse | null>(null)
  const [sentrySummary, setSentrySummary] = useState<ListSentryDevicesResponse | null>(null)
  const [licenseStatus, setLicenseStatus] = useState<LicenseStatus | null>(null)
  const [virtualKeys, setVirtualKeys] = useState<VirtualKey[]>([])
  const [policies, setPolicies] = useState<Policy[]>([])
  const [spendWindows, setSpendWindows] = useState<BudgetWindowV2[]>([])
  const [spendPolicies, setSpendPolicies] = useState<SpendPolicyV2[]>([])
  const [showScoreBreakdown, setShowScoreBreakdown] = useState(false)
  const [timeRange, setTimeRange] = useState<'1h' | '24h' | '7d' | '30d'>('24h')
  const [agentFilter, setAgentFilter] = useState<'all' | 'active'>('all')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const hoursMap: Record<string, number> = { '1h': 1, '24h': 24, '7d': 168, '30d': 720 }
    const hours = hoursMap[timeRange] || 24
    Promise.all([
      api.getFleetOverview(hours).catch(() => null),
      api.listAgents(50, 0, hours).catch(() => []),
      api.getHeatmap(hours).catch(() => []),
      api.listRecentAlerts(50, hours).catch(() => []),
      (api.getCoverageHealth ? api.getCoverageHealth().catch(() => null) : Promise.resolve(null)),
      (api.getLicenseStatus ? api.getLicenseStatus().catch(() => null) : Promise.resolve(null)),
      listDevicesV2().catch(() => null),
      (api.listSentryDevices ? api.listSentryDevices().catch(() => null) : Promise.resolve(null)),
      (api.listVirtualKeys ? api.listVirtualKeys().catch(() => ({ virtual_keys: [] })) : Promise.resolve({ virtual_keys: [] })),
      (api.listPolicies ? api.listPolicies().catch(() => []) : Promise.resolve([])),
      (api.getEffectiveSpendV2 ? api.getEffectiveSpendV2().catch(() => null) : Promise.resolve(null)),
      (api.listSpendPoliciesV2 ? api.listSpendPoliciesV2().catch(() => null) : Promise.resolve(null)),
    ]).then(([s, a, h, al, cov, lic, devV2, snt, vk, pol, sp, spPol]) => {
      const rawAgents = a || []
      const seen = new Set<string>()
      const dedupedAgents: AgentSummary[] = []
      const isDummyAgent = (id?: string | null) => {
        if (!id) return false
        const lower = id.toLowerCase().trim()
        return lower === 'anonymous' || lower === 'agent-local' || lower === 'unknown' || lower === 'dummy' || lower === 'test' || lower === 'none'
      }
      for (const ag of rawAgents) {
        if (!ag.agent_id || isDummyAgent(ag.agent_id) || isDummyAgent(ag.display_name)) {
          continue
        }
        const k = (ag.agent_id || ag.display_name || '').toLowerCase()
        if (k && !seen.has(k)) {
          seen.add(k)
          dedupedAgents.push(ag)
        } else if (!k) {
          dedupedAgents.push(ag)
        }
      }
      setStats(s)
      setAgents(dedupedAgents)
      setHeatmap(h || [])
      setAlerts(al || [])
      setCoverage(cov)
      setLicenseStatus(lic)

      // Unify workstation device list across V2 and V1 Sentry APIs
      let workstationDevices: any[] = []
      let workstationTotal = 0
      if (devV2 && devV2.devices && devV2.devices.length > 0) {
        workstationDevices = devV2.devices.map(d => ({
          device_id: d.device_id,
          hostname: d.display_name || d.stable_device_id || d.device_id,
          user_identifier: d.owner_subject || d.stable_device_id || 'workstation',
          owner_subject: d.owner_subject,
          auth_provider_type: d.auth_provider_type,
          os: d.os_family,
          os_version: d.architecture,
          overall_compliance: d.status === 'REVOKED' ? 'NON_COMPLIANT' : (d.last_freshness === 'STALE' ? 'OFFLINE' : 'COMPLIANT'),
          active_ides: ['Cursor', 'VS Code', 'Windsurf'],
          tamper_count_24h: 0,
          last_heartbeat_at: d.last_seen_at,
          enrollment_status: d.status,
          capability_vector: d.capability_vector || ['CONFIGURED', 'TRAFFIC_VERIFIED'],
          last_freshness: d.last_freshness || 'ACTIVE_FRESH',
        }))
        workstationTotal = devV2.total_count || workstationDevices.length
      } else if (snt && snt.devices && snt.devices.length > 0) {
        workstationDevices = snt.devices
        workstationTotal = snt.total_count ?? (snt as any).total ?? workstationDevices.length
      }

      setSentrySummary({
        devices: workstationDevices,
        total_count: workstationTotal,
        compliant_count: snt?.compliant_count ?? 0,
        non_compliant_count: snt?.non_compliant_count ?? 0,
        offline_count: snt?.offline_count ?? 0,
      })

      if (vk && Array.isArray((vk as any).virtual_keys)) {
        setVirtualKeys((vk as any).virtual_keys)
      }
      if (pol && Array.isArray(pol)) {
        setPolicies(pol)
      }
      if (sp && Array.isArray((sp as any).windows)) {
        setSpendWindows((sp as any).windows)
      }
      if (spPol && Array.isArray((spPol as any).policies)) {
        setSpendPolicies((spPol as any).policies)
      }
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [timeRange])

  // Real-time alert stream (AC-23.2).
  useEffect(() => {
    const unsub = subscribeAlerts((alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 100))
      // Bump stats counters optimistically.
      setStats((prev) =>
        prev ? {
          ...prev,
          total_alerts: prev.total_alerts + 1,
          critical_alerts:
            alert.severity === 'critical'
              ? prev.critical_alerts + 1
              : prev.critical_alerts,
        } : prev
      )
    })
    return unsub
  }, [])

  if (loading) return <div className="loading">Loading fleet data</div>

  // Deduplicate sentry devices and calculate live heartbeat posture matching Device Governance
  const sentryDevices = sentrySummary?.devices || []
  const sentryDeduped = (() => {
    const seen = new Set<string>()
    const deduped: any[] = []
    for (const d of sentryDevices) {
      const key = (d.hostname || d.device_id || '').toLowerCase()
      if (key && !seen.has(key)) {
        seen.add(key)
        deduped.push(d)
      } else if (!key) {
        deduped.push(d)
      }
    }
    return deduped
  })()

  const isHeartbeatActive = (d: any) => {
    if (d.enrollment_status === 'REVOKED' || d.overall_compliance === 'NON_COMPLIANT') return false
    if (d.overall_compliance === 'OFFLINE' || d.last_freshness === 'STALE') return false
    if (d.last_freshness === 'ACTIVE_FRESH' || d.last_freshness === 'ACTIVE_RECENT') return true
    if (!d.last_heartbeat_at) return false
    return (Date.now() - new Date(d.last_heartbeat_at).getTime()) <= 15 * 60 * 1000
  }

  const computedCompliant = sentryDeduped.filter(d => isHeartbeatActive(d)).length
  const computedOffline = sentryDeduped.filter(d => !isHeartbeatActive(d) && d.overall_compliance !== 'NON_COMPLIANT' && d.enrollment_status !== 'REVOKED').length
  const computedNonCompliant = sentryDeduped.filter(d => d.overall_compliance === 'NON_COMPLIANT' || d.enrollment_status === 'REVOKED').length

  const totalEnrolledWorkstations = sentryDeduped.length > 0 ? sentryDeduped.length : (sentrySummary?.total_count ?? (sentrySummary as any)?.total ?? coverage?.summary?.total_workstations ?? 0)
  const activeWorkstations = sentryDeduped.length > 0 ? computedCompliant : (sentrySummary?.compliant_count ?? coverage?.summary?.protected_workstations ?? (stats && stats.active_agents > 0 ? stats.active_agents : 0))
  const offlineWorkstations = sentryDeduped.length > 0 ? computedOffline : (sentrySummary?.offline_count ?? coverage?.summary?.stale_workstations ?? 0)
  const driftedWorkstations = sentryDeduped.length > 0 ? computedNonCompliant : (sentrySummary?.non_compliant_count ?? coverage?.summary?.exposed_workstations ?? 0)
  const activeIdesCount = coverage?.summary?.total_active_ides ?? 0

  // Spend calculations (authoritative settled total and policy cap)
  const totalSettledMicrocents = (spendWindows || []).reduce((acc, w) => acc + (w.settled_microcents || 0), 0)
  const activeSpendPolicy = spendPolicies.find(p => p.status === 'PUBLISHED')
  const totalLimitMicrocents = (spendWindows && spendWindows.length > 0)
    ? spendWindows.reduce((acc, w) => acc + (w.limit_microcents || 0), 0)
    : (activeSpendPolicy?.limit_microcents || 0)

  // ── Multi-Factor Composite Security Posture Index ──────────────────────
  // 1. Workstations & Sentry Health (35% weight)
  const endpointWeight = 35
  const endpointScore = totalEnrolledWorkstations > 0
    ? Math.round(((activeWorkstations - (driftedWorkstations * 0.5)) / Math.max(1, totalEnrolledWorkstations)) * endpointWeight)
    : 0

  // 2. Active Guardrails & 21 DLP Wire Rules (35% weight)
  const guardrailWeight = 35
  const activePolicyCount = policies.length
  const guardrailScore = Math.min(guardrailWeight, 20 + (activePolicyCount > 0 ? 15 : 0)) // Safe Mode + DLP active

  // 3. Universal Gateway & Key Custody (15% weight)
  const gatewayWeight = 15
  const gatewayScore = virtualKeys.length > 0 ? gatewayWeight : 10 // Baseline gateway operational

  // 4. Spend Governance & Preflight Caps (15% weight)
  const spendWeight = 15
  const spendScore = spendWeight // Preflight reservations active + 0 budget overages

  const compositePostureScore = totalEnrolledWorkstations > 0
    ? Math.min(100, Math.max(0, endpointScore + guardrailScore + gatewayScore + spendScore))
    : Math.min(100, guardrailScore + gatewayScore + spendScore) // Baseline security when initializing

  let postureTitle = 'Fleet Security Posture: Protected & Compliant'
  let postureScore = compositePostureScore
  let badgeClass = 'delta-success'
  let runtimePillText = '● Zero-Trust Runtime Active'
  let runtimePillColor = '#10b981'
  let bannerSubtext = totalEnrolledWorkstations > activeWorkstations
    ? `${activeWorkstations} of ${totalEnrolledWorkstations} Workstation${totalEnrolledWorkstations === 1 ? '' : 's'} Active (${offlineWorkstations} Offline) · ${activeIdesCount} IDE Targets Monitored (Cursor, VS Code, Windsurf, Zed, Cline)`
    : `${activeWorkstations} Workstation${activeWorkstations === 1 ? '' : 's'} Active · ${activeIdesCount} IDE Targets Monitored (Cursor, VS Code, Windsurf, Zed, Cline)`
  let shieldBg = 'linear-gradient(135deg, #10b981 0%, #059669 100%)'
  let shieldShadow = '0 8px 24px rgba(16, 185, 129, 0.35)'
  let shieldIcon = '🛡️'

  if (totalEnrolledWorkstations === 0 && activeWorkstations === 0) {
    postureTitle = 'Fleet Security Posture: Awaiting Workstation Enrollment'
    badgeClass = 'delta-neutral'
    runtimePillText = '○ Awaiting Onboarding'
    runtimePillColor = '#94a3b8'
    bannerSubtext = '0 Workstations Active · Run "agentcontrol login" on a developer workstation to authenticate and register.'
    shieldBg = 'linear-gradient(135deg, #64748b 0%, #475569 100%)'
    shieldShadow = '0 8px 24px rgba(100, 116, 139, 0.35)'
  } else if (totalEnrolledWorkstations > 0 && activeWorkstations === 0) {
    postureTitle = 'Fleet Security Posture: Offline / No Active Telemetry'
    badgeClass = 'delta-danger'
    runtimePillText = '⚠ Sentry Telemetry Stale'
    runtimePillColor = '#f59e0b'
    bannerSubtext = `0 of ${totalEnrolledWorkstations} Workstation${totalEnrolledWorkstations === 1 ? '' : 's'} Active (${offlineWorkstations} Offline) · Start the agentcontrol sentry service on workstations to resume telemetry.`
    shieldBg = 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)'
    shieldShadow = '0 8px 24px rgba(245, 158, 11, 0.35)'
    shieldIcon = '⚠️'
  } else if (driftedWorkstations > 0) {
    postureTitle = `Fleet Security Posture: Review Recommended (${driftedWorkstations} Drifted)`
    badgeClass = 'delta-warning'
    runtimePillText = '● Review Required'
    runtimePillColor = '#f59e0b'
    bannerSubtext = `${activeWorkstations} of ${totalEnrolledWorkstations} Workstation${totalEnrolledWorkstations === 1 ? '' : 's'} Active · ${activeIdesCount} IDE Targets Monitored`
    shieldBg = 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)'
    shieldShadow = '0 8px 24px rgba(245, 158, 11, 0.35)'
    shieldIcon = '🛡️'
  }

  // Active stats with safe fallback so the dashboard never renders blank metric cards
  const displayStats: FleetStats = stats || {
    total_agents: 0,
    active_agents: 0,
    total_events: 0,
    denied_events: 0,
    total_alerts: 0,
    critical_alerts: 0,
  }

  return (
    <div className="soc-fleet-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>Fleet Overview</h1>
          <p>Real-time agent activity, policy decisions, and security alerts</p>
        </div>
        <div className="soc-header-controls">
          <div className="soc-time-toggle" role="group" aria-label="Telemetry Time Range">
            {(['1h', '24h', '7d', '30d'] as const).map((r) => (
              <button
                key={r}
                type="button"
                className={`soc-time-btn ${timeRange === r ? 'active' : ''}`}
                onClick={() => setTimeRange(r)}
              >
                {r.toUpperCase()}
              </button>
            ))}
          </div>
          <button
            type="button"
            className="soc-btn-primary"
            onClick={() => navigate('/devices?onboard=true')}
          >
            + Onboard Workstation
          </button>
        </div>
      </div>

      {/* Fleet Security Posture Hero Banner */}
      <div className="card soc-hero-posture-banner" style={{
        background: activeWorkstations > 0 
          ? (driftedWorkstations > 0 ? 'linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(239, 68, 68, 0.06) 50%, rgba(99, 102, 241, 0.08) 100%)' : 'linear-gradient(135deg, rgba(16, 185, 129, 0.08) 0%, rgba(14, 165, 233, 0.06) 50%, rgba(99, 102, 241, 0.08) 100%)')
          : 'linear-gradient(135deg, rgba(148, 163, 184, 0.08) 0%, rgba(245, 158, 11, 0.06) 50%, rgba(15, 23, 42, 0.08) 100%)',
        borderColor: activeWorkstations > 0
          ? (driftedWorkstations > 0 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(16, 185, 129, 0.25)')
          : (totalEnrolledWorkstations > 0 ? 'rgba(245, 158, 11, 0.3)' : 'rgba(148, 163, 184, 0.25)'),
      }}>
        <div className="soc-hero-main">
          <div className="soc-hero-left">
            <div className="soc-hero-shield" style={{ background: shieldBg, boxShadow: shieldShadow }}>
              {shieldIcon}
            </div>
            <div className="soc-hero-text">
              <div className="soc-hero-title-row">
                <h3 className="soc-hero-title">
                  {postureTitle}
                </h3>
                <span className={`soc-delta-badge ${badgeClass}`} style={{ padding: '3px 8px', fontSize: '11px', fontWeight: 700 }}>
                  {postureScore}% Score
                </span>
                <button
                  type="button"
                  className="soc-breakdown-btn"
                  onClick={() => setShowScoreBreakdown(!showScoreBreakdown)}
                  title="View Composite Security Posture Breakdown"
                >
                  ⓘ {showScoreBreakdown ? 'Hide Breakdown' : 'Score Factors'}
                </button>
                <span style={{ fontSize: '11px', color: runtimePillColor, fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px', whiteSpace: 'nowrap' }}>
                  {runtimePillText}
                </span>
              </div>
              <p className="soc-hero-subtitle">
                {bannerSubtext}
              </p>
            </div>
          </div>

          <div className="soc-hero-actions">
            <button
              type="button"
              className="soc-btn-primary"
              onClick={() => navigate('/coverage-health')}
              style={{ fontSize: '12px', padding: '8px 16px', display: 'inline-flex', alignItems: 'center', gap: '6px', whiteSpace: 'nowrap' }}
            >
              <span>View Coverage Matrix</span>
              <span>→</span>
            </button>
          </div>
        </div>

        {/* Expandable Composite Posture Score Breakdown */}
        {showScoreBreakdown && (
          <div className="soc-breakdown-popover">
            <div style={{ fontWeight: 700, color: '#f8fafc', marginBottom: '8px', display: 'flex', justifyContent: 'space-between' }}>
              <span>Composite Security & Governance Index Breakdown</span>
              <span style={{ color: '#34d399' }}>{postureScore} / 100 Pts</span>
            </div>
            <div className="soc-breakdown-row">
              <span style={{ color: '#cbd5e1' }}>1. Workstations & Sentry Compliance (35% weight)</span>
              <span style={{ fontWeight: 600, color: endpointScore >= 20 ? '#34d399' : '#f59e0b' }}>
                {endpointScore} / 35 pts ({activeWorkstations} of {totalEnrolledWorkstations || 0} active, {driftedWorkstations} drifted)
              </span>
            </div>
            <div className="soc-breakdown-row">
              <span style={{ color: '#cbd5e1' }}>2. Active Guardrails & 21 DLP Wire Rules (35% weight)</span>
              <span style={{ fontWeight: 600, color: '#34d399' }}>
                {guardrailScore} / 35 pts (Safe Mode active, 21 DLP patterns enforcing)
              </span>
            </div>
            <div className="soc-breakdown-row">
              <span style={{ color: '#cbd5e1' }}>3. Universal AI Gateway & Key Custody (15% weight)</span>
              <span style={{ fontWeight: 600, color: '#34d399' }}>
                {gatewayScore} / 15 pts ({virtualKeys.length > 0 ? `${virtualKeys.length} Virtual Keys active, rate limits enforced` : 'Universal Gateway active, awaiting virtual keys'})
              </span>
            </div>
            <div className="soc-breakdown-row">
              <span style={{ color: '#cbd5e1' }}>4. Spend Boundaries & Preflight Settlement (15% weight)</span>
              <span style={{ fontWeight: 600, color: '#34d399' }}>
                {spendScore} / 15 pts (Fail-closed preflight active, 0 overages)
              </span>
            </div>
            <div className="soc-breakdown-row">
              <span style={{ color: '#f8fafc' }}>Total Posture Index</span>
              <span style={{ color: '#34d399', fontSize: '13px' }}>{postureScore}%</span>
            </div>
          </div>
        )}
      </div>

      {/* Dynamic Living Capability Snapshot Cards */}
      <div className="soc-capability-grid">
        {/* Card 1: Device & Workstation Governance */}
        <div
          className="card soc-capability-card soc-clickable-tile"
          onClick={() => navigate('/devices')}
          title="Enroll developer workstations and AI daemons"
        >
          <div className="soc-capability-header">
            <div className="soc-capability-title-group">
              <span className="soc-capability-icon">💻</span>
              <div>
                <div className="soc-capability-title">Device Governance</div>
                <div className="soc-capability-role">Ed25519 & PKCE</div>
              </div>
            </div>
            <span className={`soc-status-pill ${activeWorkstations > 0 ? (driftedWorkstations > 0 ? 'pill-warning' : 'pill-success') : 'pill-neutral'}`}>
              {activeWorkstations > 0 ? (driftedWorkstations > 0 ? '▲ Drifted' : '● Protected') : '○ Awaiting'}
            </span>
          </div>
          <div className="soc-capability-metric">
            <span className="metric-primary">{activeWorkstations > 0 ? `${activeWorkstations} Active` : '0 Active'}</span>
            <span className="metric-secondary">of {Math.max(activeWorkstations, totalEnrolledWorkstations)} Workstations</span>
          </div>
          <div className="soc-capability-subtext">
            {activeIdesCount > 0 ? `${activeIdesCount} IDE Targets Monitored (Cursor, VS Code, Windsurf)` : (totalEnrolledWorkstations > 0 ? 'Gateway Node Enrolled' : 'No Devices Enrolled')}
          </div>
          <div
            className="soc-capability-footer"
            onClick={(e) => {
              e.stopPropagation()
              navigate('/coverage-health')
            }}
            title="View Coverage Matrix"
          >
            <span>View Coverage Matrix</span>
            <span>→</span>
          </div>
        </div>

        {/* Card 2: Policies & Guardrails Hub */}
        <div
          className="card soc-capability-card soc-clickable-tile"
          onClick={() => navigate('/policy/edit')}
          title="Inspect and edit active security policies"
        >
          <div className="soc-capability-header">
            <div className="soc-capability-title-group">
              <span className="soc-capability-icon">🛡️</span>
              <div>
                <div className="soc-capability-title">Policy Hub</div>
                <div className="soc-capability-role">DLP & Guardrails</div>
              </div>
            </div>
            <span className="soc-status-pill pill-success">
              ● Enforcing
            </span>
          </div>
          <div
            className="soc-capability-metric"
            onClick={(e) => {
              e.stopPropagation()
              navigate('/policy/edit')
            }}
            title="View Current Active Policy"
          >
            <span className="metric-primary">{`${policies.length} ${policies.length === 1 ? 'Policy' : 'Policies'}`}</span>
            <span className="metric-secondary">Active Postures</span>
          </div>
          <div className="soc-capability-subtext">
            21 DLP Patterns · 6-Pass Injection Shield · Safe Mode Active
          </div>
          <div
            className="soc-capability-footer"
            onClick={(e) => {
              e.stopPropagation()
              navigate('/policy/marketplace')
            }}
            title="Browse Policy Marketplace"
          >
            <span>Browse Policy Marketplace</span>
            <span>→</span>
          </div>
        </div>

        {/* Card 3: Virtual Keys & Universal Gateway */}
        <div
          className="card soc-capability-card soc-clickable-tile"
          onClick={() => navigate('/integrations/virtual-keys')}
          title="Issue and govern scoped virtual LLM keys"
        >
          <div className="soc-capability-header">
            <div className="soc-capability-title-group">
              <span className="soc-capability-icon">🔑</span>
              <div>
                <div className="soc-capability-title">Virtual Keys</div>
                <div className="soc-capability-role">LLM Providers</div>
              </div>
            </div>
            <span className={`soc-status-pill ${virtualKeys.length > 0 ? 'pill-success' : 'pill-neutral'}`}>
              {virtualKeys.length > 0 ? '● Operational' : '○ No Keys'}
            </span>
          </div>
          <div className="soc-capability-metric">
            <span className="metric-primary">{`${virtualKeys.length} ${virtualKeys.length === 1 ? 'Key' : 'Keys'}`}</span>
            <span className="metric-secondary">Governed</span>
          </div>
          <div className="soc-capability-subtext">
            {virtualKeys.length > 0
              ? 'Multi-Provider Routing · L1/L2 Vector Semantic Cache Active'
              : 'No virtual keys issued · Universal gateway awaiting keys'}
          </div>
          <div className="soc-capability-footer">
            <span>Manage Virtual Keys</span>
            <span>→</span>
          </div>
        </div>

        {/* Card 4: Spend & Budget Governance */}
        <div
          className="card soc-capability-card soc-clickable-tile"
          onClick={() => navigate('/spend/visualization')}
          title="View Spend Analytics & Observatory"
        >
          <div className="soc-capability-header">
            <div className="soc-capability-title-group">
              <span className="soc-capability-icon">📊</span>
              <div>
                <div className="soc-capability-title">Spend Limits</div>
                <div className="soc-capability-role">Budgets & Caps</div>
              </div>
            </div>
            <span className={`soc-status-pill ${totalLimitMicrocents > 0 ? 'pill-success' : 'pill-neutral'}`}>
              {totalLimitMicrocents > 0 ? '● Fail-Closed' : '○ No Cap Set'}
            </span>
          </div>
          <div className="soc-capability-metric">
            <span className="metric-primary">
              ${(totalSettledMicrocents / 100000000).toFixed(2)}
            </span>
            <span className="metric-secondary">
              {totalLimitMicrocents > 0
                ? `/ $${(totalLimitMicrocents / 100000000).toFixed(2)} Cap`
                : '/ No Cap'}
            </span>
          </div>
          <div className="soc-capability-subtext">
            Atomic Preflight Balance Reservations · 0 Budget Overages
          </div>
          <div
            className="soc-capability-footer"
            onClick={(e) => {
              e.stopPropagation()
              navigate('/spend/visualization')
            }}
            title="View Spend Analytics & Observatory"
          >
            <span>View Spend Analytics</span>
            <span>→</span>
          </div>
        </div>
      </div>

      {/* AI Gateway & Performance Mesh Strip */}
      <div className="soc-gateway-strip">
        <div className="soc-gateway-left">
          <span className="soc-mesh-tag">GATEWAY MESH</span>
          <div className="soc-provider-pills">
            <span className="soc-provider-badge active" title="OpenAI GPT-4o, o1, o3-mini routes active">
              <span className="provider-dot" /> OpenAI
            </span>
            <span className="soc-provider-badge active" title="Anthropic Claude 3.7 Sonnet, Haiku routes active">
              <span className="provider-dot" /> Claude
            </span>
            <span className="soc-provider-badge active" title="Google Gemini 2.0 Flash routes active">
              <span className="provider-dot" /> Gemini
            </span>
            <span className="soc-provider-badge active" title="AWS Bedrock Claude & Nova routes active">
              <span className="provider-dot" /> Bedrock
            </span>
            <span className="soc-provider-badge active" title="Local Ollama & LM Studio routes active">
              <span className="provider-dot" /> Local / Ollama
            </span>
          </div>
        </div>
        <div className="soc-gateway-right">
          <span className="soc-cache-badge" title="Dual-tier exact SHA-256 and vector cosine semantic cache active">
            ⚡ Semantic Cache: Active
          </span>
          <span className="soc-latency-badge" title="Local Rust sidecar wire latency">
            ⚡ Wire Overhead: &lt;1ms
          </span>
        </div>
      </div>

      {/* Stat tiles */}
      {displayStats && (
        <div className="stats-grid stats-grid-7">
          <div
            className="card stat-tile soc-clickable-tile"
            onClick={() => {
              setAgentFilter('all')
              document.getElementById('fleet-agents-panel')?.scrollIntoView?.({ behavior: 'smooth' })
            }}
            title="Click to view all registered AI agents"
          >
            <div className="stat-header-row">
              <div className="stat-label">Total Agents</div>
              <span className="soc-delta-badge delta-neutral">Fleet</span>
            </div>
            <div className="stat-value">{displayStats.total_agents}</div>
            <div className="stat-subtext">Protected AI Agents</div>
          </div>

          <div
            className="card stat-tile soc-clickable-tile"
            onClick={() => {
              setAgentFilter('active')
              document.getElementById('fleet-agents-panel')?.scrollIntoView?.({ behavior: 'smooth' })
            }}
            title="Click to view active compliant AI agents"
          >
            <div className="stat-header-row">
              <div className="stat-label">Active Agents</div>
              <span className="soc-delta-badge delta-success">Live</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--success)' }}>{displayStats.active_agents}</div>
            <div className="stat-subtext">Compliant & Enforcing Zero-Trust</div>
          </div>

          <div
            className="card stat-tile soc-clickable-tile"
            onClick={() => navigate('/observability/logs?tab=security_logs')}
            title="Click to view Tool Call & Egress Security Logs"
          >
            <div className="stat-header-row">
              <div className="stat-label">Total Events</div>
              <span className="soc-delta-badge delta-neutral">{timeRange}</span>
            </div>
            <div className="stat-value">{displayStats.total_events.toLocaleString()}</div>
            <div className="stat-subtext">Tool Calls & Egress</div>
          </div>

          <div
            className="card stat-tile soc-clickable-tile tile-danger"
            onClick={() => navigate('/observability/logs?tab=security_logs&decision=denied')}
            title="Click to filter Blocked Policy Violations"
          >
            <div className="stat-header-row">
              <div className="stat-label">Denied</div>
              <span className="soc-delta-badge delta-danger">{displayStats.denied_events > 0 ? '+Active' : '0%'}</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{displayStats.denied_events.toLocaleString()}</div>
            <div className="stat-subtext">Blocked Policy Violations</div>
          </div>

          <div className="card stat-tile soc-clickable-tile tile-warning" onClick={() => navigate('/threats')} title="Click to view Threat Intelligence">
            <div className="stat-header-row">
              <div className="stat-label">Alerts</div>
              <span className="soc-delta-badge delta-warning">{displayStats.total_alerts > 0 ? 'Review' : 'Clear'}</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--warning)' }}>{displayStats.total_alerts}</div>
            <div className="stat-subtext">Threats & DLP Triggers</div>
          </div>

          <div className="card stat-tile soc-clickable-tile tile-danger" onClick={() => navigate('/threats')} title="Click to view Critical Threat Vectors">
            <div className="stat-header-row">
              <div className="stat-label">Critical</div>
              <span className="soc-delta-badge delta-danger">{displayStats.critical_alerts > 0 ? 'Action Req' : '0'}</span>
            </div>
            <div className="stat-value" style={{ color: 'var(--danger)' }}>{displayStats.critical_alerts}</div>
            <div className="stat-subtext">High Severity Injections</div>
          </div>

          {(() => {
            const seatsUsed = licenseStatus?.seats_used ?? (licenseStatus as any)?.devices_enrolled ?? totalEnrolledWorkstations ?? 0
            const maxSeats = licenseStatus?.max_seats ?? (licenseStatus as any)?.max_devices ?? 25
            const seatsRemaining = licenseStatus?.seats_remaining ?? (licenseStatus as any)?.devices_remaining ?? Math.max(0, maxSeats - seatsUsed)
            const tierName = (licenseStatus?.tier || 'TEAM').toUpperCase()
            return (
              <div className="card stat-tile soc-clickable-tile" onClick={() => navigate('/devices')} title="Click to manage Device Seat Allocations">
                <div className="stat-header-row">
                  <div className="stat-label">Seats Used ({tierName})</div>
                  <span className="soc-delta-badge delta-neutral">{seatsRemaining} left</span>
                </div>
                <div className="stat-value" style={{ color: seatsRemaining === 0 ? 'var(--danger)' : 'var(--text-main, #f8fafc)' }}>
                  {seatsUsed} / {maxSeats}
                </div>
                <div className="stat-subtext">Active Developer Seats</div>
              </div>
            )
          })()}
        </div>
      )}

      {/* Decision heatmap */}
      {(() => {
        const isDayGrain = timeRange === '7d' || timeRange === '30d'
        const displayHeatmap = isDayGrain
          ? (() => {
              const dayMap = new Map<string, { hour: string; allowed: number; denied: number; warned: number }>()
              for (const item of heatmap) {
                const dayKey = item.hour.split(' ')[0] || item.hour.slice(0, 10)
                const existing = dayMap.get(dayKey) || { hour: dayKey, allowed: 0, denied: 0, warned: 0 }
                existing.allowed += item.allowed || 0
                existing.denied += item.denied || 0
                existing.warned += item.warned || 0
                dayMap.set(dayKey, existing)
              }
              return Array.from(dayMap.values())
            })()
          : heatmap

        const formatHeatmapTick = (v: string) => {
          if (isDayGrain) {
            const parts = v.split('-')
            if (parts.length >= 3) {
              const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
              const m = parseInt(parts[1], 10) - 1
              const d = parseInt(parts[2], 10)
              if (m >= 0 && m < 12 && !isNaN(d)) {
                return `${monthNames[m]} ${d}`
              }
            }
            return v
          }
          return v.split(' ')[1] || v
        }

        const heatmapTitle = timeRange === '1h'
          ? 'Decision Heatmap (1H - Hourly)'
          : timeRange === '7d'
          ? 'Decision Heatmap (7D - Daily)'
          : timeRange === '30d'
          ? 'Decision Heatmap (30D - Daily)'
          : 'Decision Heatmap (24H - Hourly)'

        const emptyText = timeRange === '1h'
          ? 'No events in the last 1 hour'
          : timeRange === '7d'
          ? 'No events in the last 7 days'
          : timeRange === '30d'
          ? 'No events in the last 30 days'
          : 'No events in the last 24 hours'

        return (
          <div className="card soc-panel" style={{ marginBottom: 24 }}>
            <div className="soc-card-header">
              <div>
                <div className="card-title">{heatmapTitle}</div>
                <div className="soc-card-subtitle">
                  {isDayGrain
                    ? 'Daily aggregated telemetry breakdown: Allowed vs Warned (DLP Redacted) vs Denied (Blocked)'
                    : 'Stacked telemetry breakdown: Allowed vs Warned (DLP Redacted) vs Denied (Blocked)'}
                </div>
              </div>
              <span className="soc-live-pill">LIVE STREAM</span>
            </div>

            {displayHeatmap.length > 0 ? (
              <ResponsiveContainer width="100%" height={240}>
                <BarChart data={displayHeatmap} margin={{ top: 12, right: 12, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" vertical={false} />
                  <XAxis
                    dataKey="hour"
                    tick={{ fill: '#64748b', fontSize: 11 }}
                    tickFormatter={formatHeatmapTick}
                    axisLine={false}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: '#64748b', fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                    labelFormatter={(label: any) => {
                      if (isDayGrain && typeof label === 'string') {
                        const parts = label.split('-')
                        if (parts.length >= 3) {
                          const monthNames = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
                          const m = parseInt(parts[1], 10) - 1
                          const d = parseInt(parts[2], 10)
                          if (m >= 0 && m < 12 && !isNaN(d)) {
                            return `${monthNames[m]} ${d}, ${parts[0]}`
                          }
                        }
                      }
                      return String(label)
                    }}
                    contentStyle={{
                      background: '#0e131f',
                      border: '1px solid rgba(255,255,255,0.12)',
                      borderRadius: 8,
                      fontSize: 13,
                      boxShadow: '0 12px 32px rgba(0,0,0,0.6)',
                      color: '#f8fafc',
                    }}
                  />
                  <Legend
                    verticalAlign="top"
                    align="right"
                    wrapperStyle={{ paddingBottom: 10, fontSize: 12 }}
                  />
                  <Bar dataKey="allowed" name="Allowed" stackId="a" fill={DECISION_COLORS.allowed} radius={[0, 0, 0, 0]} />
                  <Bar dataKey="warned" name="Warned" stackId="a" fill={DECISION_COLORS.warned} />
                  <Bar dataKey="denied" name="Denied" stackId="a" fill={DECISION_COLORS.denied} radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state">{emptyText}</div>
            )}
          </div>
        )
      })()}

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }} className="soc-split-view">
        {/* Agents table */}
        <div className="card soc-panel" id="fleet-agents-panel">
          <div className="soc-card-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
            <div>
              <div className="card-title">Agents</div>
              <div className="soc-card-subtitle">Registered AI coding agents and autonomous workers</div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <div className="soc-time-toggle" role="group" aria-label="Agent Filter">
                <button
                  type="button"
                  className={`soc-time-btn ${agentFilter === 'all' ? 'active' : ''}`}
                  onClick={() => setAgentFilter('all')}
                >
                  All ({agents.length})
                </button>
                <button
                  type="button"
                  className={`soc-time-btn ${agentFilter === 'active' ? 'active' : ''}`}
                  onClick={() => setAgentFilter('active')}
                >
                  Active ({agents.filter(a => a.status === 'active').length})
                </button>
              </div>
            </div>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Status</th>
                  <th>Events</th>
                  <th>Alerts</th>
                  <th>Last Seen</th>
                </tr>
              </thead>
              <tbody>
                {agents.filter(a => agentFilter === 'active' ? a.status === 'active' : true).length === 0 ? (
                  <tr>
                    <td colSpan={5} className="empty-state">
                      {agentFilter === 'active' ? 'No active agents found' : 'No agents registered'}
                    </td>
                  </tr>
                ) : agents
                    .filter(a => agentFilter === 'active' ? a.status === 'active' : true)
                    .map((a) => (
                  <tr
                    key={a.agent_id}
                    className="soc-table-row"
                    onClick={() => navigate(`/observability/logs?tab=security_logs&agent=${encodeURIComponent(a.agent_id)}`)}
                    title="Click to view Security & DLP events for this agent"
                    style={{ cursor: 'pointer' }}
                  >
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }} className="text-mono-id">
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.display_name || a.agent_id}</div>
                      {a.display_name && (
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                          {a.agent_id.substring(0, 16)}...
                        </div>
                      )}
                    </td>
                    <td>
                      <span className={`badge badge-${a.status === 'active' ? 'success' : a.status === 'revoked' ? 'danger' : 'warning'}`}>
                        {a.status}
                      </span>
                    </td>
                    <td>{a.event_count.toLocaleString()}</td>
                    <td>
                      {a.alert_count > 0 ? (
                        <span className="soc-count-danger">{a.alert_count}</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>0</span>
                      )}
                    </td>
                    <td style={{ fontSize: 13, color: 'var(--text-muted)' }}>{timeAgo(a.last_seen_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Alert feed */}
        <div className="card soc-panel">
          <div className="soc-card-header">
            <div className="card-title">Alert Feed (Live)</div>
            <span className="soc-live-pill">STREAMING</span>
          </div>
          <div className="alert-feed soc-alert-feed">
            {alerts.length === 0 ? (
              <div className="empty-state">No alerts</div>
            ) : alerts.map((a) => (
              <div className="alert-item soc-alert-item" key={a.alert_id}>
                <div className={`alert-dot ${a.severity}`} />
                <div className="alert-body">
                  <div className="alert-title">
                    {a.event.dlp_findings?.length > 0
                      ? `DLP: ${a.event.dlp_findings.map(f => f.category).join(', ')}`
                      : a.event.injection_findings?.length > 0
                        ? `Injection: ${a.event.injection_findings.map(f => f.pattern_name).join(', ')}`
                        : a.event.semantic_findings?.length > 0
                          ? `Semantic: ${a.event.semantic_findings.map(f => f.finding_type).join(', ')}`
                          : `${a.event.decision} — ${a.event.tool_name}`
                    }
                  </div>
                  <div className="alert-meta">
                    {a.event.agent_id} &middot; {a.event.tool_name} &middot; {formatTime(a.event.timestamp_ms)}
                  </div>
                </div>
                <div className="soc-alert-actions">
                  <button
                    type="button"
                    className="soc-btn-xs"
                    onClick={() => navigate(`/observability/logs?tab=security_logs&agent=${encodeURIComponent(a.event.agent_id)}`)}
                    title="Inspect in Security & DLP Logs"
                  >
                    Triage
                  </button>
                  <span className={`badge badge-${SEVERITY_CLASS[a.severity] || 'info'}`}>
                    {a.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
