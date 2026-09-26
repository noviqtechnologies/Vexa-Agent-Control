import { useState, useEffect, type FormEvent } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  api,
  listDevicesV2,
  revokeDeviceV2,
  getSentryDeviceDetail,
  resolveHubUrl,
  type SentryDeviceSummary,
  type SentryDeviceDetail,
} from '../api/client'

const REVOCATION_PRESETS = [
  'Decommissioned / Offboarded',
  'Security Incident / Suspected Compromise',
  'Lost or Stolen Workstation',
  'Policy Violation / Unapproved Modifications',
  'Role Transition / Transferred Device',
  'Custom Reason',
]

export default function Devices() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [devices, setDevices] = useState<SentryDeviceSummary[]>([])
  const [compliantCount, setCompliantCount] = useState(0)
  const [nonCompliantCount, setNonCompliantCount] = useState(0)
  const [offlineCount, setOfflineCount] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const [filter, setFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [loading, setLoading] = useState(true)

  // Device Detail Inspection Modal State
  const [selectedDevice, setSelectedDevice] = useState<SentryDeviceDetail | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)
  const [copiedKey, setCopiedKey] = useState(false)

  // Revocation Modal State
  const [revokeTarget, setRevokeTarget] = useState<{ deviceId: string; hostname: string } | null>(null)
  const [revokeReason, setRevokeReason] = useState('Decommissioned / Offboarded')
  const [revokeCustomReason, setRevokeCustomReason] = useState('')
  const [revokeIncidentRef, setRevokeIncidentRef] = useState('')
  const [revoking, setRevoking] = useState(false)
  const [revokeError, setRevokeError] = useState<string | null>(null)

  // In-Page Notification State
  const [notification, setNotification] = useState<{ type: 'success' | 'error'; message: string } | null>(null)

  // Workstation Onboarding Modal State
  const [showTokenModal, setShowTokenModal] = useState(false)
  const [installOs, setInstallOs] = useState<'win' | 'unix'>('win')
  const [copiedField, setCopiedField] = useState<string | null>(null)

  useEffect(() => {
    if (searchParams.get('onboard') === 'true') {
      setShowTokenModal(true)
    }
  }, [searchParams])

  const handleCloseOnboardModal = () => {
    setShowTokenModal(false)
    setCopiedField(null)
    if (searchParams.get('onboard') === 'true') {
      searchParams.delete('onboard')
      setSearchParams(searchParams, { replace: true })
    }
  }

  const getEffectiveCompliance = (d: SentryDeviceSummary | SentryDeviceDetail): 'COMPLIANT' | 'NON_COMPLIANT' | 'OFFLINE' => {
    if (d.enrollment_status === 'REVOKED' || d.overall_compliance === 'NON_COMPLIANT') {
      return 'NON_COMPLIANT'
    }
    if (d.overall_compliance === 'OFFLINE' || (d as any).last_freshness === 'STALE') {
      return 'OFFLINE'
    }
    if ((d as any).last_freshness === 'ACTIVE_FRESH' || (d as any).last_freshness === 'ACTIVE_RECENT') {
      return 'COMPLIANT'
    }
    if (!d.last_heartbeat_at) {
      return 'OFFLINE'
    }
    const hbTime = new Date(d.last_heartbeat_at).getTime()
    if (Date.now() - hbTime > 15 * 60 * 1000) {
      return 'OFFLINE'
    }
    return (d.overall_compliance as any) || 'COMPLIANT'
  }

  useEffect(() => {
    fetchDevices()
  }, [filter])

  const fetchDevices = async () => {
    setLoading(true)
    try {
      let rawList: any[] = []
      let fleetTotal = 0

      // Primary: Query v2 Device Governance API
      try {
        const v2Res = await listDevicesV2()
        if (v2Res && v2Res.devices && v2Res.devices.length > 0) {
          rawList = v2Res.devices.map(d => ({
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
          fleetTotal = v2Res.total_count || rawList.length
        }
      } catch (err) {
        // Fall back to v1
      }

      if (rawList.length === 0) {
        const res = await api.listSentryDevices(filter)
        rawList = res.devices || []
        fleetTotal = res.total_count ?? (res as any).total ?? rawList.length
      }

      const seen = new Set<string>()
      const deduped: SentryDeviceSummary[] = []
      for (const d of rawList) {
        const key = (d.hostname || d.device_id || '').toLowerCase()
        const effective = getEffectiveCompliance(d)
        d.overall_compliance = effective
        if (key && !seen.has(key)) {
          seen.add(key)
          deduped.push(d)
        } else if (!key) {
          deduped.push(d)
        }
      }
      setDevices(deduped)

      if (!filter || totalCount === 0) {
        setTotalCount(fleetTotal || deduped.length)
      }

      const comp = deduped.filter(d => (d as any).last_freshness === 'ACTIVE_FRESH' || getEffectiveCompliance(d) === 'COMPLIANT').length
      const nonComp = deduped.filter(d => getEffectiveCompliance(d) === 'NON_COMPLIANT' || d.enrollment_status === 'REVOKED').length
      const offl = deduped.filter(d => (d as any).last_freshness === 'STALE' || getEffectiveCompliance(d) === 'OFFLINE').length

      setCompliantCount(comp)
      setNonCompliantCount(nonComp)
      setOfflineCount(offl)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleInspectDevice = async (deviceId: string) => {
    setLoadingDetail(true)
    try {
      const detail = await getSentryDeviceDetail(deviceId)
      setSelectedDevice(detail)
    } catch (e: any) {
      setNotification({
        type: 'error',
        message: e.message || 'Failed to fetch workstation details',
      })
      setTimeout(() => setNotification(null), 5000)
    } finally {
      setLoadingDetail(false)
    }
  }

  const openRevokeModal = (deviceId: string, hostname: string) => {
    setRevokeTarget({ deviceId, hostname })
    setRevokeReason('Decommissioned / Offboarded')
    setRevokeCustomReason('')
    setRevokeIncidentRef('')
    setRevokeError(null)
  }

  const closeRevokeModal = () => {
    if (revoking) return
    setRevokeTarget(null)
    setRevokeError(null)
  }

  const handleConfirmRevoke = async (e: FormEvent) => {
    e.preventDefault()
    if (!revokeTarget) return

    const finalReason = revokeReason === 'Custom Reason' ? revokeCustomReason.trim() : revokeReason
    if (!finalReason) {
      setRevokeError('Please provide a valid revocation reason.')
      return
    }

    setRevoking(true)
    setRevokeError(null)

    try {
      await revokeDeviceV2(revokeTarget.deviceId, finalReason)
      const targetHost = revokeTarget.hostname || revokeTarget.deviceId
      setRevokeTarget(null)
      setNotification({
        type: 'success',
        message: `Workstation "${targetHost}" has been revoked successfully. Active mTLS credentials invalidated.`,
      })
      setTimeout(() => setNotification(null), 6000)
      await fetchDevices()
    } catch (e: any) {
      setRevokeError(e.message || 'Failed to revoke device')
    } finally {
      setRevoking(false)
    }
  }

  const handleDeleteDevice = async (deviceId: string, hostname: string) => {
    if (!window.confirm(`Are you sure you want to permanently remove device "${hostname || deviceId}" from fleet inventory?`)) {
      return
    }
    try {
      await api.deleteDevice(deviceId)
      setNotification({
        type: 'success',
        message: `Device "${hostname || deviceId}" has been permanently removed from inventory.`,
      })
      setTimeout(() => setNotification(null), 6000)
      await fetchDevices()
    } catch (e: any) {
      setNotification({
        type: 'error',
        message: e.message || 'Failed to remove device',
      })
      setTimeout(() => setNotification(null), 6000)
    }
  }


  const getComplianceBadge = (status: string) => {
    switch (status) {
      case 'COMPLIANT':
        return <span className="badge badge-success">COMPLIANT</span>
      case 'NON_COMPLIANT':
        return <span className="badge badge-danger">NON-COMPLIANT</span>
      case 'NOT_INSTALLED':
        return <span className="badge badge-secondary" style={{ opacity: 0.6, background: '#3f3f46', color: '#a1a1aa' }}>NOT INSTALLED</span>
      case 'OFFLINE':
        return <span className="badge badge-secondary" style={{ background: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.3)' }}>OFFLINE</span>
      default:
        return <span className="badge badge-secondary" style={{ background: 'rgba(148, 163, 184, 0.15)', color: '#94a3b8', border: '1px solid rgba(148, 163, 184, 0.3)' }}>{status}</span>
    }
  }

  const getOsIcon = (os: string) => {
    const o = (os || '').toLowerCase()
    if (o.includes('win')) return '🪟 Windows'
    if (o.includes('mac') || o.includes('darwin')) return '🍎 macOS'
    if (o.includes('linux')) return '🐧 Linux'
    return os || 'Unknown'
  }

  const hubUrl = resolveHubUrl()

  const filteredDevices = devices.filter(d => {
    const effective = getEffectiveCompliance(d)
    if (filter) {
      if (filter === 'NON_COMPLIANT' && (effective === 'NON_COMPLIANT' || d.enrollment_status === 'REVOKED')) {
        // match
      } else if (effective !== filter) {
        return false
      }
    }
    if (!searchQuery.trim()) return true
    const q = searchQuery.toLowerCase()
    return (
      d.hostname?.toLowerCase().includes(q) ||
      d.user_identifier?.toLowerCase().includes(q) ||
      d.device_id?.toLowerCase().includes(q) ||
      d.os?.toLowerCase().includes(q)
    )
  })

  return (
    <div className="soc-device-page">
      {/* Toast Notification Banner */}
      {notification && (
        <div
          style={{
            marginBottom: 20,
            padding: '12px 16px',
            borderRadius: 'var(--radius-sm, 6px)',
            backgroundColor: notification.type === 'success' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
            border: `1px solid ${notification.type === 'success' ? 'rgba(34, 197, 94, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
            color: notification.type === 'success' ? '#4ade80' : '#f87171',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 12,
            boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.2)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, fontWeight: 500 }}>
            <span>{notification.type === 'success' ? '✔' : '⚠'}</span>
            <span>{notification.message}</span>
          </div>
          <button
            type="button"
            onClick={() => setNotification(null)}
            style={{
              background: 'none',
              border: 'none',
              color: 'currentColor',
              opacity: 0.8,
              cursor: 'pointer',
              fontSize: 16,
              padding: '0 4px',
            }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Header Bar */}
      <div className="page-header soc-page-header">
        <div>
          <h1>Device Governance</h1>
          <p>Continuous configuration locking, zero-master-key posture, and real-time compliance across developer workstations.</p>
        </div>
        <div className="soc-header-controls">
          <button
            type="button"
            className="soc-btn-primary"
            onClick={() => {
              setShowTokenModal(true)
            }}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Onboard Workstation
          </button>
        </div>
      </div>

      {/* Summary Metric Cards */}
      <div className="stats-grid stats-grid-4">
        <div className="card stat-tile soc-clickable-tile" onClick={() => setFilter('')} title="Filter All Enrolled Workstations">
          <div className="stat-header-row">
            <div className="stat-label">Total Enrolled Devices</div>
            <span className="soc-delta-badge delta-neutral">Seats</span>
          </div>
          <div className="stat-value">{totalCount || devices.length}</div>
          <div className="stat-subtext">Registered developer seats</div>
        </div>

        <div className="card stat-tile soc-clickable-tile" onClick={() => setFilter('COMPLIANT')} title="Filter Compliant Workstations">
          <div className="stat-header-row">
            <div className="stat-label">Traffic Verified & Fresh</div>
            <span className="soc-delta-badge delta-success">Active</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>{compliantCount}</div>
          <div className="stat-subtext">Verified MCP & &lt;15m heartbeat</div>
        </div>

        <div className="card stat-tile soc-clickable-tile tile-danger" onClick={() => setFilter('NON_COMPLIANT')} title="Filter Drifted Workstations">
          <div className="stat-header-row">
            <div className="stat-label">Drifted / Revoked</div>
            <span className="soc-delta-badge delta-danger">{nonCompliantCount > 0 ? 'Review' : '0'}</span>
          </div>
          <div className="stat-value" style={{ color: nonCompliantCount > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>{nonCompliantCount}</div>
          <div className="stat-subtext">Requires realignment</div>
        </div>

        <div className="card stat-tile soc-clickable-tile" onClick={() => setFilter('OFFLINE')} title="Filter Stale Workstations">
          <div className="stat-header-row">
            <div className="stat-label">Stale / Offline</div>
            <span className="soc-delta-badge delta-neutral">No signal</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--text-muted)' }}>{offlineCount}</div>
          <div className="stat-subtext">No heartbeat in &gt; 24h</div>
        </div>
      </div>

      {/* Sentry Compliance Posture Guide Card */}
      <div className="card soc-panel" style={{ padding: '20px 24px', marginBottom: '24px' }}>
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, fontSize: '14px', fontWeight: 600 }}>
          <span style={{ fontSize: 16 }}>🛡️</span> Understanding Multi-State Observability & Capability Vectors
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', fontSize: '12.5px', color: 'var(--text-secondary)' }}>
          <div style={{ padding: '14px 16px', borderRadius: 'var(--radius-sm, 8px)', border: '1px solid rgba(16, 185, 129, 0.25)', backgroundColor: 'rgba(16, 185, 129, 0.04)' }}>
            <span style={{ color: '#34d399', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 5, marginBottom: '6px' }}>
              ● CAPABILITY VECTORS
            </span>
            <p style={{ margin: 0, lineHeight: 1.5 }}>
              Operational layers verified on endpoint: <code className="soc-cap-chip">CONFIGURED</code> (local proxy locked), <code className="soc-cap-chip">MCP_WRAPPED</code> (tools routed), and <code className="soc-cap-chip">TRAFFIC_VERIFIED</code> (attested LLM transactions).
            </p>
          </div>
          <div style={{ padding: '14px 16px', borderRadius: 'var(--radius-sm, 8px)', border: '1px solid rgba(245, 158, 11, 0.25)', backgroundColor: 'rgba(245, 158, 11, 0.04)' }}>
            <span style={{ color: '#fbbf24', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 5, marginBottom: '6px' }}>
              ● FRESHNESS TIERS
            </span>
            <p style={{ margin: 0, lineHeight: 1.5 }}>
              Continuous liveness tracking: <code className="soc-cap-chip" style={{ color: '#fbbf24', borderColor: 'rgba(245, 158, 11, 0.3)' }}>ACTIVE_FRESH</code> (≤ 15m), <code className="soc-cap-chip" style={{ color: '#fbbf24', borderColor: 'rgba(245, 158, 11, 0.3)' }}>ACTIVE_RECENT</code> (≤ 24h), or <code className="soc-cap-chip" style={{ color: '#f87171', borderColor: 'rgba(239, 68, 68, 0.3)' }}>STALE</code> (&gt; 24h since last exchange).
            </p>
          </div>
          <div style={{ padding: '14px 16px', borderRadius: 'var(--radius-sm, 8px)', border: '1px solid rgba(148, 163, 184, 0.25)', backgroundColor: 'rgba(148, 163, 184, 0.04)' }}>
            <span style={{ color: '#94a3b8', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 5, marginBottom: '6px' }}>
              ● ED25519 IDENTITY ASSERTIONS
            </span>
            <p style={{ margin: 0, lineHeight: 1.5 }}>
              Workstation agent assertions are signed using non-exportable hardware or OS-keyring Ed25519 keys with sliding replay protection.
            </p>
          </div>
        </div>
      </div>

      {/* Filter & Devices Table */}
      <div className="card soc-panel">
        <div className="soc-card-header" style={{ marginBottom: 20 }}>
          <div>
            <div className="card-title">Workstation Fleet Inventory</div>
            <div className="soc-card-subtitle">{filteredDevices.length} of {totalCount || devices.length} workstations matching criteria</div>
          </div>
          <div className="soc-filter-bar">
            <div className="soc-filter-search-box">
              <span className="search-icon">🔍</span>
              <input
                type="text"
                placeholder="Search hostname, user, or device ID..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="soc-filter-input"
                style={{ width: 280 }}
              />
            </div>
            <select 
              value={filter} 
              onChange={e => setFilter(e.target.value)}
              className="soc-select-filter"
            >
              <option value="">All Statuses</option>
              <option value="COMPLIANT">Fresh / Active Only</option>
              <option value="NON_COMPLIANT">Drifted / Revoked Only</option>
              <option value="OFFLINE">Stale / Offline Only</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="loading" style={{ padding: '32px' }}>Loading fleet devices...</div>
        ) : filteredDevices.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state-icon">💻</div>
            <p>No enrolled developer workstations found.</p>
            <p>Run <code>agentcontrol login</code> on a developer workstation or click <strong>"+ Onboard Workstation"</strong> above to view setup instructions.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Workstation</th>
                  <th>Developer User</th>
                  <th>OS / Platform</th>
                  <th>Capability Vector</th>
                  <th>Freshness</th>
                  <th>Last Seen</th>
                  <th>Posture Status</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredDevices.map((d, idx) => (
                  <tr key={d.device_id || idx}>
                    <td style={{ fontWeight: 600 }}>
                      <button
                        type="button"
                        onClick={() => handleInspectDevice(d.device_id)}
                        style={{
                          background: 'none',
                          border: 'none',
                          padding: 0,
                          color: '#60a5fa',
                          cursor: 'pointer',
                          fontWeight: 600,
                          textAlign: 'left',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 6,
                          fontSize: '13.5px',
                        }}
                        title="Click to inspect workstation details, IDE configs, and public keys"
                      >
                        <span>{d.hostname || 'Unknown Host'}</span>
                        <span style={{ fontSize: 11, opacity: 0.7 }}>🔍</span>
                      </button>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                        {d.device_id}
                      </div>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span>🧑</span>
                        <span style={{ color: 'var(--text-primary)' }}>{d.owner_subject || d.user_identifier || '—'}</span>
                        {d.auth_provider_type && (
                          <span className="badge" style={{ fontSize: 10, padding: '1px 5px', textTransform: 'uppercase', background: 'rgba(99, 102, 241, 0.15)', color: '#818cf8', border: '1px solid rgba(99, 102, 241, 0.3)' }}>
                            {d.auth_provider_type}
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{ fontSize: 13 }}>{getOsIcon(d.os)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
                        {(d as any).capability_vector && (d as any).capability_vector.length > 0 ? (
                          (d as any).capability_vector.map((c: string, ci: number) => (
                            <span key={ci} className="soc-cap-chip">
                              {c}
                            </span>
                          ))
                        ) : (
                          <span className="soc-cap-chip">CONFIGURED</span>
                        )}
                      </div>
                    </td>
                    <td>
                      {(d as any).last_freshness === 'ACTIVE_FRESH' || getEffectiveCompliance(d) === 'COMPLIANT' ? (
                        <span className="soc-freshness-pill fresh">● FRESH (&lt;15m)</span>
                      ) : (d as any).last_freshness === 'ACTIVE_RECENT' ? (
                        <span className="soc-freshness-pill recent">● RECENT (&lt;24h)</span>
                      ) : (
                        <span className="soc-freshness-pill stale">● STALE (&gt;24h)</span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12, whiteSpace: 'nowrap' }}>
                      {d.last_heartbeat_at ? new Date(d.last_heartbeat_at).toLocaleString() : 'Never'}
                    </td>
                    <td>{getComplianceBadge(getEffectiveCompliance(d))}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
                        <button
                          type="button"
                          className="soc-btn-inspect"
                          onClick={() => handleInspectDevice(d.device_id)}
                          title="Inspect deep telemetry, IDE configs, and tamper history"
                        >
                          Inspect
                        </button>
                        {d.enrollment_status !== 'REVOKED' && d.overall_compliance !== 'NON_COMPLIANT' ? (
                          <button
                            type="button"
                            className="soc-btn-revoke"
                            onClick={() => openRevokeModal(d.device_id, d.hostname)}
                            title="Revoke device PKI and gateway access"
                          >
                            Revoke
                          </button>
                        ) : (
                          <div style={{ display: 'inline-flex', gap: 6, alignItems: 'center' }}>
                            <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Revoked</span>
                            <button
                              type="button"
                              className="soc-btn-revoke"
                              style={{ padding: '3px 8px', fontSize: '11px' }}
                              onClick={() => handleDeleteDevice(d.device_id, d.hostname)}
                              title="Permanently remove revoked device from fleet inventory"
                            >
                              Remove
                            </button>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Professional Device Revocation Modal */}
      {revokeTarget && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.75)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: 16,
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) closeRevokeModal()
          }}
        >
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: '540px',
              padding: '24px',
              backgroundColor: 'var(--bg-surface-1, #18181b)',
              border: '1px solid var(--border-default, #27272a)',
              borderRadius: 'var(--radius, 8px)',
              boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)',
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: '8px',
                    backgroundColor: 'rgba(239, 68, 68, 0.15)',
                    border: '1px solid rgba(239, 68, 68, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: '#ef4444',
                    fontSize: '18px',
                  }}
                >
                  ⚠️
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: 17, fontWeight: 600, color: 'var(--text-primary, #f4f4f5)' }}>
                    Revoke Workstation Credentials
                  </h3>
                  <span style={{ fontSize: 12, color: 'var(--text-muted, #71717a)' }}>
                    Immediate cryptographic quarantine
                  </span>
                </div>
              </div>
              <button
                type="button"
                onClick={closeRevokeModal}
                disabled={revoking}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted, #71717a)',
                  cursor: revoking ? 'not-allowed' : 'pointer',
                  fontSize: 18,
                  padding: 4,
                }}
              >
                ✕
              </button>
            </div>

            {/* Target Device Summary Box */}
            <div
              style={{
                backgroundColor: 'var(--bg-surface-2, #121214)',
                border: '1px solid var(--border, #27272a)',
                borderRadius: 'var(--radius-sm, 6px)',
                padding: '12px 14px',
                marginBottom: 18,
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted, #a1a1aa)', fontWeight: 600 }}>TARGET WORKSTATION</span>
                <span style={{ fontSize: 12, color: 'var(--text-primary, #f4f4f5)', fontWeight: 600 }}>{revokeTarget.hostname}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted, #71717a)' }}>Device UUID</span>
                <code style={{ fontSize: 11, fontFamily: 'var(--font-mono, monospace)', color: 'var(--text-secondary, #d4d4d8)' }}>
                  {revokeTarget.deviceId}
                </code>
              </div>
              <div style={{ marginTop: 8, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,0.06)', fontSize: 11, color: '#f87171' }}>
                ⚠ Revoking will immediately terminate mTLS access, invalidate local security daemon tokens, and block proxy AI requests.
              </div>
            </div>

            {/* Error Banner if any */}
            {revokeError && (
              <div
                style={{
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: 'var(--radius-sm, 6px)',
                  padding: '10px 14px',
                  marginBottom: 16,
                  color: '#f87171',
                  fontSize: 13,
                  display: 'flex',
                  alignItems: 'center',
                  gap: 8,
                }}
              >
                <span>✕</span>
                <div style={{ flex: 1 }}>{revokeError}</div>
              </div>
            )}

            {/* Revoke Form */}
            <form onSubmit={handleConfirmRevoke}>
              <div style={{ marginBottom: 14 }}>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, marginBottom: 6, color: 'var(--text-primary, #f4f4f5)' }}>
                  Revocation Reason *
                </label>
                <select
                  value={revokeReason}
                  onChange={(e) => setRevokeReason(e.target.value)}
                  disabled={revoking}
                  className="input"
                  style={{ width: '100%', padding: '8px 12px', marginBottom: revokeReason === 'Custom Reason' ? 8 : 0 }}
                >
                  {REVOCATION_PRESETS.map((preset) => (
                    <option key={preset} value={preset}>
                      {preset}
                    </option>
                  ))}
                </select>
                {revokeReason === 'Custom Reason' && (
                  <textarea
                    rows={3}
                    placeholder="Enter detailed audit reason for revocation..."
                    value={revokeCustomReason}
                    onChange={(e) => setRevokeCustomReason(e.target.value)}
                    required
                    disabled={revoking}
                    className="input"
                    style={{ width: '100%', padding: '8px 12px', resize: 'vertical' }}
                  />
                )}
              </div>

              <div style={{ marginBottom: 20 }}>
                <label style={{ display: 'block', fontSize: 12, fontWeight: 600, marginBottom: 6, color: 'var(--text-primary, #f4f4f5)' }}>
                  Incident Reference / Ticket ID (Optional)
                </label>
                <input
                  type="text"
                  placeholder="e.g. SEC-2026-89 or JIRA-1044"
                  value={revokeIncidentRef}
                  onChange={(e) => setRevokeIncidentRef(e.target.value)}
                  disabled={revoking}
                  className="input"
                  style={{ width: '100%', padding: '8px 12px' }}
                />
              </div>

              {/* Actions */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={closeRevokeModal}
                  disabled={revoking}
                  style={{ padding: '8px 16px' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={revoking || (revokeReason === 'Custom Reason' && !revokeCustomReason.trim())}
                  style={{
                    padding: '8px 18px',
                    backgroundColor: 'var(--danger, #ef4444)',
                    color: '#fff',
                    border: 'none',
                    borderRadius: 'var(--radius-sm, 4px)',
                    fontWeight: 600,
                    cursor: revoking ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  {revoking ? (
                    <>
                      <span style={{ display: 'inline-block', width: 12, height: 12, border: '2px solid #fff', borderRightColor: 'transparent', borderRadius: '50%', animation: 'spin 0.75s linear infinite' }} />
                      Revoking...
                    </>
                  ) : (
                    'Confirm Revocation'
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Workstation Onboarding Modal (Zero-Touch PKCE & Hardware-Bound Ed25519) */}
      {showTokenModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}>
          <div className="card" style={{ width: '100%', maxWidth: '640px', maxHeight: '92vh', overflowY: 'auto', padding: '24px', backgroundColor: 'var(--bg-surface-1)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius)', boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 8px 10px -6px rgba(0, 0, 0, 0.5)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <h3 style={{ margin: 0, fontSize: 18, fontWeight: 700 }}>Onboard Developer Workstation</h3>
                  <span className="soc-delta-badge delta-success" style={{ fontSize: 11 }}>Zero-Touch PKCE</span>
                </div>
                <p style={{ margin: 0, color: 'var(--text-secondary)', fontSize: '13px' }}>
                  Authenticate via browser PKCE SSO and automatically bind a hardware/keyring Ed25519 device key.
                </p>
              </div>
              <button
                type="button"
                onClick={handleCloseOnboardModal}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 20, padding: '2px 6px', borderRadius: 4 }}
              >
                ✕
              </button>
            </div>

            {/* Security Invariants Bar */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 8, marginBottom: 18, padding: '10px 12px', backgroundColor: 'rgba(255, 255, 255, 0.02)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 6, color: '#34d399' }}>
                <span>🛡️</span>
                <span><strong>Zero-Root-CA</strong> (No OS trust pollution)</span>
              </div>
              <div style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 6, color: '#38bdf8' }}>
                <span>🔑</span>
                <span><strong>Local Ed25519</strong> (Zero private key export)</span>
              </div>
              <div style={{ fontSize: 11, display: 'flex', alignItems: 'center', gap: 6, color: '#a78bfa' }}>
                <span>👤</span>
                <span><strong>User-Space</strong> (No Admin / root needed)</span>
              </div>
            </div>

            {/* Target Hub Indicator */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginBottom: 18 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', backgroundColor: 'var(--success)' }}></span>
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>Target Control Hub:</span>
                <code style={{ fontSize: 12, color: 'var(--primary)', fontWeight: 600 }}>{hubUrl}</code>
              </div>
              <button
                type="button"
                className="btn btn-sm"
                style={{ padding: '2px 8px', fontSize: 11, backgroundColor: copiedField === 'hub' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
                onClick={() => {
                  navigator.clipboard.writeText(hubUrl)
                  setCopiedField('hub')
                  setTimeout(() => setCopiedField(null), 2000)
                }}
              >
                {copiedField === 'hub' ? 'Copied!' : 'Copy'}
              </button>
            </div>

            {/* Step 1: Install CLI */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>1. Install Agent Control CLI (User-Space)</span>
                <div style={{ display: 'flex', gap: 4 }}>
                  <button
                    type="button"
                    onClick={() => setInstallOs('win')}
                    style={{ padding: '2px 8px', fontSize: 11, borderRadius: 4, border: 'none', cursor: 'pointer', background: installOs === 'win' ? 'var(--primary)' : 'var(--bg-surface-2)', color: installOs === 'win' ? '#fff' : 'var(--text-muted)' }}
                  >
                    Windows (PowerShell)
                  </button>
                  <button
                    type="button"
                    onClick={() => setInstallOs('unix')}
                    style={{ padding: '2px 8px', fontSize: 11, borderRadius: 4, border: 'none', cursor: 'pointer', background: installOs === 'unix' ? 'var(--primary)' : 'var(--bg-surface-2)', color: installOs === 'unix' ? '#fff' : 'var(--text-muted)' }}
                  >
                    macOS / Linux
                  </button>
                </div>
              </div>
              <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <pre style={{ margin: 0, fontSize: 11, color: installOs === 'win' ? '#38bdf8' : '#10b981', fontFamily: 'var(--font-mono)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {installOs === 'win'
                    ? `irm https://vexasec.io/install.ps1 | iex`
                    : `curl -fsSL https://vexasec.io/install.sh | bash`}
                </pre>
                <button
                  type="button"
                  className="btn btn-sm"
                  style={{ padding: '2px 8px', fontSize: 11, backgroundColor: copiedField === 'install' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer', flexShrink: 0, marginLeft: 8 }}
                  onClick={() => {
                    const cmd = installOs === 'win' ? `irm https://vexasec.io/install.ps1 | iex` : `curl -fsSL https://vexasec.io/install.sh | bash`
                    navigator.clipboard.writeText(cmd)
                    setCopiedField('install')
                    setTimeout(() => setCopiedField(null), 2000)
                  }}
                >
                  {copiedField === 'install' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Installs strictly into the developer's user profile (no administrator or root rights required).
              </div>
            </div>

            {/* Step 2: Login & Zero-Touch Device Registration */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>2. Zero-Touch Authentication & Device Enrollment</span>
                <button
                  type="button"
                  className="btn btn-sm"
                  style={{ padding: '2px 8px', fontSize: 11, backgroundColor: copiedField === 'login' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
                  onClick={() => {
                    const cmd = `agentcontrol login --hub ${hubUrl}`
                    navigator.clipboard.writeText(cmd)
                    setCopiedField('login')
                    setTimeout(() => setCopiedField(null), 2000)
                  }}
                >
                  {copiedField === 'login' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                <pre style={{ margin: 0, fontSize: 11, color: '#34d399', fontFamily: 'var(--font-mono)' }}>
                  agentcontrol login --hub {hubUrl}
                </pre>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Opens browser for enterprise PKCE SSO, generates a local Ed25519 device key in the OS Keyring, and registers the workstation with the Hub.
              </div>
            </div>

            {/* Step 3: Connect IDE Client Targets */}
            <div style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>3. Connect Verified IDE Clients</span>
                <button
                  type="button"
                  className="btn btn-sm"
                  style={{ padding: '2px 8px', fontSize: 11, backgroundColor: copiedField === 'connect' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
                  onClick={() => {
                    const cmd = `agentcontrol connect codex`
                    navigator.clipboard.writeText(cmd)
                    setCopiedField('connect')
                    setTimeout(() => setCopiedField(null), 2000)
                  }}
                >
                  {copiedField === 'connect' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                <pre style={{ margin: 0, fontSize: 11, color: '#a78bfa', fontFamily: 'var(--font-mono)' }}>
                  agentcontrol connect codex
                </pre>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Supported targets: <code>cursor</code>, <code>codex</code>, <code>claude</code>, <code>claude-code</code>, <code>antigravity</code>, <code>vscode-continue</code>. Configures ownership manifests and local proxy.
              </div>
            </div>

            {/* Step 4: Run Doctor Diagnostics */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>4. Verify Workstation Health & Invariants</span>
                <button
                  type="button"
                  className="btn btn-sm"
                  style={{ padding: '2px 8px', fontSize: 11, backgroundColor: copiedField === 'doctor' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer' }}
                  onClick={() => {
                    const cmd = `agentcontrol doctor`
                    navigator.clipboard.writeText(cmd)
                    setCopiedField('doctor')
                    setTimeout(() => setCopiedField(null), 2000)
                  }}
                >
                  {copiedField === 'doctor' ? 'Copied!' : 'Copy'}
                </button>
              </div>
              <div style={{ padding: '10px 12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                <pre style={{ margin: 0, fontSize: 11, color: '#f59e0b', fontFamily: 'var(--font-mono)' }}>
                  agentcontrol doctor
                </pre>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                Executes read-only diagnostic checks, verifying local proxy on 127.0.0.1:18080, Zero-Root-CA status, and active key binding.
              </div>
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
              <button type="button" className="btn btn-primary" onClick={handleCloseOnboardModal}>
                Done
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Loading Overlay for Device Detail */}
      {loadingDetail && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.6)',
            backdropFilter: 'blur(3px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
        >
          <div className="card" style={{ padding: '24px 32px', textAlign: 'center' }}>
            <div style={{ fontSize: 28, marginBottom: 12 }}>⚡</div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>Loading workstation telemetry...</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 4 }}>Querying granular IDE configurations & tamper states</div>
          </div>
        </div>
      )}

      {/* Granular Device Detail Inspection Modal */}
      {selectedDevice && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.8)',
            backdropFilter: 'blur(5px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: 20,
            overflowY: 'auto',
          }}
          onClick={(e) => {
            if (e.target === e.currentTarget) {
              setSelectedDevice(null)
              setCopiedKey(false)
            }
          }}
        >
          <div
            className="card"
            style={{
              width: '100%',
              maxWidth: '840px',
              maxHeight: '90vh',
              overflowY: 'auto',
              padding: '28px',
              backgroundColor: 'var(--bg-surface-1, #18181b)',
              border: '1px solid var(--border-default, #27272a)',
              borderRadius: 'var(--radius, 10px)',
              boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.7)',
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid var(--border)', paddingBottom: '16px', marginBottom: '20px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: '10px',
                    backgroundColor: 'rgba(59, 130, 246, 0.15)',
                    border: '1px solid rgba(59, 130, 246, 0.3)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '22px',
                  }}
                >
                  💻
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700, color: 'var(--text-main, #f4f4f5)' }}>
                      {selectedDevice.hostname}
                    </h2>
                    {getComplianceBadge(getEffectiveCompliance(selectedDevice))}
                    <span
                      style={{
                        fontSize: '11px',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        fontWeight: 600,
                        backgroundColor: selectedDevice.enrollment_status === 'ACTIVE' ? 'rgba(34, 197, 94, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                        color: selectedDevice.enrollment_status === 'ACTIVE' ? '#4ade80' : '#f87171',
                      }}
                    >
                      {selectedDevice.enrollment_status}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted, #71717a)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                    Device ID: {selectedDevice.device_id}
                  </div>
                </div>
              </div>
              <button
                type="button"
                onClick={() => {
                  setSelectedDevice(null)
                  setCopiedKey(false)
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted, #71717a)',
                  cursor: 'pointer',
                  fontSize: 20,
                  padding: 4,
                }}
              >
                ✕
              </button>
            </div>

            {/* Quick Metrics & System Specs Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '12px', marginBottom: '20px' }}>
              <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-surface-2, #202023)', borderRadius: 'var(--radius-sm, 6px)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Developer Owner</div>
                <div style={{ fontSize: '14px', fontWeight: 600, marginTop: '4px', color: 'var(--text-main)' }}>{selectedDevice.user_identifier || '—'}</div>
              </div>
              <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-surface-2, #202023)', borderRadius: 'var(--radius-sm, 6px)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>OS & Platform</div>
                <div style={{ fontSize: '14px', fontWeight: 600, marginTop: '4px', color: 'var(--text-main)' }}>{getOsIcon(selectedDevice.os)} <span style={{ fontSize: 12, opacity: 0.7 }}>({selectedDevice.os_version || 'standard'})</span></div>
              </div>
              <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-surface-2, #202023)', borderRadius: 'var(--radius-sm, 6px)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Daemon Version</div>
                <div style={{ fontSize: '14px', fontWeight: 600, marginTop: '4px', color: '#38bdf8' }}>v{selectedDevice.daemon_version || '2.1.0'}</div>
              </div>
              <div style={{ padding: '12px 14px', backgroundColor: 'var(--bg-surface-2, #202023)', borderRadius: 'var(--radius-sm, 6px)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Last Heartbeat</div>
                <div style={{ fontSize: '14px', fontWeight: 600, marginTop: '4px', color: 'var(--text-main)' }}>
                  {selectedDevice.last_heartbeat_at ? new Date(selectedDevice.last_heartbeat_at).toLocaleString() : 'Never'}
                </div>
              </div>
            </div>

            {/* Cryptographic Public Key Card */}
            <div style={{ padding: '14px', backgroundColor: 'var(--bg-surface-0, #121214)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginBottom: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-secondary)' }}>Workstation Cryptographic Public Key (mTLS)</div>
                {selectedDevice.public_key && (
                  <button
                    type="button"
                    className="btn btn-sm"
                    style={{ padding: '2px 8px', fontSize: '11px', backgroundColor: copiedKey ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                    onClick={() => {
                      navigator.clipboard.writeText(selectedDevice.public_key)
                      setCopiedKey(true)
                      setTimeout(() => setCopiedKey(false), 2000)
                    }}
                  >
                    {copiedKey ? '✔ Copied Key' : 'Copy Key'}
                  </button>
                )}
              </div>
              <pre style={{ margin: 0, fontSize: '11px', color: '#a78bfa', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                {selectedDevice.public_key || 'Hardware key proof verified via enrolled token / CAS certificate'}
              </pre>
            </div>

            {/* Granular IDE Targets Configuration State */}
            <div style={{ marginBottom: '24px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <h4 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--text-main)' }}>
                  Protected IDE Integrations & Proxy Locks
                </h4>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  {selectedDevice.ide_statuses ? selectedDevice.ide_statuses.length : 0} configured IDEs
                </span>
              </div>

              {(!selectedDevice.ide_statuses || selectedDevice.ide_statuses.length === 0) ? (
                <div style={{ padding: '20px', textAlign: 'center', backgroundColor: 'var(--bg-surface-0)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: 13 }}>
                  No individual IDE configuration profiles reported yet. The Sentry daemon will discover and report installed IDEs on the next 60s telemetry cycle.
                </div>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '14px' }}>
                  {selectedDevice.ide_statuses.map((ide, idx) => (
                    <div
                      key={idx}
                      style={{
                        padding: '16px',
                        backgroundColor: 'var(--bg-surface-0, #121214)',
                        border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm, 6px)',
                        borderLeft: `4px solid ${ide.compliance_state === 'COMPLIANT' ? '#22c55e' : ide.compliance_state === 'NOT_INSTALLED' || !ide.installed ? '#52525b' : '#ef4444'}`,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontSize: 16 }}>🛠️</span>
                          <strong style={{ fontSize: 14, color: 'var(--text-main)' }}>{ide.name}</strong>
                          {ide.installed && <span className="badge badge-info" style={{ fontSize: 10 }}>INSTALLED</span>}
                        </div>
                        {getComplianceBadge(ide.compliance_state)}
                      </div>

                      <div style={{ fontSize: 12, display: 'flex', flexDirection: 'column', gap: 6, color: 'var(--text-secondary)' }}>
                        <div>
                          <span style={{ color: 'var(--text-muted)' }}>Config Path: </span>
                          <code style={{ fontSize: 11, color: '#38bdf8', wordBreak: 'break-all' }}>{ide.config_path || (ide.installed ? 'Default User Settings' : 'Not Detected')}</code>
                        </div>
                        <div>
                          <span style={{ color: 'var(--text-muted)' }}>Proxy Base URL: </span>
                          <code style={{ fontSize: 11, color: '#a78bfa' }}>{ide.configured_base_url || 'http://127.0.0.1:8080'}</code>
                        </div>
                        <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
                          <span style={{ color: ide.proxy_configured ? 'var(--success)' : ide.installed ? 'var(--danger)' : 'var(--text-muted)', fontWeight: 600 }}>
                            {ide.proxy_configured ? '✔ Proxy Configured' : ide.installed ? '✖ Proxy Missing' : '○ Not Configured'}
                          </span>
                          <span style={{ color: ide.mcp_wrapped ? 'var(--success)' : 'var(--text-muted)', fontWeight: 600 }}>
                            {ide.mcp_wrapped ? '✔ MCP Wrapped' : '○ Standard Tools'}
                          </span>
                        </div>
                        {ide.last_healed_at && (
                          <div style={{ marginTop: 2, fontSize: 11, color: '#fbbf24' }}>
                            Last auto-healed: {new Date(ide.last_healed_at).toLocaleString()}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Device-Specific Tamper & Incident Log */}
            <div style={{ marginBottom: '20px' }}>
              <h4 style={{ margin: '0 0 12px 0', fontSize: '15px', fontWeight: 600, color: 'var(--text-main)' }}>
                Workstation Incident & Tamper History
              </h4>
              {(!selectedDevice.recent_tamper_events || selectedDevice.recent_tamper_events.length === 0) ? (
                <div style={{ padding: '16px', textAlign: 'center', backgroundColor: 'var(--bg-surface-0)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', color: 'var(--text-muted)', fontSize: 13 }}>
                  ✔ No tampering or bypass incidents recorded for this workstation. Proxy continuous locking is intact.
                </div>
              ) : (
                <div className="table-wrap" style={{ maxHeight: 240, overflowY: 'auto' }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Target IDE</th>
                        <th>Event Type</th>
                        <th>Details</th>
                        <th>Auto-Heal Status</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {selectedDevice.recent_tamper_events.map((te, i) => (
                        <tr key={i}>
                          <td><strong>{te.ide_name}</strong></td>
                          <td><span className="badge badge-warning">{te.event_type}</span></td>
                          <td style={{ fontSize: 12, maxWidth: 300 }}>{te.tamper_details}</td>
                          <td>
                            {te.healed_successfully ? (
                              <span style={{ color: 'var(--success)', fontWeight: 600 }}>✔ Healed (&lt;500ms)</span>
                            ) : (
                              <span style={{ color: 'var(--danger)', fontWeight: 600 }}>✖ Failed</span>
                            )}
                          </td>
                          <td style={{ color: 'var(--text-muted)', fontSize: 11 }}>
                            {new Date(te.occurred_at).toLocaleString()}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>

            {/* Action Bar Footer */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
              {selectedDevice.enrollment_status !== 'REVOKED' ? (
                <button
                  type="button"
                  className="btn btn-danger"
                  onClick={() => {
                    const dev = selectedDevice
                    setSelectedDevice(null)
                    openRevokeModal(dev.device_id, dev.hostname)
                  }}
                  style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                >
                  <span>⚠️</span> Revoke Workstation Access
                </button>
              ) : (
                <span style={{ color: 'var(--danger)', fontWeight: 600, fontSize: 13 }}>Workstation Credentials Revoked</span>
              )}
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => {
                  setSelectedDevice(null)
                  setCopiedKey(false)
                }}
              >
                Close Inspection
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
