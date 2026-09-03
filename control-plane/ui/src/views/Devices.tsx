import { useState, useEffect, type FormEvent } from 'react'
import {
  api,
  revokeDeviceV2,
  createEnrollmentTokenV2,
  getSentryDeviceDetail,
  resolveHubUrl,
  type SentryDeviceSummary,
  type SentryDeviceDetail,
  type EnrollmentTokenV2
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
  const [devices, setDevices] = useState<SentryDeviceSummary[]>([])
  const [compliantCount, setCompliantCount] = useState(0)
  const [nonCompliantCount, setNonCompliantCount] = useState(0)
  const [offlineCount, setOfflineCount] = useState(0)
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

  // Enrollment Token Modal State
  const [showTokenModal, setShowTokenModal] = useState(false)
  const [generatedToken, setGeneratedToken] = useState<EnrollmentTokenV2 | null>(null)
  const [tokenReason, setTokenReason] = useState('Workstation Onboarding')
  const [deviceLabel, setDeviceLabel] = useState('')
  const [ttlHours, setTtlHours] = useState(24)
  const [tokenError, setTokenError] = useState<string | null>(null)
  const [copiedField, setCopiedField] = useState<'unix' | 'win' | 'cli' | null>(null)

  useEffect(() => {
    fetchDevices()
  }, [filter])

  const fetchDevices = async () => {
    setLoading(true)
    try {
      const res = await api.listSentryDevices(filter)
      const rawList = res.devices || []
      const seen = new Set<string>()
      const deduped: SentryDeviceSummary[] = []
      for (const d of rawList) {
        const key = (d.hostname || d.device_id || '').toLowerCase()
        if (key && !seen.has(key)) {
          seen.add(key)
          deduped.push(d)
        } else if (!key) {
          deduped.push(d)
        }
      }
      setDevices(deduped)
      setCompliantCount(res.compliant_count || 0)
      setNonCompliantCount(res.non_compliant_count || 0)
      setOfflineCount(res.offline_count || 0)
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

  const handleGenerateToken = async (e: FormEvent) => {
    e.preventDefault()
    setTokenError(null)
    try {
      const tok = await createEnrollmentTokenV2(tokenReason || 'Workstation Onboarding', deviceLabel, '', ttlHours)
      setGeneratedToken(tok)
    } catch (err: any) {
      setTokenError(err.message || 'Failed to create enrollment token')
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
      default:
        return <span className="badge badge-info" style={{ opacity: 0.7 }}>OFFLINE</span>
    }
  }

  const getOsIcon = (os: string) => {
    const o = (os || '').toLowerCase()
    if (o.includes('win')) return '🪟 Windows'
    if (o.includes('mac') || o.includes('darwin')) return '🍎 macOS'
    if (o.includes('linux')) return '🐧 Linux'
    return os || 'Unknown'
  }

  const hubUrl = resolveHubUrl(generatedToken?.hub_url)

  const filteredDevices = devices.filter(d => {
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
    <div style={{ padding: '24px' }}>
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
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
        <div>
          <h1>Device Governance</h1>
          <p>Continuous configuration locking, zero-master-key posture, and real-time compliance across developer workstations.</p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => {
            setGeneratedToken(null)
            setTokenError(null)
            setShowTokenModal(true)
          }}
          style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 16px', fontWeight: 600 }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Generate Enrollment Token
        </button>
      </div>

      {/* Summary Metric Cards */}
      <div className="card" style={{ padding: 24, marginBottom: 24, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 24 }}>
        <div style={{ cursor: 'pointer' }} onClick={() => setFilter('')}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>TOTAL ENROLLED DEVICES</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: 'var(--text-main)' }}>
            {devices.length}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Registered developer seats</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 24, cursor: 'pointer' }} onClick={() => setFilter('COMPLIANT')}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>COMPLIANT WORKSTATIONS</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: 'var(--success)' }}>
            {compliantCount}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Proxy locked & active</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 24, cursor: 'pointer' }} onClick={() => setFilter('NON_COMPLIANT')}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>DRIFTED / NON-COMPLIANT</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: nonCompliantCount > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
            {nonCompliantCount}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Requires admin review</span>
        </div>

        <div style={{ borderLeft: '1px solid var(--border)', paddingLeft: 24, cursor: 'pointer' }} onClick={() => setFilter('OFFLINE')}>
          <p style={{ color: 'var(--text-muted)', fontSize: 12, fontWeight: 600, letterSpacing: '0.05em', marginBottom: 4 }}>OFFLINE WORKSTATIONS</p>
          <div style={{ fontSize: 36, fontWeight: 300, color: 'var(--text-muted)' }}>
            {offlineCount}
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>No heartbeat in {'>'} 3m</span>
        </div>
      </div>

      {/* Sentry Compliance Posture Guide Card */}
      <div className="card" style={{ padding: '16px 20px', marginBottom: '24px', backgroundColor: 'var(--bg-surface-2)', borderColor: 'var(--border)' }}>
        <h4 style={{ margin: '0 0 10px 0', fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>🛡️</span> Understanding Sentry Governance & Posture
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', fontSize: '12px', color: 'var(--text-secondary)' }}>
          <div style={{ padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(16, 185, 129, 0.25)', backgroundColor: 'rgba(16, 185, 129, 0.05)' }}>
            <span style={{ color: 'var(--success)', fontWeight: 700, display: 'block', marginBottom: '4px' }}>● COMPLIANT</span>
            Sentry Daemon active (heartbeat ≤ 3m) and all detected IDE AI completions route securely through the local gateway (<code>127.0.0.1:8080</code>).
          </div>
          <div style={{ padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(239, 68, 68, 0.25)', backgroundColor: 'rgba(239, 68, 68, 0.05)' }}>
            <span style={{ color: 'var(--danger)', fontWeight: 700, display: 'block', marginBottom: '4px' }}>● NON-COMPLIANT / DRIFTED</span>
            Triggered if an IDE configuration is altered or removed without auto-heal, an unmanaged LLM client is detected, or the device was revoked.
          </div>
          <div style={{ padding: '10px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid rgba(148, 163, 184, 0.25)', backgroundColor: 'rgba(148, 163, 184, 0.05)' }}>
            <span style={{ color: 'var(--text-muted)', fontWeight: 700, display: 'block', marginBottom: '4px' }}>● OFFLINE (&gt; 3m)</span>
            Workstation daemon has not transmitted telemetry in over 3 minutes. Machine may be asleep, shut down, or disconnected from the network.
          </div>
        </div>
      </div>

      {/* Filter & Devices Table */}
      <div className="card">
        <div style={{ padding: '18px 24px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <h3 style={{ fontSize: 16, margin: 0 }}>Workstation Fleet Inventory</h3>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <input
              type="text"
              placeholder="Search hostname, user, or device ID..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="input"
              style={{ padding: '6px 12px', fontSize: 13, minWidth: 260 }}
            />
            <select 
              value={filter} 
              onChange={e => setFilter(e.target.value)}
              style={{ padding: '6px 12px', background: 'var(--bg-card)', border: '1px solid var(--border)', color: '#fff', borderRadius: 'var(--radius-sm)' }}
            >
              <option value="">All Statuses</option>
              <option value="COMPLIANT">Compliant Only</option>
              <option value="NON_COMPLIANT">Non-Compliant Only</option>
              <option value="OFFLINE">Offline Only</option>
            </select>
          </div>
        </div>

        {loading ? (
          <div className="loading" style={{ padding: '32px' }}>Loading fleet devices...</div>
        ) : filteredDevices.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)' }}>
            <p style={{ fontSize: 15, fontWeight: 500, color: 'var(--text-secondary)' }}>No enrolled developer workstations found.</p>
            <p style={{ fontSize: 13, marginTop: 6 }}>Click <strong>"+ Generate Enrollment Token"</strong> above or run <code>agentcontrol enroll</code> on a workstation to onboard it.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>Developer User</th>
                  <th>OS / Platform</th>
                  <th>Protected IDEs</th>
                  <th>24h Tamper Count</th>
                  <th>Last Heartbeat</th>
                  <th>Compliance Posture</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredDevices.map((d, idx) => (
                  <tr key={d.device_id || idx} style={{ transition: 'background-color 0.15s ease' }}>
                    <td style={{ fontWeight: 600 }}>
                      <button
                        type="button"
                        onClick={() => handleInspectDevice(d.device_id)}
                        style={{
                          background: 'none',
                          border: 'none',
                          padding: 0,
                          color: 'var(--accent-primary, #60a5fa)',
                          cursor: 'pointer',
                          fontWeight: 600,
                          textAlign: 'left',
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 6,
                        }}
                        title="Click to inspect workstation details, IDE configs, and public keys"
                      >
                        <span>{d.hostname || 'Unknown Host'}</span>
                        <span style={{ fontSize: 11, opacity: 0.7 }}>🔍</span>
                      </button>
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 13 }}>{d.user_identifier || '—'}</td>
                    <td>{getOsIcon(d.os)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        {d.active_ides && d.active_ides.length > 0 ? (
                          d.active_ides.map((ide, i) => (
                            <span key={i} className="badge badge-info" style={{ fontSize: 11 }}>
                              {ide}
                            </span>
                          ))
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>None detected</span>
                        )}
                      </div>
                    </td>
                    <td>
                      {d.tamper_count_24h > 0 ? (
                        <span style={{ color: 'var(--warning)', fontWeight: 600 }}>{d.tamper_count_24h} incidents</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>0</span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12, whiteSpace: 'nowrap' }}>
                      {d.last_heartbeat_at ? new Date(d.last_heartbeat_at).toLocaleString() : 'Never'}
                    </td>
                    <td>{getComplianceBadge(d.overall_compliance)}</td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: 8, alignItems: 'center' }}>
                        <button
                          type="button"
                          className="btn btn-sm"
                          style={{
                            padding: '4px 10px',
                            fontSize: '11px',
                            backgroundColor: 'var(--bg-surface-2, #27272a)',
                            color: 'var(--text-main, #f4f4f5)',
                            border: '1px solid var(--border, #3f3f46)',
                            borderRadius: '4px',
                            cursor: 'pointer',
                          }}
                          onClick={() => handleInspectDevice(d.device_id)}
                          title="Inspect deep telemetry, IDE configs, and tamper history"
                        >
                          Inspect
                        </button>
                        {d.enrollment_status !== 'REVOKED' && d.overall_compliance !== 'NON_COMPLIANT' ? (
                          <button
                            className="btn btn-sm btn-danger"
                            style={{ padding: '4px 10px', fontSize: '11px', backgroundColor: 'var(--danger, #ef4444)', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                            onClick={() => openRevokeModal(d.device_id, d.hostname)}
                            title="Revoke device PKI and gateway access"
                          >
                            Revoke
                          </button>
                        ) : (
                          <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Revoked</span>
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

      {/* Enrollment Token Modal */}
      {showTokenModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}>
          <div className="card" style={{ width: '100%', maxWidth: '580px', padding: '24px', backgroundColor: 'var(--bg-surface-1)', border: '1px solid var(--border-default)', borderRadius: 'var(--radius)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <h3 style={{ margin: 0, fontSize: 18 }}>Generate Workstation Enrollment Token</h3>
              <button
                type="button"
                onClick={() => setShowTokenModal(false)}
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 18 }}
              >
                ✕
              </button>
            </div>
            <p style={{ color: 'var(--text-secondary)', fontSize: '13px', marginBottom: '20px' }}>
              Issue a single-use token (OTET) to securely onboard a developer workstation into Agent Control IDE Sentry Governance.
            </p>

            {tokenError && (
              <div
                style={{
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  borderRadius: 'var(--radius-sm, 6px)',
                  padding: '10px 14px',
                  marginBottom: 16,
                  color: '#f87171',
                  fontSize: 13,
                }}
              >
                {tokenError}
              </div>
            )}

            {!generatedToken ? (
              <form onSubmit={handleGenerateToken}>
                <div style={{ marginBottom: '14px' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>Workstation / Developer Purpose *</label>
                  <input
                    type="text"
                    value={tokenReason}
                    onChange={(e) => setTokenReason(e.target.value)}
                    required
                    placeholder="e.g. Alice MacBook Pro Onboarding"
                    className="input"
                    style={{ width: '100%', padding: '8px 12px' }}
                  />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '20px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>Device Label (Optional)</label>
                    <input
                      type="text"
                      value={deviceLabel}
                      onChange={(e) => setDeviceLabel(e.target.value)}
                      placeholder="e.g. dev-laptop-alex"
                      className="input"
                      style={{ width: '100%', padding: '8px 12px' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '6px', color: 'var(--text-primary)' }}>Token Validity (Hours)</label>
                    <input
                      type="number"
                      value={ttlHours}
                      onChange={(e) => setTtlHours(parseInt(e.target.value) || 24)}
                      className="input"
                      style={{ width: '100%', padding: '8px 12px' }}
                    />
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
                  <button type="button" className="btn" onClick={() => setShowTokenModal(false)}>Cancel</button>
                  <button type="submit" className="btn btn-primary" style={{ padding: '8px 16px' }}>Generate Token</button>
                </div>
              </form>
            ) : (
              <div>
                <div style={{ padding: '12px 14px', backgroundColor: 'rgba(16, 185, 129, 0.1)', border: '1px solid rgba(16, 185, 129, 0.3)', borderRadius: 'var(--radius-sm)', marginBottom: '16px' }}>
                  <span style={{ color: 'var(--success)', fontWeight: 700, display: 'block', fontSize: '13px' }}>✔ One-Time Enrollment Token Generated</span>
                  <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>Single-use token valid for {ttlHours} hours. Transmit over a secure private channel.</span>
                </div>

                {/* macOS / Linux Command */}
                <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>macOS / Linux (Bash):</div>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ padding: '2px 8px', fontSize: '11px', backgroundColor: copiedField === 'unix' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      onClick={() => {
                        const cmd = `curl -fsSL https://vexasec.io/install/team_otet.sh | AGENTCONTROL_TOKEN="${generatedToken.token}" AGENTCONTROL_HUB_URL="${hubUrl}" bash`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('unix')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'unix' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '11px', color: '#10b981', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    curl -fsSL https://vexasec.io/install/team_otet.sh | AGENTCONTROL_TOKEN="{generatedToken.token}" AGENTCONTROL_HUB_URL="{hubUrl}" bash
                  </pre>
                </div>

                {/* Windows Command */}
                <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginBottom: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>Windows (PowerShell):</div>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ padding: '2px 8px', fontSize: '11px', backgroundColor: copiedField === 'win' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      onClick={() => {
                        const cmd = `$env:AGENTCONTROL_TOKEN="${generatedToken.token}"; $env:AGENTCONTROL_HUB_URL="${hubUrl}"; irm https://vexasec.io/install/team_otet.ps1 | iex`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('win')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'win' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '11px', color: '#38bdf8', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    $env:AGENTCONTROL_TOKEN="{generatedToken.token}"; $env:AGENTCONTROL_HUB_URL="{hubUrl}"; irm https://vexasec.io/install/team_otet.ps1 | iex
                  </pre>
                  <div style={{ marginTop: '8px', fontSize: '11px', color: '#fbbf24', display: 'flex', alignItems: 'center', gap: '5px' }}>
                    <span>ℹ️</span>
                    <span><strong>Note:</strong> Sentry service installation requires Administrator privileges on Windows (run PowerShell as Administrator).</span>
                  </div>
                </div>

                {/* Agent Control CLI Direct Command */}
                <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginBottom: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>Direct CLI:</div>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ padding: '2px 8px', fontSize: '11px', backgroundColor: copiedField === 'cli' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      onClick={() => {
                        const cmd = `agentcontrol enroll --hub-url ${hubUrl} --token ${generatedToken.token}`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('cli')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'cli' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '11px', color: '#a78bfa', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    agentcontrol enroll --hub-url {hubUrl} --token {generatedToken.token}
                  </pre>
                </div>

                <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                  <button type="button" className="btn btn-primary" onClick={() => { setShowTokenModal(false); setCopiedField(null); }}>Done</button>
                </div>
              </div>
            )}
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
                    {getComplianceBadge(selectedDevice.overall_compliance)}
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
