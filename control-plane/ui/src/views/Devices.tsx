import { useState, useEffect, type FormEvent } from 'react'
import {
  api,
  revokeDeviceV2,
  createEnrollmentTokenV2,
  type SentryDeviceSummary,
  type EnrollmentTokenV2
} from '../api/client'

export default function Devices() {
  const [devices, setDevices] = useState<SentryDeviceSummary[]>([])
  const [compliantCount, setCompliantCount] = useState(0)
  const [nonCompliantCount, setNonCompliantCount] = useState(0)
  const [offlineCount, setOfflineCount] = useState(0)
  const [filter, setFilter] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [loading, setLoading] = useState(true)

  // Enrollment Token Modal State
  const [showTokenModal, setShowTokenModal] = useState(false)
  const [generatedToken, setGeneratedToken] = useState<EnrollmentTokenV2 | null>(null)
  const [tokenReason, setTokenReason] = useState('Workstation Onboarding')
  const [deviceLabel, setDeviceLabel] = useState('')
  const [ttlHours, setTtlHours] = useState(24)
  const [copiedField, setCopiedField] = useState<'unix' | 'win' | 'cli' | null>(null)

  useEffect(() => {
    fetchDevices()
  }, [filter])

  const fetchDevices = async () => {
    setLoading(true)
    try {
      const res = await api.listSentryDevices(filter)
      setDevices(res.devices || [])
      setCompliantCount(res.compliant_count || 0)
      setNonCompliantCount(res.non_compliant_count || 0)
      setOfflineCount(res.offline_count || 0)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleRevoke = async (deviceId: string, hostname: string) => {
    const reason = prompt(`Enter a revocation reason for device "${hostname}" (${deviceId}):`, 'Decommissioned / Offboarded')
    if (reason && reason.trim()) {
      try {
        await revokeDeviceV2(deviceId, reason.trim())
        await fetchDevices()
      } catch (e: any) {
        alert(`Failed to revoke device: ${e.message}`)
      }
    }
  }

  const handleGenerateToken = async (e: FormEvent) => {
    e.preventDefault()
    try {
      const tok = await createEnrollmentTokenV2(tokenReason || 'Workstation Onboarding', deviceLabel, '', ttlHours)
      setGeneratedToken(tok)
    } catch (err: any) {
      alert(`Failed to create enrollment token: ${err.message}`)
    }
  }

  const getComplianceBadge = (status: string) => {
    switch (status) {
      case 'COMPLIANT':
        return <span className="badge badge-success">COMPLIANT</span>
      case 'NON_COMPLIANT':
        return <span className="badge badge-danger">NON-COMPLIANT</span>
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

  const hubUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8400'

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
            <p style={{ fontSize: 13, marginTop: 6 }}>Click <strong>"+ Generate Enrollment Token"</strong> above or run <code>agentwall enroll</code> on a workstation to onboard it.</p>
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
                  <tr key={d.device_id || idx}>
                    <td style={{ fontWeight: 600 }}>{d.hostname || 'Unknown Host'}</td>
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
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                      {d.last_heartbeat_at ? new Date(d.last_heartbeat_at).toLocaleTimeString() : 'Never'}
                    </td>
                    <td>{getComplianceBadge(d.overall_compliance)}</td>
                    <td style={{ textAlign: 'right' }}>
                      {d.enrollment_status !== 'REVOKED' && d.overall_compliance !== 'NON_COMPLIANT' ? (
                        <button
                          className="btn btn-sm btn-danger"
                          style={{ padding: '4px 10px', fontSize: '11px', backgroundColor: 'var(--danger)', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                          onClick={() => handleRevoke(d.device_id, d.hostname)}
                          title="Revoke device PKI and gateway access"
                        >
                          Revoke
                        </button>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>Revoked</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Enrollment Token Modal */}
      {showTokenModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000, padding: 16 }}>
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
                      placeholder="e.g. dev-laptop-wasim"
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
                        const cmd = `curl -fsSL https://vexasec.io/install/team_otet.sh | AGENTWALL_TOKEN="${generatedToken.token}" AGENTWALL_HUB_URL="${hubUrl}" bash`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('unix')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'unix' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '11px', color: '#10b981', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    curl -fsSL https://vexasec.io/install/team_otet.sh | AGENTWALL_TOKEN="{generatedToken.token}" AGENTWALL_HUB_URL="{hubUrl}" bash
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
                        const cmd = `$env:AGENTWALL_TOKEN="${generatedToken.token}"; $env:AGENTWALL_HUB_URL="${hubUrl}"; irm https://vexasec.io/install/team_otet.ps1 | iex`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('win')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'win' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '11px', color: '#38bdf8', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    $env:AGENTWALL_TOKEN="{generatedToken.token}"; $env:AGENTWALL_HUB_URL="{hubUrl}"; irm https://vexasec.io/install/team_otet.ps1 | iex
                  </pre>
                </div>

                {/* AgentWall CLI Direct Command */}
                <div style={{ padding: '12px', backgroundColor: 'var(--bg-surface-0)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', marginBottom: '16px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>Direct CLI:</div>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ padding: '2px 8px', fontSize: '11px', backgroundColor: copiedField === 'cli' ? 'var(--success)' : 'var(--bg-surface-3)', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      onClick={() => {
                        const cmd = `agentwall enroll --hub ${hubUrl} --token ${generatedToken.token}`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('cli')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'cli' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '11px', color: '#a78bfa', whiteSpace: 'pre-wrap', wordBreak: 'break-all', fontFamily: 'var(--font-mono)' }}>
                    agentwall enroll --hub {hubUrl} --token {generatedToken.token}
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
    </div>
  )
}
