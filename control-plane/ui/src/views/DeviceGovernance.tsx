import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  listDevices, revokeDevice, createEnrollmentToken,
  type Device, type EnrollmentToken
} from '../api/client'

function timeAgo(iso: string): string {
  if (!iso) return 'never'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

export default function DeviceGovernance() {
  const [searchParams] = useSearchParams()
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [osFilter, setOsFilter] = useState(searchParams.get('os') || '')
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || '')
  const [showTokenModal, setShowTokenModal] = useState(false)
  const [generatedToken, setGeneratedToken] = useState<EnrollmentToken | null>(null)
  const [rawTokenValue, setRawTokenValue] = useState('')
  const [maxUses, setMaxUses] = useState(10)
  const [ttlHours, setTtlHours] = useState(24)
  const [copiedField, setCopiedField] = useState<'unix' | 'win' | null>(null)

  const [allDevices, setAllDevices] = useState<Device[]>([])

  useEffect(() => {
    setStatusFilter(searchParams.get('status') || '')
    setOsFilter(searchParams.get('os') || '')
  }, [searchParams])

  const fetchDevices = () => {
    setLoading(true)
    // Fetch overall device fleet for accurate stat tiles
    listDevices('', '')
      .then((res) => {
        setAllDevices(res.devices || [])
      })
      .catch(() => {})

    // Fetch filtered devices for table display
    listDevices(osFilter, statusFilter)
      .then((res) => {
        setDevices(res.devices || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  useEffect(() => {
    fetchDevices()
  }, [osFilter, statusFilter])

  const handleRevoke = async (deviceId: string) => {
    if (confirm(`Are you sure you want to revoke device ${deviceId}? All future pings and API access will be blocked.`)) {
      try {
        await revokeDevice(deviceId)
        fetchDevices()
      } catch (e: any) {
        alert(`Failed to revoke device: ${e.message}`)
      }
    }
  }

function generateSecureToken(): string {
  const bytes = new Uint8Array(16)
  window.crypto.getRandomValues(bytes)
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('').toUpperCase()
  return `TOK-${hex}`
}

  const handleGenerateToken = async (e: React.FormEvent) => {
    e.preventDefault()
    const tokenVal = rawTokenValue || generateSecureToken()
    try {
      const tok = await createEnrollmentToken(tokenVal, maxUses, ttlHours)
      setGeneratedToken({ ...tok, token_hash: tokenVal })
    } catch (err: any) {
      alert(`Failed to create enrollment token: ${err.message}`)
    }
  }

  const totalDevices = allDevices.length
  const compliantCount = allDevices.filter(d => d.compliance_status === 'COMPLIANT').length
  const nonCompliantCount = allDevices.filter(d => d.compliance_status === 'NON_COMPLIANT').length
  const unreachableCount = allDevices.filter(d => d.compliance_status === 'UNREACHABLE').length

  return (
    <div style={{ padding: '24px' }}>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1>Central Device Governance</h1>
          <p>Fleet management, PKI identity binding, and OS Sentry daemon health</p>
        </div>
        <button
          className="btn btn-primary"
          onClick={() => {
            setGeneratedToken(null)
            setRawTokenValue(generateSecureToken())
            setShowTokenModal(true)
          }}
        >
          + Generate Enrollment Token
        </button>
      </div>

      {/* Stats Summary Tiles */}
      <div className="stats-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px', marginBottom: '24px' }}>
        <div className="card stat-tile soc-clickable-tile" onClick={() => setStatusFilter('')} style={{ cursor: 'pointer' }}>
          <div className="stat-value">{totalDevices}</div>
          <div className="stat-label">Total Enrolled Devices</div>
        </div>
        <div className="card stat-tile soc-clickable-tile" onClick={() => setStatusFilter('COMPLIANT')} style={{ cursor: 'pointer' }}>
          <div className="stat-value" style={{ color: '#22c55e' }}>{compliantCount}</div>
          <div className="stat-label">Compliant</div>
        </div>
        <div className="card stat-tile soc-clickable-tile" onClick={() => setStatusFilter('UNREACHABLE')} style={{ cursor: 'pointer' }}>
          <div className="stat-value" style={{ color: '#f59e0b' }}>{unreachableCount}</div>
          <div className="stat-label">Unreachable (3-10m)</div>
        </div>
        <div className="card stat-tile soc-clickable-tile" onClick={() => setStatusFilter('NON_COMPLIANT')} style={{ cursor: 'pointer' }}>
          <div className="stat-value" style={{ color: '#ef4444' }}>{nonCompliantCount}</div>
          <div className="stat-label">Non-Compliant / Revoked</div>
        </div>
      </div>

      {/* Compliance Status Reference Guide */}
      <div className="card" style={{ padding: '16px', marginBottom: '24px', backgroundColor: '#18181b', borderColor: '#27272a' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>
          🛡️ Understanding Device Posture & Compliance Statuses
        </h4>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px', fontSize: '12px', color: '#a1a1aa' }}>
          <div style={{ padding: '10px', borderRadius: '6px', border: '1px solid rgba(34, 197, 94, 0.2)', backgroundColor: 'rgba(34, 197, 94, 0.05)' }}>
            <span style={{ color: '#22c55e', fontWeight: 700, display: 'block', marginBottom: '4px' }}>● COMPLIANT</span>
            Workstation daemon heartbeat active (≤ 3m) AND <strong>100% of detected IDE MCP servers are wrapped</strong> through AgentWall security proxy.
          </div>
          <div style={{ padding: '10px', borderRadius: '6px', border: '1px solid rgba(245, 158, 11, 0.2)', backgroundColor: 'rgba(245, 158, 11, 0.05)' }}>
            <span style={{ color: '#f59e0b', fontWeight: 700, display: 'block', marginBottom: '4px' }}>● UNREACHABLE (3-10m)</span>
            Device daemon has not sent a heartbeat for 3–10 minutes. Device may be offline, asleep, or network connection interrupted.
          </div>
          <div style={{ padding: '10px', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.2)', backgroundColor: 'rgba(239, 68, 68, 0.05)' }}>
            <span style={{ color: '#ef4444', fontWeight: 700, display: 'block', marginBottom: '4px' }}>● NON-COMPLIANT / REVOKED</span>
            Triggered if <strong>any unwrapped MCP tool</strong> exists (wrapped &lt; total), heartbeat &gt; 10m, or device manually revoked by Admin.
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card" style={{ padding: '16px', marginBottom: '24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px' }}>
        <div style={{ display: 'flex', gap: '16px', alignItems: 'center' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>OS Family</label>
            <select value={osFilter} onChange={(e) => setOsFilter(e.target.value)} className="input">
              <option value="">All Operating Systems</option>
              <option value="macos">macOS</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
              <option value="wsl">WSL / WSL2</option>
            </select>
          </div>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>Compliance Status</label>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className="input">
              <option value="">All Statuses (Show All)</option>
              <option value="COMPLIANT">COMPLIANT</option>
              <option value="UNREACHABLE">UNREACHABLE</option>
              <option value="NON_COMPLIANT">NON_COMPLIANT</option>
            </select>
          </div>
        </div>

        {(statusFilter || osFilter) && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', background: 'rgba(59, 130, 246, 0.1)', padding: '8px 14px', borderRadius: '6px', border: '1px solid rgba(59, 130, 246, 0.3)' }}>
            <span style={{ fontSize: '13px', color: '#93c5fd' }}>
              Filtering by: <strong>{statusFilter || 'All Statuses'}</strong> {osFilter ? `(${osFilter})` : ''} — Showing {devices.length} of {allDevices.length} total enrolled devices.
            </span>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ fontSize: '12px', padding: '4px 10px', height: 'auto' }}
              onClick={() => {
                setStatusFilter('')
                setOsFilter('')
              }}
            >
              Clear Filters
            </button>
          </div>
        )}
      </div>

      {/* Devices Table */}
      <div className="card">
        {loading ? (
          <div className="loading" style={{ padding: '24px' }}>Loading fleet devices...</div>
        ) : devices.length === 0 ? (
          <div style={{ padding: '32px', textAlign: 'center', color: '#a1a1aa' }}>
            <p style={{ margin: '0 0 12px 0', fontSize: '14px' }}>
              No enrolled devices found matching filter {statusFilter ? `"${statusFilter}"` : ''} {osFilter ? `(${osFilter})` : ''}.
            </p>
            {statusFilter || osFilter ? (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  setStatusFilter('')
                  setOsFilter('')
                }}
              >
                Clear Filters (Show All {allDevices.length} Devices)
              </button>
            ) : (
              <p style={{ margin: 0, fontSize: '13px', color: '#71717a' }}>
                Generate an Enrollment Token above to onboard machines.
              </p>
            )}
          </div>
        ) : (
          <table className="table" style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ textAlign: 'left', borderBottom: '1px solid #333' }}>
                <th style={{ padding: '12px' }}>Device ID</th>
                <th style={{ padding: '12px' }}>Hostname</th>
                <th style={{ padding: '12px' }}>OS & Arch</th>
                <th style={{ padding: '12px' }}>Status</th>
                <th style={{ padding: '12px' }}>Wrapped IDEs</th>
                <th style={{ padding: '12px' }}>Last Heartbeat</th>
                <th style={{ padding: '12px' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {devices.map((d) => (
                <tr key={d.device_id} style={{ borderBottom: '1px solid #222' }}>
                  <td style={{ padding: '12px', fontFamily: 'monospace' }}>{d.device_id}</td>
                  <td style={{ padding: '12px', fontWeight: 500 }}>{d.hostname}</td>
                  <td style={{ padding: '12px' }}>
                    <span className="badge" style={{ textTransform: 'uppercase', fontSize: '11px' }}>
                      {d.os_family} / {d.os_arch}
                    </span>
                  </td>
                  <td style={{ padding: '12px' }}>
                    <span
                      style={{
                        padding: '4px 8px',
                        borderRadius: '4px',
                        fontSize: '11px',
                        fontWeight: 700,
                        backgroundColor:
                          d.compliance_status === 'COMPLIANT'
                            ? 'rgba(34, 197, 94, 0.15)'
                            : d.compliance_status === 'UNREACHABLE'
                            ? 'rgba(245, 158, 11, 0.15)'
                            : 'rgba(239, 68, 68, 0.15)',
                        color:
                          d.compliance_status === 'COMPLIANT'
                            ? '#22c55e'
                            : d.compliance_status === 'UNREACHABLE'
                            ? '#f59e0b'
                            : '#ef4444',
                      }}
                    >
                      {d.is_revoked ? 'REVOKED' : d.compliance_status}
                    </span>
                  </td>
                  <td style={{ padding: '12px' }}>
                    {d.mcp_servers_wrapped} / {d.mcp_servers_total} wrapped
                  </td>
                  <td style={{ padding: '12px', color: '#aaa', fontSize: '13px' }}>
                    {timeAgo(d.last_heartbeat_at)}
                  </td>
                  <td style={{ padding: '12px' }}>
                    {!d.is_revoked && (
                      <button
                        className="btn btn-sm btn-danger"
                        style={{ padding: '4px 8px', fontSize: '11px', backgroundColor: '#ef4444', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                        onClick={() => handleRevoke(d.device_id)}
                      >
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Token Modal */}
      {showTokenModal && (
        <div style={{ position: 'fixed', inset: 0, backgroundColor: 'rgba(0,0,0,0.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ width: '540px', padding: '24px' }}>
            <h3>Generate One-Time Enrollment Token (OTET)</h3>
            <p style={{ color: '#aaa', fontSize: '13px', marginBottom: '16px' }}>
              Issue a token to enroll developer workstations into central PKI governance.
            </p>

            {!generatedToken ? (
              <form onSubmit={handleGenerateToken}>
                <div style={{ marginBottom: '12px' }}>
                  <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>Token Value</label>
                  <input
                    type="text"
                    value={rawTokenValue}
                    onChange={(e) => setRawTokenValue(e.target.value)}
                    className="input"
                    style={{ width: '100%', fontFamily: 'monospace' }}
                  />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>Max Uses</label>
                    <input
                      type="number"
                      value={maxUses}
                      onChange={(e) => setMaxUses(parseInt(e.target.value) || 1)}
                      className="input"
                      style={{ width: '100%' }}
                    />
                  </div>
                  <div>
                    <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, marginBottom: '4px' }}>TTL (Hours)</label>
                    <input
                      type="number"
                      value={ttlHours}
                      onChange={(e) => setTtlHours(parseInt(e.target.value) || 24)}
                      className="input"
                      style={{ width: '100%' }}
                    />
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                  <button type="button" className="btn" onClick={() => setShowTokenModal(false)}>Cancel</button>
                  <button type="submit" className="btn btn-primary">Generate Token</button>
                </div>
              </form>
            ) : (
              <div>
                <div style={{ padding: '12px', backgroundColor: '#111', borderRadius: '6px', marginBottom: '16px', position: 'relative' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#888' }}>Enrollment Command (Linux / macOS):</div>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ padding: '2px 8px', fontSize: '11px', backgroundColor: copiedField === 'unix' ? '#22c55e' : '#333', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      onClick={() => {
                        const cmd = `curl -fsSL https://vexasec.io/install.sh | AGENTWALL_TOKEN="${generatedToken.token_hash}" bash`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('unix')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'unix' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '12px', color: '#22c55e', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    curl -fsSL https://vexasec.io/install.sh | AGENTWALL_TOKEN="{generatedToken.token_hash}" bash
                  </pre>
                </div>
                <div style={{ padding: '12px', backgroundColor: '#111', borderRadius: '6px', marginBottom: '16px', position: 'relative' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                    <div style={{ fontSize: '12px', color: '#888' }}>Enrollment Command (Windows PowerShell):</div>
                    <button
                      type="button"
                      className="btn btn-sm"
                      style={{ padding: '2px 8px', fontSize: '11px', backgroundColor: copiedField === 'win' ? '#22c55e' : '#333', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
                      onClick={() => {
                        const cmd = `$env:AGENTWALL_TOKEN="${generatedToken.token_hash}"; irm https://vexasec.io/install.ps1 | iex`
                        navigator.clipboard.writeText(cmd)
                        setCopiedField('win')
                        setTimeout(() => setCopiedField(null), 2000)
                      }}
                    >
                      {copiedField === 'win' ? 'Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre style={{ margin: 0, fontSize: '12px', color: '#3b82f6', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    $env:AGENTWALL_TOKEN="{generatedToken.token_hash}"; irm https://vexasec.io/install.ps1 | iex
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
