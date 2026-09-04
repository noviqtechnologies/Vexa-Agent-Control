import { useEffect, useState } from 'react'
import { api, type CredentialMeta } from '../api/client'

function formatDate(ms: number): string {
  return new Date(ms).toLocaleDateString([], {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function ttlDisplay(seconds: number): string {
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`
  return `${Math.floor(seconds / 86400)}d`
}

function expiryStatus(expiresAtMs: number): { label: string; cls: string } {
  const remaining = expiresAtMs - Date.now()
  if (remaining <= 0) return { label: 'Expired', cls: 'danger' }
  if (remaining < 3600_000) return { label: 'Expiring soon', cls: 'warning' }
  return { label: 'Active', cls: 'success' }
}

const REASON_LABELS: Record<string, string> = {
  scheduled: 'Scheduled',
  manual: 'Manual',
  compromise: 'Compromise',
  policy_change: 'Policy Change',
}

export default function IdentityGovernance() {
  const [credentials, setCredentials] = useState<CredentialMeta[]>([])
  const [loading, setLoading] = useState(true)
  const [rotating, setRotating] = useState<string | null>(null)
  const [rotateMsg, setRotateMsg] = useState<{ agentId: string; ok: boolean; text: string } | null>(null)

  useEffect(() => {
    api.listCredentials()
      .then(res => setCredentials(res || []))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  function handleRotate(agentId: string) {
    setRotating(agentId)
    setRotateMsg(null)
    api.triggerRotation(agentId)
      .then((result) => {
        setRotateMsg({ agentId, ok: true, text: `Rotated — new credential ${result.new_credential_id}` })
        api.listCredentials().then(res => setCredentials(res || [])).catch(() => {})
      })
      .catch((err) => {
        setRotateMsg({ agentId, ok: false, text: `Rotation failed: ${err.message}` })
      })
      .finally(() => setRotating(null))
  }

  const [showModal, setShowModal] = useState(false)
  const [copiedCurl, setCopiedCurl] = useState(false)

  if (loading) return <div className="loading">Loading identity data</div>

  const hubOrigin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:8400'
  const sampleCurl = `curl -X POST ${hubOrigin}/api/v1/ingest/credentials \\
  -H "Content-Type: application/json" \\
  -H "X-Gateway-Secret: local-dev-shared-secret-change-me" \\
  -d '{
    "credential_id": "cred-agent-01",
    "agent_id": "agent-sentry-01",
    "scope": ["mcp:tools:execute", "egress:https"],
    "ttl_seconds": 86400,
    "created_at_ms": ${Date.now()},
    "expires_at_ms": ${Date.now() + 86400000},
    "last_rotated_at_ms": ${Date.now()},
    "rotation_history": []
  }'`

  return (
    <div className="soc-identity-page">
      <div className="page-header soc-page-header">
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h1>Identity Governance</h1>
            <span className="coming-soon-badge">Coming Soon</span>
          </div>
          <p>Autonomous agent credentials, tool-level scopes, TTLs, and rotation history</p>
        </div>
        <div className="soc-header-controls">
          <button
            type="button"
            className="soc-btn-primary"
            onClick={() => setShowModal(true)}
          >
            + Issue Sample Credential
          </button>
        </div>
      </div>

      {/* Roadmap Preview Banner */}
      <div className="roadmap-preview-banner">
        <span style={{ fontSize: 24, lineHeight: 1 }}>🚀</span>
        <div>
          <h4 style={{ margin: '0 0 4px 0', fontSize: '14px', fontWeight: 600, color: '#e0e7ff' }}>
            Roadmap Preview — Autonomous AI Daemon Identity Management (IAM)
          </h4>
          <div style={{ fontSize: '13px', color: '#c7d2fe', lineHeight: '1.5' }}>
            Autonomous background AI daemons will use short-lived cryptographic tokens with tool-level scopes (e.g. <code>mcp:tools:execute</code>) and automated policy-driven rotation.
            <div style={{ marginTop: 4 }}>
              <strong>Current Governance:</strong> Developer workstations and IDEs are active in <a href="#/devices" style={{ color: '#93c5fd', textDecoration: 'underline' }}>Device Governance</a>, and LLM access is governed via <a href="#/integrations/virtual-keys" style={{ color: '#93c5fd', textDecoration: 'underline' }}>Virtual Keys</a>.
            </div>
          </div>
        </div>
      </div>

      {/* Summary stats */}
      <div className="stats-grid soc-stats-grid">
        <div className="card stat-tile soc-clickable-tile">
          <div className="stat-header-row">
            <div className="stat-label">Total Credentials</div>
            <span className="soc-delta-badge delta-neutral">Issued</span>
          </div>
          <div className="stat-value">{credentials.length}</div>
          <div className="stat-subtext">Issued identity tokens</div>
        </div>
        <div className="card stat-tile soc-clickable-tile">
          <div className="stat-header-row">
            <div className="stat-label">Active</div>
            <span className="soc-delta-badge delta-success">Live</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {credentials.filter(c => c.expires_at_ms > Date.now()).length}
          </div>
          <div className="stat-subtext">Within valid TTL window</div>
        </div>
        <div className="card stat-tile soc-clickable-tile tile-danger">
          <div className="stat-header-row">
            <div className="stat-label">Expired</div>
            <span className="soc-delta-badge delta-danger">Revoked</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--danger)' }}>
            {credentials.filter(c => c.expires_at_ms <= Date.now()).length}
          </div>
          <div className="stat-subtext">Requires credential rotation</div>
        </div>
        <div className="card stat-tile soc-clickable-tile tile-warning">
          <div className="stat-header-row">
            <div className="stat-label">Expiring Soon</div>
            <span className="soc-delta-badge delta-warning">&lt; 1h</span>
          </div>
          <div className="stat-value" style={{ color: 'var(--warning)' }}>
            {credentials.filter(c => {
              const remaining = c.expires_at_ms - Date.now()
              return remaining > 0 && remaining < 3600_000
            }).length}
          </div>
          <div className="stat-subtext">Pending automatic rotation</div>
        </div>
      </div>

      {/* Identity Posture Reference Guide */}
      <div className="card soc-panel" style={{ padding: '18px 22px', marginBottom: '24px' }}>
        <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <span>🔐</span> Understanding Agent Identity & Scoped Credentials
        </div>
        <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
          Agent Control enforces least-privilege Zero-Trust identity binding for AI daemons.
          Credentials define tool scopes (e.g. <code>mcp:tools:execute</code>) and strict TTLs. Gateway proxies auto-rotate tokens based on security policies.
        </div>
      </div>

      {/* Modal / Onboard Info */}
      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ background: '#18181b', padding: '24px', borderRadius: '8px', maxWidth: '600px', width: '90%', border: '1px solid #27272a' }}>
            <h3 style={{ marginTop: 0, color: '#f4f4f5' }}>Register / Issue Agent Credential</h3>
            <p style={{ fontSize: '13px', color: '#a1a1aa' }}>
              Credentials are issued automatically during agent onboarding or ingested via the control-plane ingest API:
            </p>
            <pre style={{ background: '#09090b', padding: '12px', borderRadius: '6px', overflowX: 'auto', fontSize: '12px', color: '#38bdf8' }}>
              {sampleCurl}
            </pre>
            <div style={{ marginTop: '16px', display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => {
                  navigator.clipboard.writeText(sampleCurl)
                  setCopiedCurl(true)
                  setTimeout(() => setCopiedCurl(false), 2000)
                }}
              >
                {copiedCurl ? '✔ Copied to Clipboard!' : 'Copy cURL Snippet'}
              </button>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setShowModal(false)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Credential cards */}
      {credentials.length === 0 ? (
        <div className="card empty-state" style={{ padding: '32px', textAlign: 'center' }}>
          <p style={{ margin: '0 0 12px 0', fontSize: '14px', color: '#a1a1aa' }}>
            No agent credentials registered yet.
          </p>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={() => setShowModal(true)}
          >
            How to Ingest Credentials
          </button>
        </div>
      ) : (
        <div className="cred-grid">
          {credentials.map((c) => {
            const status = expiryStatus(c.expires_at_ms)
            return (
              <div className="card cred-card" key={c.credential_id}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div className="cred-id">{c.credential_id}</div>
                  <span className={`badge badge-${status.cls}`}>{status.label}</span>
                </div>

                <div className="cred-scope">
                  {(c.scope || []).map((s) => (
                    <span className="scope-tag" key={s}>{s}</span>
                  ))}
                </div>

                <div className="cred-detail" style={{ marginTop: 12 }}>
                  <span>Agent</span>
                  <span>{c.agent_id}</span>
                </div>
                <div className="cred-detail">
                  <span>TTL</span>
                  <span>{ttlDisplay(c.ttl_seconds)}</span>
                </div>
                <div className="cred-detail">
                  <span>Created</span>
                  <span>{formatDate(c.created_at_ms)}</span>
                </div>
                <div className="cred-detail">
                  <span>Expires</span>
                  <span>{formatDate(c.expires_at_ms)}</span>
                </div>
                {c.last_rotated_at_ms && (
                  <div className="cred-detail">
                    <span>Last Rotated</span>
                    <span>{formatDate(c.last_rotated_at_ms)}</span>
                  </div>
                )}

                {/* Rotate button */}
                <div style={{ marginTop: 12 }}>
                  <button
                    className="refresh-btn"
                    disabled={rotating === c.agent_id}
                    onClick={() => handleRotate(c.agent_id)}
                    style={{ width: '100%' }}
                  >
                    {rotating === c.agent_id ? 'Rotating...' : 'Rotate Credential'}
                  </button>
                  {rotateMsg && rotateMsg.agentId === c.agent_id && (
                    <div style={{
                      marginTop: 8,
                      fontSize: 13,
                      color: rotateMsg.ok ? 'var(--success)' : 'var(--danger)',
                    }}>
                      {rotateMsg.text}
                    </div>
                  )}
                </div>

                {/* Rotation history */}
                {c.rotation_history?.length > 0 && (
                  <div style={{ marginTop: 12, borderTop: '1px solid var(--border)', paddingTop: 12 }}>
                    <div className="card-title" style={{ marginBottom: 8 }}>Rotation History</div>
                    {(c.rotation_history || []).map((r, i) => (
                      <div className="cred-detail" key={i}>
                        <span>{REASON_LABELS[r.reason] || r.reason}</span>
                        <span>{formatDate(r.rotated_at_ms)}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
