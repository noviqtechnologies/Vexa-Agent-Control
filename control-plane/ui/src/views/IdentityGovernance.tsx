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

  if (loading) return <div className="loading">Loading identity data</div>

  const sampleCurl = `curl -X POST http://localhost:8080/api/v1/ingest/credentials \\
  -H "Content-Type: application/json" \\
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
    <>
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h1>Identity Governance</h1>
          <p>Agent credentials, scopes, TTLs, and rotation history</p>
        </div>
        <button
          type="button"
          className="btn btn-primary"
          onClick={() => setShowModal(true)}
        >
          + Issue Sample Credential
        </button>
      </div>

      {/* Summary stats */}
      <div className="stats-grid">
        <div className="card stat-tile">
          <div className="stat-value">{credentials.length}</div>
          <div className="stat-label">Total Credentials</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--success)' }}>
            {credentials.filter(c => c.expires_at_ms > Date.now()).length}
          </div>
          <div className="stat-label">Active</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--danger)' }}>
            {credentials.filter(c => c.expires_at_ms <= Date.now()).length}
          </div>
          <div className="stat-label">Expired</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--warning)' }}>
            {credentials.filter(c => {
              const remaining = c.expires_at_ms - Date.now()
              return remaining > 0 && remaining < 3600_000
            }).length}
          </div>
          <div className="stat-label">Expiring Soon</div>
        </div>
      </div>

      {/* Identity Posture Reference Guide */}
      <div className="card" style={{ padding: '16px', marginBottom: '24px', backgroundColor: '#18181b', borderColor: '#27272a' }}>
        <h4 style={{ margin: '0 0 8px 0', fontSize: '14px', fontWeight: 600, color: '#f4f4f5' }}>
          🔐 Understanding Agent Identity & Scoped Credentials
        </h4>
        <div style={{ fontSize: '13px', color: '#a1a1aa', lineHeight: '1.5' }}>
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
                  alert('cURL snippet copied to clipboard!')
                }}
              >
                Copy cURL Snippet
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
    </>
  )
}
