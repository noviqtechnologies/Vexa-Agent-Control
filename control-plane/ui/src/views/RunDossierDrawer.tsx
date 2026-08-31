import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { RunDossier } from '../api/client'

interface Props {
  dossier: RunDossier
  onClose: () => void
}

function microcentsToUSD(microcents: number): number {
  return (microcents || 0) / 100_000_000
}

export default function RunDossierDrawer({ dossier, onClose }: Props) {
  const navigate = useNavigate()
  const [tab, setTab] = useState<'identity' | 'policy' | 'economics' | 'events' | 'dispatch'>('economics')

  const handleNavigateEffectivePolicy = () => {
    const params = new URLSearchParams()
    if (dossier.identity?.device_id) params.set('device_id', dossier.identity.device_id)
    if (dossier.identity?.project_id) params.set('project_id', dossier.identity.project_id)
    if (dossier.dispatch?.provider) params.set('provider', dossier.dispatch.provider)
    if (dossier.dispatch?.model) params.set('model', dossier.dispatch.model)
    navigate(`/policy/effective-explorer?${params.toString()}`)
  }

  return (
    <div className="drawer-backdrop" onClick={onClose}>
      <div className="dossier-drawer" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="drawer-header">
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <h2 style={{ fontSize: 18, margin: 0 }}>Run Dossier</h2>
              <span className={`badge-state state-${dossier.outcome?.state?.toLowerCase() || 'settled'}`}>
                {dossier.outcome?.state || 'UNKNOWN'}
              </span>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: 12, color: 'var(--text-muted)' }}>
              ID: <span style={{ fontFamily: 'var(--font-mono)' }}>{dossier.run_id}</span>
            </p>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              type="button"
              className="soc-btn-secondary"
              style={{ fontSize: 12, padding: '5px 10px' }}
              onClick={handleNavigateEffectivePolicy}
            >
              ⚖️ View Effective Policy
            </button>
            <button
              type="button"
              className="soc-btn-secondary"
              style={{ fontSize: 16, padding: '4px 8px' }}
              onClick={onClose}
              aria-label="Close Drawer"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Tab Strip */}
        <div className="drawer-tabs">
          {(['economics', 'identity', 'policy', 'events', 'dispatch'] as const).map((t) => (
            <button
              key={t}
              type="button"
              className={`drawer-tab-btn ${tab === t ? 'active' : ''}`}
              onClick={() => setTab(t)}
            >
              {t.toUpperCase()}
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="drawer-body">
          {tab === 'economics' && (
            <div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 20 }}>
                <div style={{ padding: 14, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>RESERVED</div>
                  <div style={{ fontSize: 20, color: '#38bdf8', fontWeight: 600, marginTop: 4 }}>
                    ${microcentsToUSD(dossier.economics?.reserved_microcents || 0).toFixed(4)}
                  </div>
                </div>
                <div style={{ padding: 14, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>SETTLED (ACTUAL)</div>
                  <div style={{ fontSize: 20, color: '#10b981', fontWeight: 600, marginTop: 4 }}>
                    ${microcentsToUSD(dossier.economics?.settled_microcents || 0).toFixed(4)}
                  </div>
                </div>
                <div style={{ padding: 14, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>RELEASED</div>
                  <div style={{ fontSize: 20, color: '#f59e0b', fontWeight: 600, marginTop: 4 }}>
                    ${microcentsToUSD(dossier.economics?.released_microcents || 0).toFixed(4)}
                  </div>
                </div>
              </div>

              <div className="dossier-kv-grid">
                <span className="dossier-k">Duration</span>
                <span className="dossier-v">{dossier.outcome?.duration_ms || 0} ms</span>

                <span className="dossier-k">Started At</span>
                <span className="dossier-v">{dossier.outcome?.started_at ? new Date(dossier.outcome.started_at).toLocaleString() : 'N/A'}</span>

                <span className="dossier-k">Settled At</span>
                <span className="dossier-v">{dossier.outcome?.settled_at ? new Date(dossier.outcome.settled_at).toLocaleString() : 'N/A'}</span>

                {dossier.outcome?.release_reason && (
                  <>
                    <span className="dossier-k">Release Reason</span>
                    <span className="dossier-v">{dossier.outcome.release_reason}</span>
                  </>
                )}
              </div>
            </div>
          )}

          {tab === 'identity' && (
            <div className="dossier-kv-grid">
              <span className="dossier-k">Device ID</span>
              <span className="dossier-v" style={{ fontFamily: 'var(--font-mono)' }}>{dossier.identity?.device_id || 'N/A'}</span>

              <span className="dossier-k">Hostname</span>
              <span className="dossier-v">{dossier.identity?.device_hostname || 'N/A'}</span>

              <span className="dossier-k">Compliance</span>
              <span className="dossier-v" style={{ color: '#10b981' }}>{dossier.identity?.device_compliance || 'COMPLIANT'}</span>

              <span className="dossier-k">Project Scope</span>
              <span className="dossier-v">{dossier.identity?.project_id || 'default'}</span>

              <span className="dossier-k">Correlation Key</span>
              <span className="dossier-v" style={{ fontFamily: 'var(--font-mono)' }}>{dossier.request_id || 'N/A'}</span>
            </div>
          )}

          {tab === 'policy' && (
            <div>
              <div style={{ marginBottom: 12 }}>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>Price Book Version: </span>
                <strong style={{ fontFamily: 'var(--font-mono)' }}>{dossier.policy?.price_book_version_id || 'default'}</strong>
              </div>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>Governing Policy Snapshot (JSONB):</p>
              <pre className="json-code-box">
                {JSON.stringify(dossier.policy?.snapshot, null, 2)}
              </pre>
            </div>
          )}

          {tab === 'events' && (
            <div>
              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>Immutable Append-Only Spend Events Ledger:</p>
              {(!dossier.economics?.events || dossier.economics.events.length === 0) ? (
                <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No transaction events recorded for this reservation.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {dossier.economics.events.map((ev, idx) => (
                    <div key={idx} style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 6, border: '1px solid var(--border)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                        <span className={`badge ${ev.event_type === 'SETTLED' ? 'badge-success' : 'badge-info'}`}>{ev.event_type}</span>
                        <strong style={{ color: 'var(--warning)' }}>${(ev.amount_microcents / 100_000_000).toFixed(4)}</strong>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                        Occurred: {new Date(ev.occurred_at).toLocaleTimeString()} · Reason: {ev.reason_code}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {tab === 'dispatch' && (
            <div className="dossier-kv-grid">
              <span className="dossier-k">Upstream Provider</span>
              <span className="dossier-v" style={{ textTransform: 'uppercase', fontWeight: 600 }}>{dossier.dispatch?.provider || 'N/A'}</span>

              <span className="dossier-k">Model Selector</span>
              <span className="dossier-v" style={{ fontFamily: 'var(--font-mono)' }}>{dossier.dispatch?.model || 'N/A'}</span>

              <span className="dossier-k">Roundtrip Duration</span>
              <span className="dossier-v">{dossier.outcome?.duration_ms || 0} ms</span>
            </div>
          )}
        </div>

        {/* Provenance Footer */}
        <div style={{ padding: '14px 24px', background: 'rgba(0,0,0,0.3)', borderTop: '1px solid var(--border)', fontSize: 12, color: 'var(--text-muted)', display: 'flex', justifyContent: 'space-between' }}>
          <span>Confidence: <strong style={{ color: '#10b981' }}>{dossier.provenance?.confidence || 'observed'}</strong></span>
          <span>Source: {dossier.provenance?.evidence_source || 'postgresql_spend_reservations'}</span>
        </div>
      </div>
    </div>
  )
}
