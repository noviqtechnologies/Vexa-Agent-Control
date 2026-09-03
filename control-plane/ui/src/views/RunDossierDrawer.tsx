import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { RunDossier } from '../api/client'
import SessionTraceDrawer from '../components/observability/SessionTraceDrawer'
import './RunExplorer.css'

interface Props {
  dossier: RunDossier
  onClose: () => void
}

function microcentsToUSD(microcents?: number): number {
  return (microcents || 0) / 100_000_000
}

function formatStatusText(code?: number, state?: string): { label: string; badgeClass: string } {
  const normState = (state || '').toUpperCase()
  if (normState === 'AUTHORIZED') {
    return { label: 'Pending (In-Flight)', badgeClass: 'badge-info' }
  }
  if (!code || code === 0) {
    if (normState === 'RELEASED') return { label: '503 Service Unavailable', badgeClass: 'badge-danger' }
    if (normState === 'DENIED' || normState === 'BLOCKED') return { label: '403 Forbidden', badgeClass: 'badge-danger' }
    if (normState === 'FAILED' || normState === 'ERROR') return { label: '500 Server Error', badgeClass: 'badge-danger' }
    return { label: '200 OK', badgeClass: 'badge-success' }
  }
  if (code === 200) return { label: '200 OK', badgeClass: 'badge-success' }
  if (code === 503) return { label: '503 Service Unavailable', badgeClass: 'badge-danger' }
  if (code === 502) return { label: '502 Bad Gateway', badgeClass: 'badge-danger' }
  if (code === 504) return { label: '504 Gateway Timeout', badgeClass: 'badge-danger' }
  if (code === 403) return { label: '403 Forbidden', badgeClass: 'badge-danger' }
  if (code === 429) return { label: '429 Too Many Requests', badgeClass: 'badge-danger' }
  if (code === 499) return { label: '499 Client Cancelled', badgeClass: 'badge-warning' }
  if (code >= 400) return { label: `${code} Error`, badgeClass: 'badge-danger' }
  return { label: `${code} OK`, badgeClass: 'badge-success' }
}

export default function RunDossierDrawer({ dossier, onClose }: Props) {
  const navigate = useNavigate()
  const [tab, setTab] = useState<'identity' | 'policy' | 'economics' | 'events' | 'dispatch'>('economics')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [traceSessionId, setTraceSessionId] = useState<string | null>(null)

  const handleNavigateEffectivePolicy = () => {
    const params = new URLSearchParams()
    if (dossier.identity?.device_id) params.set('device_id', dossier.identity.device_id)
    if (dossier.identity?.project_id) params.set('project_id', dossier.identity.project_id)
    if (dossier.dispatch?.provider) params.set('provider', dossier.dispatch.provider)
    if (dossier.dispatch?.model) params.set('model', dossier.dispatch.model)
    navigate(`/policy/effective-explorer?${params.toString()}`)
  }

  const copyText = (text: string, key: string) => {
    navigator.clipboard.writeText(text)
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  const isSettled = dossier.outcome?.state?.toUpperCase() === 'SETTLED'
  const isReleased = dossier.outcome?.state?.toUpperCase() === 'RELEASED'
  const isDenied = dossier.outcome?.state?.toUpperCase() === 'DENIED' || dossier.outcome?.state?.toUpperCase() === 'BLOCKED'
  const isFailed = dossier.outcome?.state?.toUpperCase() === 'FAILED' || dossier.outcome?.state?.toUpperCase() === 'ERROR'

  // Billed financial impact: Only successfully SETTLED runs incur actual spend.
  // RELEASED, FAILED, and DENIED runs have $0.00 actual billed cost.
  const netBilledMicrocents = isSettled ? (dossier.economics?.settled_microcents || 0) : 0
  const netBilledUSD = microcentsToUSD(netBilledMicrocents)

  const reservedUSD = microcentsToUSD(dossier.economics?.reserved_microcents || 0)
  const settledUSD = microcentsToUSD(dossier.economics?.settled_microcents || 0)
  const releasedUSD = microcentsToUSD(
    dossier.economics?.released_microcents !== undefined
      ? dossier.economics.released_microcents
      : isReleased || isDenied || isFailed
      ? dossier.economics?.reserved_microcents || 0
      : Math.max(0, (dossier.economics?.reserved_microcents || 0) - (dossier.economics?.settled_microcents || 0))
  )

  const statusInfo = formatStatusText(dossier.outcome?.status_code, dossier.outcome?.state)

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
            {dossier.identity?.session_id && (
              <button
                type="button"
                className="soc-btn-secondary"
                style={{ fontSize: 12, padding: '5px 10px', borderColor: '#a78bfa', color: '#c4b5fd' }}
                onClick={() => setTraceSessionId(dossier.identity?.session_id || null)}
              >
                🧭 Trace Session
              </button>
            )}
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
              {/* 4-KPI Grid with Net Billed Spend */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10, marginBottom: 20 }}>
                <div style={{ padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>RESERVED (HOLD)</div>
                  <div style={{ fontSize: 18, color: '#38bdf8', fontWeight: 600, marginTop: 4 }}>
                    ${reservedUSD.toFixed(4)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Pre-flight ceiling</div>
                </div>

                <div style={{ padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>SETTLED (ACTUAL)</div>
                  <div style={{ fontSize: 18, color: '#10b981', fontWeight: 600, marginTop: 4 }}>
                    ${settledUSD.toFixed(4)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Usage captured</div>
                </div>

                <div style={{ padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>RELEASED</div>
                  <div style={{ fontSize: 18, color: '#f59e0b', fontWeight: 600, marginTop: 4 }}>
                    ${releasedUSD.toFixed(4)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>Unused hold returned</div>
                </div>

                <div style={{ padding: 12, background: isSettled ? 'rgba(16, 185, 129, 0.08)' : 'rgba(255,255,255,0.05)', borderRadius: 6, border: '1px solid ' + (isSettled ? 'rgba(16, 185, 129, 0.3)' : 'var(--border)') }}>
                  <div style={{ fontSize: 10, color: isSettled ? '#10b981' : 'var(--text-muted)', fontWeight: 600 }}>NET BILLED SPEND</div>
                  <div style={{ fontSize: 18, color: isSettled ? '#10b981' : '#f0f6fc', fontWeight: 700, marginTop: 4 }}>
                    ${netBilledUSD.toFixed(4)}
                  </div>
                  <div style={{ fontSize: 10, color: isSettled ? '#10b981' : 'var(--text-muted)', marginTop: 2 }}>
                    {isSettled ? 'Charged to tenant' : 'Zero spend incurred'}
                  </div>
                </div>
              </div>

              {/* Token & Cache Economics Breakdown */}
              <div style={{ padding: 14, background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border)', borderRadius: 6, marginBottom: 20 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-bright)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  🪙 Token Volume & Prompt Cache Economics
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>PROMPT TOKENS</div>
                    <div style={{ fontSize: 15, fontWeight: 600, marginTop: 2 }}>{(dossier.economics?.input_tokens || 0).toLocaleString()}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>COMPLETION TOKENS</div>
                    <div style={{ fontSize: 15, fontWeight: 600, marginTop: 2 }}>{(dossier.economics?.output_tokens || 0).toLocaleString()}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>CACHED TOKENS</div>
                    <div style={{ fontSize: 15, fontWeight: 600, color: '#38bdf8', marginTop: 2 }}>
                      {(dossier.economics?.cached_tokens || 0).toLocaleString()}
                    </div>
                  </div>
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>CACHE HIT RATIO</div>
                    <div style={{ fontSize: 15, fontWeight: 600, color: (dossier.economics?.cached_tokens || 0) > 0 ? '#10b981' : 'var(--text-muted)', marginTop: 2 }}>
                      {((dossier.economics?.input_tokens || 0) + (dossier.economics?.cached_tokens || 0)) > 0
                        ? `${(((dossier.economics?.cached_tokens || 0) / ((dossier.economics?.input_tokens || 0) + (dossier.economics?.cached_tokens || 0))) * 100).toFixed(1)}%`
                        : '0.0%'}
                    </div>
                  </div>
                </div>
                {Boolean(dossier.economics?.ttft_ms) && (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 10, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,0.05)' }}>
                    ⚡ Time to First Token (TTFT): <strong>{dossier.economics?.ttft_ms} ms</strong>
                  </div>
                )}
              </div>

              <div className="dossier-kv-grid">
                <span className="dossier-k">HTTP Status Code</span>
                <span className="dossier-v">
                  <span className={`badge ${statusInfo.badgeClass}`}>
                    {statusInfo.label}
                  </span>
                </span>

                <span className="dossier-k">Execution State</span>
                <span className="dossier-v">
                  <span className={`badge-state state-${dossier.outcome?.state?.toLowerCase() || 'settled'}`}>
                    {dossier.outcome?.state || 'UNKNOWN'}
                  </span>
                </span>

                <span className="dossier-k">Duration</span>
                <span className="dossier-v">{dossier.outcome?.duration_ms || 0} ms</span>

                <span className="dossier-k">Started At</span>
                <span className="dossier-v">{dossier.outcome?.started_at ? new Date(dossier.outcome.started_at).toLocaleString() : 'N/A'}</span>

                <span className="dossier-k">Settled / Closed At</span>
                <span className="dossier-v">
                  {dossier.outcome?.settled_at
                    ? new Date(dossier.outcome.settled_at).toLocaleString()
                    : dossier.outcome?.released_at
                    ? new Date(dossier.outcome.released_at).toLocaleString()
                    : 'N/A'}
                </span>

                {dossier.outcome?.release_reason && (
                  <>
                    <span className="dossier-k">Release Reason</span>
                    <span className="dossier-v">
                      <code style={{ background: 'rgba(245, 158, 11, 0.15)', color: '#f59e0b', padding: '2px 6px', borderRadius: 4, fontSize: 12 }}>
                        {dossier.outcome.release_reason}
                      </code>
                    </span>
                  </>
                )}
              </div>
            </div>
          )}

          {tab === 'identity' && (
            <div className="dossier-kv-grid">
              <span className="dossier-k">Device ID</span>
              <span className="dossier-v" style={{ fontFamily: 'var(--font-mono)' }}>
                {dossier.identity?.device_id || 'N/A'}
              </span>

              <span className="dossier-k">Hostname</span>
              <span className="dossier-v">{dossier.identity?.device_hostname || dossier.identity?.device_id || 'N/A'}</span>

              <span className="dossier-k">Compliance</span>
              <span className="dossier-v">
                <span
                  style={{
                    color: dossier.identity?.device_compliance === 'COMPLIANT'
                      ? '#10b981'
                      : dossier.identity?.device_compliance === 'NON_COMPLIANT'
                      ? '#ef4444'
                      : dossier.identity?.device_compliance === 'UNREGISTERED' || dossier.identity?.device_compliance === 'NOT_ENROLLED'
                      ? '#94a3b8'
                      : '#f59e0b',
                    fontWeight: 600,
                  }}
                >
                  {dossier.identity?.device_compliance || 'UNKNOWN'}
                </span>
              </span>

              {dossier.identity?.session_id && (
                <>
                  <span className="dossier-k">Session Trace</span>
                  <span className="dossier-v" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <code style={{ fontFamily: 'var(--font-mono)' }}>{dossier.identity.session_id}</code>
                    <button
                      type="button"
                      className="soc-btn-secondary"
                      style={{ fontSize: 11, padding: '2px 8px', borderColor: '#a78bfa', color: '#c4b5fd' }}
                      onClick={() => setTraceSessionId(dossier.identity?.session_id || null)}
                    >
                      🧭 Trace Session
                    </button>
                  </span>
                </>
              )}

              {dossier.identity?.virtual_key_prefix && (
                <>
                  <span className="dossier-k">Virtual Key</span>
                  <span className="dossier-v">
                    <span className="obs-key-pill">{dossier.identity.virtual_key_prefix}</span>
                    {dossier.identity.virtual_key_alias && (
                      <span style={{ marginLeft: 6, color: 'var(--text-muted)' }}>({dossier.identity.virtual_key_alias})</span>
                    )}
                  </span>
                </>
              )}

              {(dossier.identity?.internal_user_id || dossier.identity?.end_user_id) && (
                <>
                  <span className="dossier-k">Attributed User</span>
                  <span className="dossier-v">
                    {dossier.identity.internal_user_id || dossier.identity.end_user_id}
                  </span>
                </>
              )}

              <span className="dossier-k">Project Scope</span>
              <span className="dossier-v">{dossier.identity?.project_id || 'default'}</span>

              <span className="dossier-k">Correlation Key</span>
              <span className="dossier-v" style={{ fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span>{dossier.request_id || 'N/A'}</span>
                {dossier.request_id && (
                  <button
                    type="button"
                    className="soc-btn-secondary"
                    style={{ fontSize: 11, padding: '2px 6px' }}
                    onClick={() => copyText(dossier.request_id, 'req-id')}
                  >
                    {copiedKey === 'req-id' ? '✓ Copied' : 'Copy'}
                  </button>
                )}
              </span>
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
              {/* Executive Ledger Summary */}
              <div style={{ padding: 12, background: 'rgba(255,255,255,0.03)', borderRadius: 6, border: '1px solid var(--border)', marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>TRANSACTION BALANCE SUMMARY</div>
                  <div style={{ fontSize: 12, color: 'var(--text-bright)', marginTop: 4 }}>
                    Hold: <span style={{ color: '#38bdf8' }}>+${reservedUSD.toFixed(4)}</span>
                    {' · '}
                    Returned: <span style={{ color: '#f59e0b' }}>-${releasedUSD.toFixed(4)}</span>
                  </div>
                </div>
                <div style={{ textAlign: 'right' }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>NET BILLED IMPACT</div>
                  <div style={{ fontSize: 16, color: isSettled ? '#10b981' : '#f0f6fc', fontWeight: 700 }}>
                    ${netBilledUSD.toFixed(4)}
                  </div>
                </div>
              </div>

              <p style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 12 }}>Immutable Append-Only Spend Events Ledger:</p>
              {(!dossier.economics?.events || dossier.economics.events.length === 0) ? (
                <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>No transaction events recorded for this reservation.</p>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {dossier.economics.events.map((ev, idx) => {
                    const isEvSettled = ev.event_type === 'SETTLED'
                    const isEvReleased = ev.event_type === 'RELEASED'
                    const isEvAuth = ev.event_type === 'AUTHORIZED'
                    const amountUSD = (ev.amount_microcents / 100_000_000).toFixed(4)

                    let badgeClass = 'badge-info'
                    let amountColor = '#38bdf8'
                    let amountPrefix = '+'
                    let amountLabel = '(Hold / Ceiling)'
                    let description = 'Budget ceiling reserved pre-execution'

                    if (isEvSettled) {
                      badgeClass = 'badge-success'
                      amountColor = '#10b981'
                      amountPrefix = '+'
                      amountLabel = '(Actual Usage Billed)'
                      description = 'Provider execution finalized and billed'
                    } else if (isEvReleased) {
                      badgeClass = 'badge-warning'
                      amountColor = '#f59e0b'
                      amountPrefix = '-'
                      amountLabel = '(Unused Hold Returned)'
                      description = `Hold cancelled & budget restored to tenant (Net charge: $0.00)`
                    } else if (isEvAuth) {
                      badgeClass = 'badge-info'
                      amountColor = '#38bdf8'
                      amountPrefix = '+'
                      amountLabel = '(Pre-flight Hold)'
                      description = 'Pre-flight budget reservation ceiling'
                    }

                    return (
                      <div key={idx} style={{ padding: 12, background: 'rgba(255,255,255,0.02)', borderRadius: 6, border: '1px solid var(--border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                          <span className={`badge ${badgeClass}`}>{ev.event_type}</span>
                          <div style={{ textAlign: 'right' }}>
                            <strong style={{ color: amountColor, fontSize: 14 }}>{amountPrefix}${amountUSD}</strong>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 6 }}>{amountLabel}</span>
                          </div>
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                          Occurred: {new Date(ev.occurred_at).toLocaleTimeString()} · Reason: <code style={{ color: 'var(--text-bright)' }}>{ev.reason_code}</code>
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4, fontStyle: 'italic' }}>
                          {description}
                        </div>
                      </div>
                    )
                  })}
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
          <span>Confidence: <strong style={{ color: dossier.provenance?.confidence === 'observed' ? '#10b981' : '#f59e0b' }}>{dossier.provenance?.confidence || 'observed'}</strong></span>
          <span>Source: {dossier.provenance?.evidence_source || 'postgresql_spend_reservations'}</span>
        </div>
      </div>

      {/* Embedded Session Trace Drawer */}
      {traceSessionId && (
        <SessionTraceDrawer
          sessionId={traceSessionId}
          onClose={() => setTraceSessionId(null)}
        />
      )}
    </div>
  )
}

