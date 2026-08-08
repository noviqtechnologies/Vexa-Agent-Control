import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { subscribeAlerts, type RedactedAlert } from '../api/client'

export default function NotificationCenter() {
  const [alerts, setAlerts] = useState<RedactedAlert[]>([])
  const [isOpen, setIsOpen] = useState(false)
  const [hasUnread, setHasUnread] = useState(false)
  const [hitlActionStatus, setHitlActionStatus] = useState<Record<string, 'approved' | 'denied'>>({})
  const containerRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    if (typeof EventSource === 'undefined') return
    const unsub = subscribeAlerts((alert) => {
      setAlerts((prev) => [alert, ...prev].slice(0, 50))
      setHasUnread(true)
    })
    return unsub
  }, [])

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const criticalCount = alerts.filter((a) => a.severity === 'critical').length

  const handleToggle = () => {
    setIsOpen((prev) => !prev)
    if (!isOpen) {
      setHasUnread(false)
    }
  }

  const handleHitlAction = (alertId: string, action: 'approved' | 'denied') => {
    setHitlActionStatus((prev) => ({ ...prev, [alertId]: action }))
  }

  const clearAlerts = () => {
    setAlerts([])
    setHasUnread(false)
  }

  const formatTimestamp = (ms: number) => {
    const d = new Date(ms)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  }

  return (
    <div className="soc-notification-center" ref={containerRef}>
      <button
        type="button"
        className={`soc-bell-btn ${hasUnread ? 'has-unread' : ''} ${criticalCount > 0 ? 'is-critical' : ''}`}
        onClick={handleToggle}
        aria-label="Security Alerts and Notifications"
        title="Live Security Alerts"
      >
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
          <path d="M13.73 21a2 2 0 0 1-3.46 0" />
        </svg>
        {alerts.length > 0 && (
          <span className={`soc-bell-badge ${criticalCount > 0 ? 'badge-critical' : 'badge-normal'}`}>
            {alerts.length > 99 ? '99+' : alerts.length}
          </span>
        )}
      </button>

      {isOpen && (
        <div className="soc-notification-dropdown">
          <div className="soc-dropdown-header">
            <div>
              <div className="soc-dropdown-title">Security Alert Stream</div>
              <div className="soc-dropdown-sub">
                {alerts.length} event{alerts.length === 1 ? '' : 's'} recorded &bull; {criticalCount} critical
              </div>
            </div>
            {alerts.length > 0 && (
              <button type="button" className="soc-btn-text" onClick={clearAlerts}>
                Clear All
              </button>
            )}
          </div>

          <div className="soc-dropdown-body">
            {alerts.length === 0 ? (
              <div className="soc-dropdown-empty">
                <div className="soc-empty-shield">🛡️</div>
                <div className="soc-empty-title">All Systems Normal</div>
                <p>Zero active security alerts or DLP policy violations detected in the current session.</p>
              </div>
            ) : (
              alerts.map((a) => {
                const actionTaken = hitlActionStatus[a.alert_id]
                return (
                  <div key={a.alert_id} className={`soc-dropdown-alert-item severity-${a.severity}`}>
                    <div className="alert-item-top">
                      <span className={`soc-severity-pill ${a.severity}`}>
                        {a.severity.toUpperCase()}
                      </span>
                      <span className="alert-time">{formatTimestamp(a.event.timestamp_ms)}</span>
                    </div>

                    <div className="alert-item-title">
                      {a.event.dlp_findings?.length > 0
                        ? `DLP Redaction: ${a.event.dlp_findings.map((f) => f.category).join(', ')}`
                        : a.event.injection_findings?.length > 0
                          ? `Prompt Injection: ${a.event.injection_findings.map((f) => f.pattern_name).join(', ')}`
                          : a.event.semantic_findings?.length > 0
                            ? `Semantic Anomaly: ${a.event.semantic_findings.map((f) => f.finding_type).join(', ')}`
                            : `${a.event.decision.toUpperCase()} &bull; ${a.event.tool_name}`}
                    </div>

                    <div className="alert-item-meta">
                      <span className="meta-agent font-mono">{a.event.agent_id}</span>
                      <span className="meta-sep">&bull;</span>
                      <span className="meta-tool">{a.event.tool_name}</span>
                    </div>

                    {actionTaken ? (
                      <div className={`hitl-result-badge result-${actionTaken}`}>
                        {actionTaken === 'approved' ? '✓ HITL Override: Approved' : '✗ Intercept: Blocked & Enforced'}
                      </div>
                    ) : (
                      <div className="alert-action-row">
                        <button
                          type="button"
                          className="soc-btn-action btn-triage"
                          onClick={() => {
                            navigate(`/audit?search=${a.event.agent_id}`)
                            setIsOpen(false)
                          }}
                        >
                          Triage in Audit
                        </button>
                        <button
                          type="button"
                          className="soc-btn-action btn-approve"
                          onClick={() => handleHitlAction(a.alert_id, 'approved')}
                          title="Human-in-the-Loop Override Approval"
                        >
                          Approve
                        </button>
                        <button
                          type="button"
                          className="soc-btn-action btn-deny"
                          onClick={() => handleHitlAction(a.alert_id, 'denied')}
                          title="Enforce Immediate Policy Block"
                        >
                          Block
                        </button>
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>

          <div className="soc-dropdown-footer">
            <button
              type="button"
              className="soc-footer-link"
              onClick={() => {
                navigate('/audit')
                setIsOpen(false)
              }}
            >
              View Full Cryptographic Audit Log &rarr;
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
