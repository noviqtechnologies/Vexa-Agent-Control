import { useState, useEffect } from 'react'
import { api, type SentryTamperEvent } from '../api/client'

export default function TamperLog() {
  const [events, setEvents] = useState<SentryTamperEvent[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetchEvents()
  }, [])

  const fetchEvents = async () => {
    setLoading(true)
    try {
      const res = await api.listSentryTamperEvents(100)
      setEvents(res.events || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const getEventBadge = (type: string) => {
    switch (type) {
      case 'AUTO_HEALED':
        return <span className="badge badge-success">AUTO_HEALED</span>
      case 'CONFIG_TAMPERED':
        return <span className="badge badge-warning">CONFIG_TAMPERED</span>
      case 'PROXY_BYPASSED':
      case 'DAEMON_DISABLED':
        return <span className="badge badge-danger">{type}</span>
      default:
        return <span className="badge badge-info">{type}</span>
    }
  }

  return (
    <div className="soc-tamper-log-page">
      <div className="page-header soc-page-header">
        <div>
          <h1>IDE Tamper & Drift Audit Log</h1>
          <p>Immutable forensic record of configuration tampering, proxy bypass attempts, and automatic self-healing events across developer workstations.</p>
        </div>
      </div>

      <div className="card soc-panel">
        <div className="soc-card-header">
          <div>
            <div className="card-title">Workstation Event Stream</div>
            <div className="soc-card-subtitle">Real-time tamper detections and proxy lock integrity alerts</div>
          </div>
          <span className="soc-live-pill">FORENSIC LOG</span>
        </div>

        {loading ? (
          <div className="loading">Loading tamper events...</div>
        ) : events.length === 0 ? (
          <div className="empty-state">
            <p style={{ fontSize: 15, fontWeight: 500 }}>No configuration tampering or bypass events recorded.</p>
            <p style={{ fontSize: 13, marginTop: 4 }}>Workstation Sentry Daemons are actively maintaining required proxy locks.</p>
          </div>
        ) : (
          <div className="table-wrap">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Event ID</th>
                  <th>Workstation / User</th>
                  <th>Target IDE</th>
                  <th>Incident Type</th>
                  <th>Forensic Details</th>
                  <th>Self-Healed</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {events.map((e, idx) => (
                  <tr key={idx} className="soc-table-row">
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} className="text-mono-id">{e.event_id.substring(0, 8)}...</td>
                    <td>
                      <div><strong>{e.hostname}</strong></div>
                      <span style={{ fontSize: 12, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{e.user_identifier}</span>
                    </td>
                    <td><span className="badge badge-info">{e.ide_name}</span></td>
                    <td>{getEventBadge(e.event_type)}</td>
                    <td style={{ fontSize: 13, maxWidth: 350 }}>{e.tamper_details}</td>
                    <td>
                      {e.healed_successfully ? (
                        <span style={{ color: 'var(--success)', fontWeight: 600 }}>✔ Yes (&lt;500ms)</span>
                      ) : (
                        <span style={{ color: 'var(--danger)', fontWeight: 600 }}>✖ Blocked</span>
                      )}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{new Date(e.occurred_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
