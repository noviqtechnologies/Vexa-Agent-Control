import { useState, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import RequestLogsTab from '../components/observability/RequestLogsTab'
import AuditLogsTab from '../components/observability/AuditLogsTab'
import DeletedKeysTab from '../components/observability/DeletedKeysTab'
import DeletedTeamsTab from '../components/observability/DeletedTeamsTab'
import './ObservabilityLogs.css'

type TabType = 'request_logs' | 'audit' | 'deleted_keys' | 'deleted_teams'

export default function ObservabilityLogs() {
  const [searchParams, setSearchParams] = useSearchParams()
  const tabParam = searchParams.get('tab') as TabType | null
  const [activeTab, setActiveTab] = useState<TabType>(
    tabParam === 'audit' || tabParam === 'deleted_keys' || tabParam === 'deleted_teams'
      ? tabParam
      : 'request_logs'
  )

  useEffect(() => {
    if (tabParam && (tabParam === 'request_logs' || tabParam === 'audit' || tabParam === 'deleted_keys' || tabParam === 'deleted_teams')) {
      setActiveTab(tabParam)
    }
  }, [tabParam])

  const handleTabChange = (tab: TabType) => {
    setActiveTab(tab)
    setSearchParams({ tab })
  }

  return (
    <div className="obs-logs-page">
      <div className="page-header soc-page-header obs-page-header">
        <div className="obs-header-left">
          <h1>Observability & Logs</h1>
          <p>Real-time gateway traffic telemetry, immutable management audit ledger, and compliance tombstone tracking.</p>
        </div>
      </div>

      {/* Primary Tab Navigation */}
      <nav className="obs-tabs-nav" aria-label="Observability Tabs">
        <button
          type="button"
          className={`obs-tab-btn ${activeTab === 'request_logs' ? 'active' : ''}`}
          onClick={() => handleTabChange('request_logs')}
        >
          Request Logs
        </button>
        <button
          type="button"
          className={`obs-tab-btn ${activeTab === 'audit' ? 'active' : ''}`}
          onClick={() => handleTabChange('audit')}
        >
          Audit Logs
        </button>
        <button
          type="button"
          className={`obs-tab-btn ${activeTab === 'deleted_keys' ? 'active' : ''}`}
          onClick={() => handleTabChange('deleted_keys')}
        >
          Deleted Keys
        </button>
        <button
          type="button"
          className={`obs-tab-btn ${activeTab === 'deleted_teams' ? 'active' : ''}`}
          onClick={() => handleTabChange('deleted_teams')}
        >
          Deleted Teams
        </button>
      </nav>

      {/* Tab Panels */}
      <div className="obs-tab-content">
        {activeTab === 'request_logs' && <RequestLogsTab />}
        {activeTab === 'audit' && <AuditLogsTab />}
        {activeTab === 'deleted_keys' && <DeletedKeysTab />}
        {activeTab === 'deleted_teams' && <DeletedTeamsTab />}
      </div>
    </div>
  )
}
