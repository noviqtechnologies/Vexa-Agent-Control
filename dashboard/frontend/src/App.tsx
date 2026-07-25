import { useEffect } from 'react'
import { Routes, Route, NavLink, Navigate } from 'react-router-dom'
import { useAuth } from './auth/AuthContext'
import RequireAuth from './auth/RequireAuth'
import { setAuthToken } from './api/client'
import FleetOverview from './views/FleetOverview'
import IdentityGovernance from './views/IdentityGovernance'
import PolicyInsights from './views/PolicyInsights'
import ThreatIntelligence from './views/ThreatIntelligence'

export default function App() {
  const { token } = useAuth()

  useEffect(() => {
    setAuthToken(token)
  }, [token])

  return (
    <div className="app-shell">
      <nav className="sidebar">
        <div className="sidebar-logo">
          Agent<span>Wall</span>
        </div>
        <NavLink
          to="/fleet"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
          Fleet Overview
        </NavLink>
        <NavLink
          to="/identity"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Identity Governance
        </NavLink>
        <NavLink
          to="/policy"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          Policy Insights
        </NavLink>
        <NavLink
          to="/threats"
          className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          Threat Intelligence
        </NavLink>
      </nav>

      <main className="main-content">
        <RequireAuth>
          <Routes>
            <Route path="/" element={<Navigate to="/fleet" replace />} />
            <Route path="/fleet" element={<FleetOverview />} />
            <Route path="/identity" element={<IdentityGovernance />} />
            <Route path="/policy" element={<PolicyInsights />} />
            <Route path="/threats" element={<ThreatIntelligence />} />
          </Routes>
        </RequireAuth>
      </main>
    </div>
  )
}
