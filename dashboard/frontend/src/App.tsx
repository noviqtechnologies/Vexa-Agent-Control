import { useState } from 'react'
import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './auth/AuthContext'
import RequireAuth from './auth/RequireAuth'
import FleetOverview from './views/FleetOverview'
import IdentityGovernance from './views/IdentityGovernance'
import PolicyInsights from './views/PolicyInsights'
import PolicyEditor from './views/PolicyEditor'
import ThreatIntelligence from './views/ThreatIntelligence'
import AuthProviders from './views/AuthProviders'
import Users from './views/Users'
import SafeMode from './views/SafeMode'
import AuditLogs from './views/AuditLogs'
import IdeConnections from './views/IdeConnections'
import Login from './views/Login'
import RequireAdmin from './auth/RequireAdmin'
import McpServers from './views/McpServers'

interface NavSection {
  id: string
  label: string
  icon: React.ReactNode
  children: { label: string; to: string }[]
}

const NAV_SECTIONS: NavSection[] = [
  {
    id: 'policy',
    label: 'Policy Management',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
    children: [
      { label: 'Active Policies', to: '/policy' },
      { label: 'Policy Editor', to: '/policy/edit' },
      { label: 'Safe Mode', to: '/policy/safe-mode' },
    ],
  },
  {
    id: 'observation',
    label: 'Observation & Routing',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
        <circle cx="12" cy="12" r="3"/>
      </svg>
    ),
    children: [
      { label: 'Threat Intelligence', to: '/threats' },
      { label: 'Audit Logs', to: '/audit' },
    ],
  },
  {
    id: 'users',
    label: 'User Management',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
        <circle cx="9" cy="7" r="4"/>
        <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
        <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
      </svg>
    ),
    children: [
      { label: 'Users', to: '/admin/users' },
      { label: 'Auth Providers', to: '/admin/auth-providers' },
    ],
  },
  {
    id: 'integrations',
    label: 'Ecosystem Integrations',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="2" y="3" width="20" height="14" rx="2"/>
        <path d="M8 21h8m-4-4v4"/>
      </svg>
    ),
    children: [
      { label: 'IDE Connections', to: '/integrations/ide' },
      { label: 'MCP Servers', to: '/integrations/mcp-servers' },
    ],
  },
]

function ChevronIcon({ open }: { open: boolean }) {
  return (
    <svg
      width="13"
      height="13"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      style={{ transition: 'transform 0.2s ease', transform: open ? 'rotate(90deg)' : 'rotate(0deg)', flexShrink: 0 }}
    >
      <polyline points="9 18 15 12 9 6"/>
    </svg>
  )
}

function Sidebar({ onLogout }: { onLogout: () => void }) {
  const location = useLocation()

  // Determine which sections should be open by default (those containing the active route)
  function getDefaultOpen(): Set<string> {
    const open = new Set<string>()
    for (const section of NAV_SECTIONS) {
      if (section.children.some(c => location.pathname.startsWith(c.to))) {
        open.add(section.id)
      }
    }
    // Default: open all sections
    if (open.size === 0) NAV_SECTIONS.forEach(s => open.add(s.id))
    return open
  }

  const [openSections, setOpenSections] = useState<Set<string>>(getDefaultOpen)

  function toggleSection(id: string) {
    setOpenSections(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  return (
    <nav className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2" style={{ flexShrink: 0 }}>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        Agent<span>Wall</span>
      </div>

      {/* Dashboard — top-level single link */}
      <NavLink
        to="/fleet"
        className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/>
          <rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
        </svg>
        Dashboard
      </NavLink>

      {/* Agent Identity — single link */}
      <NavLink
        to="/identity"
        className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="2" y="5" width="20" height="14" rx="2"/>
          <path d="M16 10a4 4 0 0 1-8 0"/>
        </svg>
        Agent Identity
      </NavLink>

      {/* Divider */}
      <div style={{ height: 1, background: 'var(--border)', margin: '8px 0' }} />

      {/* Accordion sections */}
      {NAV_SECTIONS.map(section => {
        const isOpen = openSections.has(section.id)
        const hasActiveChild = section.children.some(c => location.pathname.startsWith(c.to))
        return (
          <div key={section.id} className="nav-section">
            <button
              className={`nav-section-header ${hasActiveChild ? 'nav-section-header--active' : ''}`}
              onClick={() => toggleSection(section.id)}
              aria-expanded={isOpen}
            >
              <span className="nav-section-icon">{section.icon}</span>
              <span className="nav-section-label">{section.label}</span>
              <ChevronIcon open={isOpen} />
            </button>
            {isOpen && (
              <div className="nav-children">
                {section.children.map(child => (
                  <NavLink
                    key={child.to}
                    to={child.to}
                    className={({ isActive }) => `nav-child-link ${isActive ? 'active' : ''}`}
                    end
                  >
                    {child.label}
                  </NavLink>
                ))}
              </div>
            )}
          </div>
        )
      })}

      <div style={{ flex: 1 }} />

      {/* Bottom Sign Out */}
      <div style={{ height: 1, background: 'var(--border)', margin: '8px 0' }} />
      <button
        className="nav-link"
        onClick={onLogout}
        style={{ background: 'none', border: 'none', width: '100%', textAlign: 'left', cursor: 'pointer', color: 'var(--text-muted)' }}
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/>
          <polyline points="16 17 21 12 16 7"/>
          <line x1="21" y1="12" x2="9" y2="12"/>
        </svg>
        Sign Out
      </button>
    </nav>
  )
}

export default function App() {
  const { authenticated, logout } = useAuth()

  return (
    <Routes>
      <Route path="/login" element={authenticated ? <Navigate to="/fleet" /> : <Login />} />

      <Route path="*" element={
        <RequireAuth>
          <div className="app-shell">
            <Sidebar onLogout={logout} />

            <main className="main-content">
              <Routes>
                <Route path="/" element={<Navigate to="/fleet" replace />} />
                <Route path="/fleet" element={<FleetOverview />} />
                <Route path="/identity" element={<IdentityGovernance />} />
                <Route path="/policy" element={<PolicyInsights />} />
                <Route path="/policy/edit" element={<PolicyEditor />} />
                <Route path="/policy/safe-mode" element={<SafeMode />} />
                <Route path="/threats" element={<ThreatIntelligence />} />
                <Route path="/audit" element={<AuditLogs />} />
                <Route path="/admin/auth-providers" element={<AuthProviders />} />
                <Route path="/admin/users" element={<Users />} />
                <Route path="/integrations/ide" element={<IdeConnections />} />
                <Route path="/integrations/mcp-servers" element={
                  <RequireAdmin>
                    <McpServers />
                  </RequireAdmin>
                } />
                {/* Legacy redirect */}
                <Route path="/settings/auth" element={<Navigate to="/admin/auth-providers" replace />} />
              </Routes>
            </main>
          </div>
        </RequireAuth>
      } />
    </Routes>
  )
}
