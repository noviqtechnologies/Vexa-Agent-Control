import { useState } from 'react'
import { Routes, Route, NavLink, Navigate, useLocation } from 'react-router-dom'
import { useAuth } from './auth/AuthContext'
import RequireAuth from './auth/RequireAuth'
import FleetOverview from './views/FleetOverview'
import IdentityGovernance from './views/IdentityGovernance'
import PolicyInsights from './views/PolicyInsights'
import PolicyEditor from './views/PolicyEditor'
import PolicyMarketplace from './views/PolicyMarketplace'
import ThreatIntelligence from './views/ThreatIntelligence'
import AuthProviders from './views/AuthProviders'
import Users from './views/Users'
import SafeMode from './views/SafeMode'
import AuditLogs from './views/AuditLogs'
import Login from './views/Login'
import RequireAdmin from './auth/RequireAdmin'
import McpServers from './views/McpServers'
import LlmProviders from './views/LlmProviders'
import GroupPolicyEditor from './views/GroupPolicyEditor'
import SpendLimits from './views/SpendLimits'
import IncreaseRequests from './views/IncreaseRequests'
import SpendStatus from './views/SpendStatus'
import SpendVisualization from './views/SpendVisualization'
import Devices from './views/Devices'
import TamperLog from './views/TamperLog'
import CommandPalette from './components/CommandPalette'
import NotificationCenter from './components/NotificationCenter'

interface NavSection {
  id: string
  label: string
  icon: React.ReactNode
  children: { label: string; to: string }[]
}

const NAV_SECTIONS: NavSection[] = [
  {
    id: 'team',
    label: 'Team & Fleet',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
        <circle cx="9" cy="7" r="4"/>
        <path d="M23 21v-2a4 4 0 0 0-3-3.87"/>
        <path d="M16 3.13a4 4 0 0 1 0 7.75"/>
      </svg>
    ),
    children: [
      { label: 'Device Governance', to: '/devices' },
      { label: 'IDE Tamper Log', to: '/devices/tamper-log' },
      { label: 'Users & Roles', to: '/admin/users' },
      { label: 'Auth Providers & SSO', to: '/admin/auth-providers' },
    ],
  },
  {
    id: 'integrations',
    label: 'Integrations & Keys',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="2" y="3" width="20" height="14" rx="2"/>
        <path d="M8 21h8m-4-4v4"/>
      </svg>
    ),
    children: [
      { label: 'LLM Providers', to: '/integrations/llm-providers' },
      { label: 'MCP Servers', to: '/integrations/mcp-servers' },
    ],
  },
  {
    id: 'spend',
    label: 'Spend & Budgets',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <circle cx="12" cy="12" r="10"/><path d="M16 8h-6a2 2 0 1 0 0 4h4a2 2 0 1 1 0 4H8"/><path d="M12 18V6"/>
      </svg>
    ),
    children: [
      { label: 'Spend Limits', to: '/spend/limits' },
      { label: 'Increase Requests', to: '/spend/requests' },
      { label: 'Spend Status', to: '/spend/status' },
      { label: 'Usage Analytics', to: '/spend/visualization' },
    ],
  },
  {
    id: 'policies',
    label: 'Policies & Security',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      </svg>
    ),
    children: [
      { label: 'Active Policies', to: '/policy' },
      { label: 'Policy Marketplace', to: '/policy/marketplace' },
      { label: 'Policy Editor', to: '/policy/edit' },
      { label: 'Group Policies', to: '/policy/group' },
      { label: 'Threat Intelligence', to: '/threats' },
      { label: 'Audit Logs', to: '/audit' },
      { label: 'Safe Mode', to: '/policy/safe-mode' },
      { label: 'Agent Identity', to: '/identity' },
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

function Sidebar({ onLogout, onOpenCommandPalette }: { onLogout: () => void; onOpenCommandPalette: () => void }) {
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
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2.2" style={{ flexShrink: 0 }}>
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          <path d="M9 12l2 2 4-4"/>
        </svg>
        <span className="sidebar-brand-text">Vexa <span>Agent Control</span></span>
      </div>

      {/* Quick search command button in sidebar */}
      <button
        type="button"
        className="sidebar-quick-search-btn"
        onClick={onOpenCommandPalette}
        title="Open Command Palette (Ctrl+K)"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        <span>Search actions...</span>
        <kbd className="sidebar-kbd">Ctrl K</kbd>
      </button>

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

function GlobalAuthBanner() {
  const { needsAuthProviderConfig } = useAuth();
  const location = useLocation();

  if (!needsAuthProviderConfig) return null;
  if (location.pathname === '/admin/auth-providers') return null;

  return (
    <div className="ap-global-warning-banner" style={{ margin: '20px 20px 0', cursor: 'pointer' }} onClick={() => window.location.href = '/admin/auth-providers'}>
      <div className="ap-global-warning-icon">
        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
          <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
        </svg>
      </div>
      <div className="ap-global-warning-content">
        <strong>No Auth Providers Configured!</strong>
        <p>To finish setting up Agent Control, you'll need to configure an Auth Provider. Select one below to get started!</p>
      </div>
    </div>
  );
}

function TopHeaderBar({ onOpenCommandPalette }: { onOpenCommandPalette: () => void }) {
  return (
    <header className="soc-top-bar">
      <div className="soc-top-bar-left">
        <button
          type="button"
          className="soc-search-trigger"
          onClick={onOpenCommandPalette}
          aria-label="Open Command Palette"
        >
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <span className="soc-search-text">Quick jump to policy, agent, or action...</span>
          <kbd className="soc-search-kbd">Ctrl K</kbd>
        </button>
      </div>

      <div className="soc-top-bar-right">
        <div className="soc-gateway-status-pill">
          <span className="status-dot-pulse" />
          <span className="status-text">Gateway Active</span>
          <span className="status-mode">Zero-Trust</span>
        </div>

        <NotificationCenter />
      </div>
    </header>
  )
}

export default function App() {
  const { authenticated, logout } = useAuth()
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false)

  return (
    <>
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
      />
      <Routes>
        <Route path="/login" element={authenticated ? <Navigate to="/fleet" /> : <Login />} />

        <Route path="*" element={
          <RequireAuth>
            <div className="app-shell">
              <Sidebar
                onLogout={logout}
                onOpenCommandPalette={() => setIsCommandPaletteOpen(true)}
              />

              <div className="main-viewport-wrapper">
                <TopHeaderBar onOpenCommandPalette={() => setIsCommandPaletteOpen(true)} />
                <main className="main-content">
                  <GlobalAuthBanner />
                  <Routes>
                    <Route path="/" element={<Navigate to="/fleet" replace />} />
                    <Route path="/fleet" element={<FleetOverview />} />
                    <Route path="/identity" element={<IdentityGovernance />} />
                    <Route path="/policy" element={<PolicyInsights />} />
                    <Route path="/policy/marketplace" element={<PolicyMarketplace />} />
                    <Route path="/policy-marketplace" element={<PolicyMarketplace />} />
                    <Route path="/policy/edit" element={<PolicyEditor />} />
                    <Route path="/policy/group" element={<GroupPolicyEditor />} />
                    <Route path="/spend/limits" element={<SpendLimits />} />
                    <Route path="/spend/requests" element={<IncreaseRequests />} />
                    <Route path="/spend/status" element={<SpendStatus />} />
                    <Route path="/spend/visualization" element={<SpendVisualization />} />
                    <Route path="/policy/safe-mode" element={<SafeMode />} />
                    <Route path="/threats" element={<ThreatIntelligence />} />
                    <Route path="/audit" element={<AuditLogs />} />
                    <Route path="/admin/auth-providers" element={<AuthProviders />} />
                    <Route path="/admin/users" element={<Users />} />
                    <Route path="/admin/devices" element={<Navigate to="/devices" replace />} />
                    <Route path="/devices" element={<Devices />} />
                    <Route path="/devices/tamper-log" element={<TamperLog />} />
                    <Route path="/integrations/ide" element={<Navigate to="/devices" replace />} />
                    <Route path="/integrations/mcp-servers" element={
                      <RequireAdmin>
                        <McpServers />
                      </RequireAdmin>
                    } />
                    <Route path="/integrations/llm-providers" element={
                      <RequireAdmin>
                        <LlmProviders />
                      </RequireAdmin>
                    } />
                    {/* Legacy redirect */}
                    <Route path="/settings/auth" element={<Navigate to="/admin/auth-providers" replace />} />
                  </Routes>
                </main>
              </div>
            </div>
          </RequireAuth>
        } />
      </Routes>
    </>
  )
}
