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
import SaaSOperator from './views/SaaSOperator'
import CommandPalette from './components/CommandPalette'
import NotificationCenter from './components/NotificationCenter'
import SetInitialPasswordModal from './components/SetInitialPasswordModal'
import SessionTimeoutModal from './components/SessionTimeoutModal'

interface NavSection {
  id: string
  label: string
  icon: React.ReactNode
  children: { label: string; to: string }[]
}

const OPERATOR_NAV_SECTIONS: NavSection[] = [
  {
    id: 'operator',
    label: 'Platform Operations',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
        <line x1="8" y1="21" x2="16" y2="21"/>
        <line x1="12" y1="17" x2="12" y2="21"/>
      </svg>
    ),
    children: [
      { label: 'Tenant Management', to: '/operator' },
    ],
  },
  {
    id: 'audit-section',
    label: 'Audit & Compliance',
    icon: (
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" />
        <line x1="16" y1="17" x2="8" y2="17" />
        <polyline points="10 9 9 9 8 9" />
      </svg>
    ),
    children: [
      { label: 'Platform Audit Ledger', to: '/audit' },
    ],
  },
]

const CUSTOMER_NAV_SECTIONS: NavSection[] = [
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
      { label: 'Policy Editor', to: '/policy/edit' },
      { label: 'Policy Marketplace', to: '/policy/marketplace' },
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
      style={{
        transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
        transition: 'transform 0.18s cubic-bezier(0.4, 0, 0.2, 1)',
        flexShrink: 0,
      }}
    >
      <polyline points="9 18 15 12 9 6" />
    </svg>
  )
}

function Sidebar({ onLogout }: { onLogout: () => void }) {
  const location = useLocation()
  const { user, needsAuthProviderConfig } = useAuth()
  const isOperator = !!user?.is_saas_operator
  const isEnforced = needsAuthProviderConfig && !isOperator

  const visibleSections = isOperator ? OPERATOR_NAV_SECTIONS : CUSTOMER_NAV_SECTIONS

  const [collapsed, setCollapsed] = useState<Record<string, boolean>>(() => {
    const state: Record<string, boolean> = {}
    visibleSections.forEach((s) => {
      if (isEnforced && s.id === 'team') {
        state[s.id] = false
      } else {
        const isCurrentSection = s.children.some((c) => location.pathname.startsWith(c.to))
        state[s.id] = !isCurrentSection
      }
    })
    return state
  })

  function toggleSection(id: string) {
    setCollapsed((prev) => ({ ...prev, [id]: !prev[id] }))
  }

  return (
    <aside className="app-sidebar">
      {/* Brand / Logo header */}
      <div className="sidebar-brand">
        <NavLink to={isOperator ? "/operator" : "/fleet"} className="brand-link">
          <div className="brand-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div className="brand-text">
            <span className="brand-name">Vexa Agent Control</span>
            <span className="brand-tag">{isOperator ? "Platform Management" : "SOC Console"}</span>
          </div>
        </NavLink>
      </div>

      {/* Top-level standalone Overview link */}
      <div className="sidebar-top-nav">
        {isOperator ? (
          <NavLink
            to="/operator"
            className={({ isActive }) => `sidebar-nav-item single-item ${isActive ? 'active' : ''}`}
          >
            <span className="item-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                <line x1="8" y1="21" x2="16" y2="21"/>
                <line x1="12" y1="17" x2="12" y2="21"/>
              </svg>
            </span>
            <span className="item-label">Platform Overview</span>
          </NavLink>
        ) : isEnforced ? (
          <div className="sidebar-nav-item single-item disabled" title="Complete Authentication Setup to unlock Fleet Overview">
            <span className="item-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </span>
            <span className="item-label">Fleet Overview</span>
            <span className="sidebar-lock-pill">Locked</span>
          </div>
        ) : (
          <NavLink
            to="/fleet"
            className={({ isActive }) => `sidebar-nav-item single-item ${isActive ? 'active' : ''}`}
          >
            <span className="item-icon">
              <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <rect x="3" y="3" width="7" height="7" />
                <rect x="14" y="3" width="7" height="7" />
                <rect x="14" y="14" width="7" height="7" />
                <rect x="3" y="14" width="7" height="7" />
              </svg>
            </span>
            <span className="item-label">Fleet Overview</span>
          </NavLink>
        )}
      </div>

      {/* Collapsible Section Groups */}
      <nav className="sidebar-nav-groups">
        {visibleSections.map((section) => {
          const isOpen = isEnforced && section.id === 'team' ? true : !collapsed[section.id]
          const isCurrentSection = section.children.some((c) => location.pathname.startsWith(c.to))
          return (
            <div key={section.id} className={`nav-section-group ${isCurrentSection ? 'has-active' : ''}`}>
              <button
                type="button"
                className={`section-header-btn ${isOpen ? 'open' : ''}`}
                onClick={() => toggleSection(section.id)}
              >
                <span className="section-icon">{section.icon}</span>
                <span className="section-label">{section.label}</span>
                <span className="section-arrow">
                  <ChevronIcon open={isOpen} />
                </span>
              </button>

              {isOpen && (
                <div className="section-children-list">
                  {section.children.map((child) => {
                    const isAuthProviders = child.to === '/admin/auth-providers'
                    const isChildDisabled = isEnforced && !isAuthProviders

                    if (isChildDisabled) {
                      return (
                        <div
                          key={child.to}
                          className="sidebar-nav-item child-item disabled"
                          title="Complete Authentication Setup to unlock"
                        >
                          <span className="child-dot child-dot-locked">🔒</span>
                          <span className="item-label">{child.label}</span>
                        </div>
                      )
                    }

                    return (
                      <NavLink
                        key={child.to}
                        to={child.to}
                        className={({ isActive }) => `sidebar-nav-item child-item ${isActive ? 'active' : ''} ${isAuthProviders && isEnforced ? 'action-required-pulse' : ''}`}
                      >
                        <span className="child-dot" />
                        <span className="item-label">{child.label}</span>
                        {isAuthProviders && isEnforced && (
                          <span className="sidebar-action-pill">Setup Required</span>
                        )}
                      </NavLink>
                    )
                  })}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      {/* Footer / Logout */}
      <div className="sidebar-footer">
        <button type="button" className="sidebar-logout-btn" onClick={onLogout} title="Sign Out">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          <span>Sign Out</span>
        </button>
      </div>
    </aside>
  )
}

function GlobalAuthBanner() {
  const { user, needsAuthProviderConfig } = useAuth()
  const location = useLocation()

  if (!needsAuthProviderConfig || user?.is_saas_operator || location.pathname.startsWith('/admin/auth-providers')) return null

  return (
    <div style={{
      background: 'rgba(234, 179, 8, 0.15)',
      border: '1px solid rgba(234, 179, 8, 0.3)',
      color: '#eab308',
      padding: '12px 16px',
      margin: '16px 24px 0 24px',
      borderRadius: '8px',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      fontSize: '13px'
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
        <span>
          <strong>Action Required:</strong> No Identity Providers are enabled. Local authentication or SSO must be configured to secure access.
        </span>
      </div>
      <NavLink 
        to="/admin/auth-providers" 
        style={{
          background: '#eab308',
          color: '#000',
          padding: '4px 12px',
          borderRadius: '4px',
          fontWeight: 600,
          textDecoration: 'none'
        }}
      >
        Configure SSO
      </NavLink>
    </div>
  )
}

function TopHeaderBar({ onOpenCommandPalette }: { onOpenCommandPalette: () => void }) {
  const { user, needsAuthProviderConfig } = useAuth()
  const isEnforced = needsAuthProviderConfig && !user?.is_saas_operator

  const roleLabel = user?.is_saas_operator
    ? 'Platform Super-Admin'
    : user?.is_admin
    ? 'Tenant Admin'
    : 'User'

  const roleClass = user?.is_saas_operator
    ? 'role-operator'
    : user?.is_admin
    ? 'role-tenant-admin'
    : 'role-user'

  const workspaceLabel = user?.is_saas_operator
    ? '🌐 Platform Management (Super-Admin)'
    : `🏢 ${user?.organization_name || 'Organization Workspace'}`

  return (
    <header className="top-header-bar">
      <div className="header-breadcrumbs">
        <span className="live-indicator-dot" title="Real-time SOC connection active" />
        <span className="header-env-tag">{workspaceLabel}</span>
        {isEnforced && (
          <span className="soc-locked-banner-pill">
            🔒 Initial Setup Required • Console Locked
          </span>
        )}
      </div>
      <div className="header-actions">
        <button
          type="button"
          className="header-cmd-btn"
          onClick={onOpenCommandPalette}
          title="Command Palette (Cmd+K)"
        >
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="11" cy="11" r="8" />
            <line x1="21" y1="21" x2="16.65" y2="16.65" />
          </svg>
          <span className="cmd-btn-label">Quick Search…</span>
          <kbd>Ctrl+K</kbd>
        </button>

        <NotificationCenter />

        {/* User Identity Profile Pill */}
        {user && (
          <div className="soc-user-profile-pill">
            <div className="soc-user-avatar">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2">
                <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                <circle cx="12" cy="7" r="4" />
              </svg>
            </div>
            <div className="soc-user-details">
              <span className="soc-user-email" title={user.id}>{user.id}</span>
              <span className={`soc-role-badge ${roleClass}`}>{roleLabel}</span>
            </div>
          </div>
        )}
      </div>
    </header>
  )
}

export default function App() {
  const { authenticated, logout, user, needsAuthProviderConfig, needsPasswordSetup } = useAuth()
  const [isCommandPaletteOpen, setIsCommandPaletteOpen] = useState(false)
  const isEnforced = needsAuthProviderConfig && !user?.is_saas_operator

  return (
    <>
      <SessionTimeoutModal />
      {authenticated && needsPasswordSetup && !user?.is_saas_operator && (
        <SetInitialPasswordModal />
      )}
      <CommandPalette
        isOpen={isCommandPaletteOpen}
        onClose={() => setIsCommandPaletteOpen(false)}
      />
      <Routes>
        <Route path="/login" element={authenticated ? (user?.is_saas_operator ? <Navigate to="/operator" replace /> : <Navigate to="/fleet" replace />) : <Login />} />

        <Route path="*" element={
          <RequireAuth>
            <div className="app-shell">
              <Sidebar
                onLogout={logout}
              />

              <div className="main-viewport-wrapper">
                <TopHeaderBar onOpenCommandPalette={() => setIsCommandPaletteOpen(true)} />
                <main className="main-content">
                  <GlobalAuthBanner />
                  {user?.is_saas_operator ? (
                    <Routes>
                      <Route path="/" element={<Navigate to="/operator" replace />} />
                      <Route path="/operator" element={<SaaSOperator />} />
                      <Route path="/operator/tenants" element={<SaaSOperator />} />
                      <Route path="/audit" element={<AuditLogs />} />
                      <Route path="*" element={<Navigate to="/operator" replace />} />
                    </Routes>
                  ) : isEnforced ? (
                    <Routes>
                      <Route path="/admin/auth-providers" element={<AuthProviders />} />
                      <Route path="*" element={<Navigate to="/admin/auth-providers" replace />} />
                    </Routes>
                  ) : (
                    <Routes>
                      <Route path="/" element={<Navigate to="/fleet" replace />} />
                      <Route path="/fleet" element={<FleetOverview />} />
                      <Route path="/identity" element={<IdentityGovernance />} />
                      <Route path="/policy" element={<Navigate to="/policy/edit" replace />} />
                      <Route path="/policy/insights" element={<PolicyInsights />} />
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
                      <Route path="*" element={<Navigate to="/fleet" replace />} />
                    </Routes>
                  )}
                </main>
              </div>
            </div>
          </RequireAuth>
        } />
      </Routes>
    </>
  )
}
