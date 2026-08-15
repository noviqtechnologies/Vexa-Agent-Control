import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import App from './App'

vi.mock('./views/FleetOverview', () => ({
  default: () => <div data-testid="fleet-overview">FleetOverview</div>,
}))
vi.mock('./views/IdentityGovernance', () => ({
  default: () => <div data-testid="identity-governance">IdentityGovernance</div>,
}))
vi.mock('./views/PolicyInsights', () => ({
  default: () => <div data-testid="policy-insights">PolicyInsights</div>,
}))
vi.mock('./views/ThreatIntelligence', () => ({
  default: () => <div data-testid="threat-intelligence">ThreatIntelligence</div>,
}))
vi.mock('./views/SaaSOperator', () => ({
  default: () => <div data-testid="saas-operator">SaaSOperator</div>,
}))

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      user_id: 'admin',
      tenant_id: '00000000-0000-0000-0000-000000000001',
      is_admin: true,
      is_saas_operator: true,
    }),
  }))
})

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>
  )
}

describe('App routing', () => {
  it('renders accordion navigation items', async () => {
    renderAt('/')
    expect(await screen.findByText('Fleet Overview')).toBeInTheDocument()
    expect(screen.getByText('Team & Fleet')).toBeInTheDocument()
    expect(screen.getByText('Policies & Security')).toBeInTheDocument()
    expect(screen.getByText('Spend & Budgets')).toBeInTheDocument()
    expect(screen.getByText('Integrations & Keys')).toBeInTheDocument()
  })

  it('redirects / to /fleet', async () => {
    renderAt('/')
    expect(await screen.findByTestId('fleet-overview')).toBeInTheDocument()
  })

  it('renders FleetOverview at /fleet', async () => {
    renderAt('/fleet')
    expect(await screen.findByTestId('fleet-overview')).toBeInTheDocument()
  })

  it('renders IdentityGovernance at /identity', async () => {
    renderAt('/identity')
    expect(await screen.findByTestId('identity-governance')).toBeInTheDocument()
  })

  it('renders SaaSOperator at /operator/tenants', async () => {
    renderAt('/operator/tenants')
    expect(await screen.findByTestId('saas-operator')).toBeInTheDocument()
  })
})
