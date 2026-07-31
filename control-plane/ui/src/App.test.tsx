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

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
    ok: true,
    json: async () => ({}),
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
    expect(await screen.findByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Agent Identity')).toBeInTheDocument()
    expect(screen.getByText('Policy Management')).toBeInTheDocument()
    expect(screen.getByText('Observation & Routing')).toBeInTheDocument()
    expect(screen.getByText('User Management')).toBeInTheDocument()
    expect(screen.getByText('Ecosystem Integrations')).toBeInTheDocument()
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

  it('renders PolicyInsights at /policy', async () => {
    renderAt('/policy')
    expect(await screen.findByTestId('policy-insights')).toBeInTheDocument()
  })

  it('renders ThreatIntelligence at /threats', async () => {
    renderAt('/threats')
    expect(await screen.findByTestId('threat-intelligence')).toBeInTheDocument()
  })

  it('shows AgentWall logo', async () => {
    renderAt('/')
    expect(await screen.findByText(/Agentwall/i)).toBeInTheDocument()
  })
})
