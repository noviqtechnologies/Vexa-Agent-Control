import { describe, it, expect, vi } from 'vitest'
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

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider config={null}>
        <App />
      </AuthProvider>
    </MemoryRouter>
  )
}

describe('App routing', () => {
  it('renders four nav links', () => {
    renderAt('/')
    expect(screen.getByText('Fleet Overview')).toBeInTheDocument()
    expect(screen.getByText('Identity Governance')).toBeInTheDocument()
    expect(screen.getByText('Policy Insights')).toBeInTheDocument()
    expect(screen.getByText('Threat Intelligence')).toBeInTheDocument()
  })

  it('redirects / to /fleet', () => {
    renderAt('/')
    expect(screen.getByTestId('fleet-overview')).toBeInTheDocument()
  })

  it('renders FleetOverview at /fleet', () => {
    renderAt('/fleet')
    expect(screen.getByTestId('fleet-overview')).toBeInTheDocument()
  })

  it('renders IdentityGovernance at /identity', () => {
    renderAt('/identity')
    expect(screen.getByTestId('identity-governance')).toBeInTheDocument()
  })

  it('renders PolicyInsights at /policy', () => {
    renderAt('/policy')
    expect(screen.getByTestId('policy-insights')).toBeInTheDocument()
  })

  it('renders ThreatIntelligence at /threats', () => {
    renderAt('/threats')
    expect(screen.getByTestId('threat-intelligence')).toBeInTheDocument()
  })

  it('shows AgentWall logo', () => {
    renderAt('/')
    expect(screen.getByText(/Agent/)).toBeInTheDocument()
  })
})
