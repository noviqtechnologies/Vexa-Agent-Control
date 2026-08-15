import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import SaaSOperator from './SaaSOperator'

describe('SaaSOperator View', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url === '/api/v1/operator/organizations') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            {
              id: 'org-123',
              name: 'Acme Health',
              slug: 'acme-health',
              contact_email: 'admin@acme.com',
              license_tier: 'enterprise',
              max_seats: 50,
              is_trial: true,
              trial_days: 15,
              days_remaining: 14,
              status: 'ACTIVE',
              created_at: new Date().toISOString(),
              has_bootstrap: false
            }
          ])
        })
      }
      if (url === '/api/v1/operator/stats') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            total_organizations: 1,
            active_trials: 1,
            expiring_within_7d: 0,
            total_seats: 50
          })
        })
      }
      return Promise.reject(new Error('Unknown URL'))
    }))
  })

  it('renders KPI headers and organization directory table', async () => {
    render(<SaaSOperator />)

    expect(screen.getByText(/Platform Operations & Tenant Onboarding/i)).toBeDefined()
    expect(screen.getByText(/Onboard Organization/i)).toBeDefined()

    await waitFor(() => {
      expect(screen.getByText('Acme Health')).toBeDefined()
      expect(screen.getByText('acme-health.vexasec.io')).toBeDefined()
      expect(screen.getByText('15d Free Trial')).toBeDefined()
      expect(screen.getByText('14 days left')).toBeDefined()
    })
  })
})
