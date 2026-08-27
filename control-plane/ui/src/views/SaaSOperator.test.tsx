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
      expect(screen.getByText('slug: acme-health')).toBeDefined()
      expect(screen.getByText(/admin@acme\.com/i)).toBeDefined()
      expect(screen.getByText('15d Free Trial')).toBeDefined()
      expect(screen.getByText('14 days left')).toBeDefined()
    })
  })

  it('handles HTML 403 error cleanly without displaying raw HTML markup', async () => {
    const { fireEvent } = await import('@testing-library/react')
    
    vi.stubGlobal('fetch', vi.fn((url: string, opts?: any) => {
      if (url === '/api/v1/operator/organizations' && opts?.method === 'POST') {
        return Promise.resolve({
          ok: false,
          status: 403,
          statusText: 'Forbidden',
          text: () => Promise.resolve('<!doctype html> <meta charset="utf-8"> <title>403</title> 403 Forbidden')
        })
      }
      if (url === '/api/v1/operator/organizations') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([])
        })
      }
      if (url === '/api/v1/operator/stats') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({ total_organizations: 0, active_trials: 0, expiring_within_7d: 0, total_seats: 0 })
        })
      }
      return Promise.reject(new Error('Unknown URL'))
    }))

    render(<SaaSOperator />)
    
    const onboardBtn = screen.getByRole('button', { name: /Onboard Organization/i })
    fireEvent.click(onboardBtn)

    expect(screen.getByText('Onboard New Organization')).toBeDefined()

    const nameInput = screen.getByPlaceholderText('e.g. Acme Corp')
    const emailInput = screen.getByPlaceholderText('admin@acmecorp.com')
    const submitBtn = screen.getByRole('button', { name: /Provision Organization/i })

    fireEvent.change(nameInput, { target: { value: 'Acme Corp' } })
    fireEvent.change(emailInput, { target: { value: 'admin@acmecorp.com' } })
    fireEvent.click(submitBtn)

    await waitFor(() => {
      expect(screen.getByText(/Access Denied \(HTTP 403 Forbidden\)/i)).toBeDefined()
    })
  })
})
