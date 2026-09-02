import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import LicenseSettings from './LicenseSettings'

describe('Organization & License View', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url === '/api/v1/organization') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            id: 'org-123',
            name: 'Acme Health',
            slug: 'acme-health',
            contact_email: 'admin@acme.com',
            license_tier: 'enterprise',
            max_devices: 50,
            enrolled_devices: 12,
            days_remaining: 14,
            status: 'active',
            created_at: new Date().toISOString(),
          })
        })
      }
      return Promise.reject(new Error('Unknown URL: ' + url))
    }))
  })

  it('renders KPI headers and organization profile', async () => {
    render(<LicenseSettings />)

    await waitFor(() => {
      expect(screen.getByText('Organization & License')).toBeDefined()
      expect(screen.getByText('Acme Health')).toBeDefined()
      expect(screen.getByText('acme-health')).toBeDefined()
      expect(screen.getByText('admin@acme.com')).toBeDefined()
      expect(screen.getByText('enterprise')).toBeDefined()
      expect(screen.getByText('12 / 50')).toBeDefined()
    })
  })
})
