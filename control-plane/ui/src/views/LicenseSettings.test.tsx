import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import LicenseSettings from './LicenseSettings'

describe('LicenseSettings View', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url === '/api/v1/organization') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({
            id: '00000000-0000-0000-0000-000000000001',
            name: 'Acme Security',
            slug: 'acme-sec',
            contact_email: 'admin@acmesec.com',
            license_tier: 'team',
            max_devices: 25,
            enrolled_devices: 5,
            days_remaining: 300,
            status: 'active',
            created_at: new Date().toISOString(),
          })
        })
      }
      return Promise.reject(new Error('Unknown URL: ' + url))
    }))
  })

  it('renders organization profile and license tier card', async () => {
    render(<LicenseSettings />)

    await waitFor(() => {
      expect(screen.getByText('Organization & License')).toBeDefined()
      expect(screen.getByText('Acme Security')).toBeDefined()
      expect(screen.getByText('acme-sec')).toBeDefined()
      expect(screen.getByText('admin@acmesec.com')).toBeDefined()
      expect(screen.getByText('team')).toBeDefined()
      expect(screen.getByText('5 / 25')).toBeDefined()
      expect(screen.getByText(/20 device slots remaining/i)).toBeDefined()
    })
  })
})
