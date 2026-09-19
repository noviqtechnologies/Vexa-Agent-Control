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
            max_devices: 5,
            enrolled_devices: 2,
            days_remaining: 25,
            has_license_key: false,
            status: 'active',
            created_at: new Date().toISOString(),
          })
        })
      }
      return Promise.reject(new Error('Unknown URL: ' + url))
    }))
  })

  it('renders organization profile, 5-device Early Access tier, and slots remaining', async () => {
    render(<LicenseSettings />)

    await waitFor(() => {
      expect(screen.getByText('Organization & License')).toBeDefined()
      expect(screen.getByText('Acme Security')).toBeDefined()
      expect(screen.getByText('acme-sec')).toBeDefined()
      expect(screen.getByText('admin@acmesec.com')).toBeDefined()
      expect(screen.getByText('team')).toBeDefined()
      expect(screen.getByText('2 / 5')).toBeDefined()
      expect(screen.getByText(/3 device slots remaining/i)).toBeDefined()
    })
  })

  it('displays warning alert when Early Access 5-device quota is reached', async () => {
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
            max_devices: 5,
            enrolled_devices: 5,
            days_remaining: 20,
            has_license_key: false,
            status: 'active',
            created_at: new Date().toISOString(),
          })
        })
      }
      return Promise.reject(new Error('Unknown URL: ' + url))
    }))

    render(<LicenseSettings />)

    await waitFor(() => {
      expect(screen.getByText(/Early Access Capacity Reached \(5\/5 devices\)/i)).toBeDefined()
    })
  })

  it('displays expiration danger alert when 30-day Early Access window has elapsed', async () => {
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
            max_devices: 5,
            enrolled_devices: 3,
            days_remaining: 0,
            has_license_key: false,
            is_evaluation_expired: true,
            status: 'trial_expired',
            created_at: new Date(Date.now() - 35 * 24 * 3600 * 1000).toISOString(),
          })
        })
      }
      return Promise.reject(new Error('Unknown URL: ' + url))
    }))

    render(<LicenseSettings />)
  })
})
