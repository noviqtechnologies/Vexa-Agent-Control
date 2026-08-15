import { render, screen, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import PolicyMarketplace from './PolicyMarketplace'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    listTemplates: vi.fn(),
    savePolicy: vi.fn(),
    createCustomTemplate: vi.fn(),
  },
}))

describe('PolicyMarketplace', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.listTemplates).mockResolvedValue([
      {
        id: 'safe-cursor',
        name: 'Safe Cursor Workstation',
        category: 'Developer Security',
        description: 'Blocks rm -rf and sensitive .env reads.',
        tags: ['IDE', 'Cursor'],
        icon: 'shield-check',
        content: 'version: "2.1"',
        is_custom: false,
        created_at: '2026-08-11T00:00:00Z',
        updated_at: '2026-08-11T00:00:00Z',
      },
      {
        id: 'hipaa-compliance',
        name: 'HIPAA & Medical PII Protection',
        category: 'Healthcare & Compliance',
        description: 'Auto-redacts PHI, SSNs, and medical records.',
        tags: ['HIPAA', 'DLP'],
        icon: 'heart-pulse',
        content: 'version: "2.1"',
        is_custom: false,
        created_at: '2026-08-11T00:00:00Z',
        updated_at: '2026-08-11T00:00:00Z',
      },
    ])
  })

  it('renders Policy Marketplace title and templates', async () => {
    render(
      <MemoryRouter>
        <PolicyMarketplace />
      </MemoryRouter>
    )

    expect(screen.getByText('Policy Marketplace')).toBeInTheDocument()

    await waitFor(() => {
      expect(screen.getByText('Safe Cursor Workstation')).toBeInTheDocument()
      expect(screen.getByText('HIPAA & Medical PII Protection')).toBeInTheDocument()
    })
  })

  it('filters templates when searching', async () => {
    render(
      <MemoryRouter>
        <PolicyMarketplace />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Safe Cursor Workstation')).toBeInTheDocument()
    })

    const searchInput = screen.getByPlaceholderText(/Search templates by posture/i)
    const userEvent = (await import('@testing-library/user-event')).default.setup()
    await userEvent.type(searchInput, 'HIPAA')

    expect(screen.queryByText('Safe Cursor Workstation')).not.toBeInTheDocument()
    expect(screen.getByText('HIPAA & Medical PII Protection')).toBeInTheDocument()
  })
})
