import { render, screen, waitFor, fireEvent } from '@testing-library/react'
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
        id: 'au-adv-pii',
        name: 'Advanced PII Protection (Australia)',
        category: 'PII Protection',
        categories: ['Australia', 'PII Protection', 'Regulatory'],
        complexity: 'High Complexity',
        description: 'Protects Australian-specific identifiers and credentials.',
        tags: ['Australia', 'TFN', 'Medicare'],
        guardrails: ['au-pii-tax-identifiers', 'au-pii-passports'],
        icon: 'shield',
        content: 'version: "2"\ndefault_action: deny',
        is_custom: false,
        created_at: '2026-08-11T00:00:00Z',
        updated_at: '2026-08-11T00:00:00Z',
      },
      {
        id: 'safe-cursor',
        name: 'Safe Cursor Workstation',
        category: 'Developer Security',
        categories: ['Developer Security', 'Security'],
        complexity: 'Medium Complexity',
        description: 'Blocks rm -rf and sensitive .env reads.',
        tags: ['IDE', 'Cursor'],
        guardrails: ['shell-destructive-blocks', 'filesystem-secret-shield'],
        icon: 'shield-check',
        content: 'version: "2"\ndefault_action: deny',
        is_custom: false,
        created_at: '2026-08-11T00:00:00Z',
        updated_at: '2026-08-11T00:00:00Z',
      },
      {
        id: 'hipaa-compliance',
        name: 'HIPAA & Medical PII Protection',
        category: 'Healthcare',
        categories: ['Healthcare', 'PII Protection', 'Regulatory'],
        complexity: 'High Complexity',
        description: 'Auto-redacts PHI, SSNs, and medical records.',
        tags: ['HIPAA', 'DLP'],
        guardrails: ['healthcare-phi-redactor', 'mrn-identifier-block'],
        icon: 'heart-pulse',
        content: 'version: "2"\ndefault_action: deny',
        is_custom: false,
        created_at: '2026-08-11T00:00:00Z',
        updated_at: '2026-08-11T00:00:00Z',
      },
    ])
  })

  it('renders Policy Templates title, category sidebar, and templates with guardrails', async () => {
    render(
      <MemoryRouter>
        <PolicyMarketplace />
      </MemoryRouter>
    )

    expect(screen.getByText('Policy Templates')).toBeInTheDocument()
    expect(screen.getByText('Categories')).toBeInTheDocument()
    expect(screen.getByText('✨ Use AI to find templates')).toBeInTheDocument()

    await waitFor(() => {
      expect(screen.getByText('Advanced PII Protection (Australia)')).toBeInTheDocument()
      expect(screen.getByText('Safe Cursor Workstation')).toBeInTheDocument()
      expect(screen.getByText('HIPAA & Medical PII Protection')).toBeInTheDocument()
    })

    // Check guardrails pills render
    expect(screen.getAllByText('au-pii-tax-identifiers').length).toBeGreaterThan(0)
    expect(screen.getAllByText('shell-destructive-blocks').length).toBeGreaterThan(0)
  })

  it('filters templates when searching by keyword or guardrail', async () => {
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

  it('filters templates by category sidebar checkbox', async () => {
    render(
      <MemoryRouter>
        <PolicyMarketplace />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Safe Cursor Workstation')).toBeInTheDocument()
    })

    const auCheckboxLabel = document.getElementById('cat-checkbox-australia')!
    fireEvent.click(auCheckboxLabel)

    await waitFor(() => {
      expect(screen.getByText('Advanced PII Protection (Australia)')).toBeInTheDocument()
      expect(screen.queryByText('Safe Cursor Workstation')).not.toBeInTheDocument()
    })
  })

  it('filters templates by complexity level button', async () => {
    render(
      <MemoryRouter>
        <PolicyMarketplace />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Safe Cursor Workstation')).toBeInTheDocument()
      expect(screen.getByText('HIPAA & Medical PII Protection')).toBeInTheDocument()
    })

    const mediumBtn = screen.getByRole('button', { name: /Medium Complexity/i })
    fireEvent.click(mediumBtn)

    await waitFor(() => {
      expect(screen.getByText('Safe Cursor Workstation')).toBeInTheDocument()
      expect(screen.queryByText('HIPAA & Medical PII Protection')).not.toBeInTheDocument()
    })
  })

  it('opens Use Template modal and deploys active posture', async () => {
    vi.mocked(api.savePolicy).mockResolvedValue({
      id: 'p-1',
      version: 'v-au-adv-pii-1234',
      content: 'version: "2"',
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })

    render(
      <MemoryRouter>
        <PolicyMarketplace />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Advanced PII Protection (Australia)')).toBeInTheDocument()
    })

    const useTemplateBtns = await screen.findAllByRole('button', { name: /Use Template/i })
    fireEvent.click(useTemplateBtns[0])

    await waitFor(() => {
      expect(screen.getByText('🚀 Apply Immediately to Active Fleet')).toBeInTheDocument()
    })

    const deployBtn = screen.getByRole('button', { name: /Deploy Active Posture/i })
    fireEvent.click(deployBtn)

    await waitFor(() => {
      expect(api.savePolicy).toHaveBeenCalled()
      expect(screen.getByText(/Successfully applied/i)).toBeInTheDocument()
    })
  })

  it('opens AI Template Finder modal and runs recommendation', async () => {
    render(
      <MemoryRouter>
        <PolicyMarketplace />
      </MemoryRouter>
    )

    const aiBtn = screen.getByRole('button', { name: /✨ Use AI to find templates/i })
    fireEvent.click(aiBtn)

    expect(await screen.findByText('AI Policy Template Finder')).toBeInTheDocument()

    // Click quick prompt inside the modal
    const quickPrompt = await screen.findByRole('button', { name: /Australia TFN & Banking/i })
    fireEvent.click(quickPrompt)

    expect(await screen.findByText(/Top Recommended Postures:/i)).toBeInTheDocument()
    expect(screen.getAllByText(/% Match/i).length).toBeGreaterThan(0)
  })
})
