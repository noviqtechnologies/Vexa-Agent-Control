import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import VirtualKeys from './VirtualKeys'
import { api, type VirtualKey } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    listVirtualKeys: vi.fn(),
    createVirtualKey: vi.fn(),
    deleteVirtualKey: vi.fn(),
    rotateVirtualKey: vi.fn(),
    resetVirtualKeySpend: vi.fn(),
  },
}))

const mockKeys: VirtualKey[] = [
  {
    id: 'vk-1',
    tenant_id: 'tenant-1',
    key_prefix: 'sk-vex-abc123...',
    name: 'Cursor Team Lead',
    team_id: 'frontend-eng',
    created_by: 'admin',
    created_at: '2026-08-30T10:00:00Z',
    allowed_ips: ['10.0.0.0/8'],
    max_rpm: 60,
    max_tpm: 100000,
    max_concurrent_requests: 10,
    monthly_budget_microcents: 50_00000000, // $50.00
    spent_microcents: 12_50000000,         // $12.50
    allowed_models: ['claude-3-5-sonnet*', 'gpt-4o'],
    allowed_routes: ['/v1/chat/completions'],
    status: 'active',
  },
  {
    id: 'vk-2',
    tenant_id: 'tenant-1',
    key_prefix: 'sk-vex-xyz789...',
    name: 'CI Batch Runner',
    team_id: 'devops',
    created_by: 'admin',
    created_at: '2026-08-30T11:00:00Z',
    allowed_ips: [],
    max_rpm: 120,
    max_tpm: 200000,
    max_concurrent_requests: 20,
    monthly_budget_microcents: 100_00000000, // $100.00
    spent_microcents: 95_00000000,          // $95.00
    allowed_models: ['gpt-4o-mini'],
    allowed_routes: [],
    status: 'rotating',
  }
]

describe('VirtualKeys View', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.listVirtualKeys).mockResolvedValue({ virtual_keys: mockKeys })
  })

  it('renders Virtual Keys view, KPI summary, and active keys table', async () => {
    render(
      <MemoryRouter>
        <VirtualKeys />
      </MemoryRouter>
    )

    expect(screen.getByText('Scoped Virtual Keys')).toBeInTheDocument()
    expect(screen.getByText('Issue Virtual Key')).toBeInTheDocument()

    await waitFor(() => {
      expect(screen.getByText('Cursor Team Lead')).toBeInTheDocument()
      expect(screen.getByText('CI Batch Runner')).toBeInTheDocument()
      expect(screen.getByText('sk-vex-abc123...')).toBeInTheDocument()
      expect(screen.getByText('sk-vex-xyz789...')).toBeInTheDocument()
      expect(screen.getByText('Active Virtual Keys')).toBeInTheDocument()
    })
  })

  it('filters keys by search query', async () => {
    render(
      <MemoryRouter>
        <VirtualKeys />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Cursor Team Lead')).toBeInTheDocument()
      expect(screen.getByText('CI Batch Runner')).toBeInTheDocument()
    })

    const searchInput = screen.getByPlaceholderText(/Search by key name/i)
    fireEvent.change(searchInput, { target: { value: 'devops' } })

    expect(screen.queryByText('Cursor Team Lead')).not.toBeInTheDocument()
    expect(screen.getByText('CI Batch Runner')).toBeInTheDocument()
  })

  it('opens create modal and generates a new scoped virtual key', async () => {
    vi.mocked(api.createVirtualKey).mockResolvedValue({
      virtual_key: {
        id: 'vk-3',
        tenant_id: 'tenant-1',
        key_prefix: 'sk-vex-new123...',
        name: 'New Release Agent',
        team_id: 'release-team',
        created_by: 'admin',
        created_at: new Date().toISOString(),
        allowed_ips: [],
        max_rpm: 30,
        max_tpm: 50000,
        max_concurrent_requests: 5,
        monthly_budget_microcents: 25_00000000,
        spent_microcents: 0,
        allowed_models: ['gpt-4o'],
        allowed_routes: [],
        status: 'active',
      },
      raw_secret: 'sk-vex-secret-token-abcdef123456',
    })

    render(
      <MemoryRouter>
        <VirtualKeys />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Cursor Team Lead')).toBeInTheDocument()
    })

    // Open modal
    fireEvent.click(screen.getByRole('button', { name: /Issue Virtual Key/i }))
    expect(screen.getByText('Issue Scoped Virtual Key')).toBeInTheDocument()

    // Fill form
    const nameInput = screen.getByPlaceholderText(/e.g. cursor-ide-team/i)
    fireEvent.change(nameInput, { target: { value: 'New Release Agent' } })

    // Submit
    fireEvent.click(screen.getByRole('button', { name: /Generate Virtual Key/i }))

    await waitFor(() => {
      expect(api.createVirtualKey).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'New Release Agent',
        })
      )
      // Secret reveal modal appears
      expect(screen.getByText('Virtual Key Secret Generated')).toBeInTheDocument()
      expect(screen.getByText('sk-vex-secret-token-abcdef123456')).toBeInTheDocument()
    })
  })

  it('creates virtual key with custom persona and budget cadence', async () => {
    vi.mocked(api.createVirtualKey).mockResolvedValue({
      virtual_key: {
        id: 'vk-agent-1',
        tenant_id: 'tenant-1',
        key_prefix: 'sk-vex-agent...',
        name: 'Devin Autonomous Agent',
        team_id: 'ai-lab',
        created_by: 'admin',
        created_at: new Date().toISOString(),
        allowed_ips: [],
        max_rpm: 30,
        max_tpm: 50000,
        max_concurrent_requests: 5,
        monthly_budget_microcents: 25_00000000,
        spent_microcents: 0,
        allowed_models: ['gpt-4o'],
        allowed_routes: [],
        status: 'active',
        owner_type: 'agent',
        budget_period: 'daily',
      },
      raw_secret: 'sk-vex-secret-agent-xyz',
    })

    render(
      <MemoryRouter>
        <VirtualKeys />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Cursor Team Lead')).toBeInTheDocument()
    })

    // Open modal
    fireEvent.click(screen.getByRole('button', { name: /Issue Virtual Key/i }))

    // Select Agent persona
    fireEvent.click(screen.getByLabelText(/Autonomous AI Agent/i))

    // Select Daily cadence
    const cadenceSelect = screen.getByLabelText('Budget Cadence')
    fireEvent.change(cadenceSelect, { target: { value: 'daily' } })

    // Fill name
    const nameInput = screen.getByPlaceholderText(/e.g. cursor-ide-team/i)
    fireEvent.change(nameInput, { target: { value: 'Devin Autonomous Agent' } })

    // Submit
    fireEvent.click(screen.getByRole('button', { name: /Generate Virtual Key/i }))

    await waitFor(() => {
      expect(api.createVirtualKey).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'Devin Autonomous Agent',
          owner_type: 'agent',
          budget_period: 'daily',
        })
      )
    })
  })
})
