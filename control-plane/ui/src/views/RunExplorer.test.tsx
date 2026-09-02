import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import RunExplorer from './RunExplorer'
import type { RunSummary, RunDossier } from '../api/client'

const mockRuns: RunSummary[] = [
  {
    run_id: 'res-test-12345678',
    request_id: 'req-test-1',
    device_id: 'win-dev-1',
    project_id: 'default',
    provider: 'openai',
    model: 'gpt-4o',
    state: 'SETTLED',
    reserved_microcents: 100000000,
    settled_microcents: 75000000,
    started_at: new Date().toISOString(),
    duration_ms: 1250,
  },
]

const mockDossier: RunDossier = {
  run_id: 'res-test-12345678',
  request_id: 'req-test-1',
  identity: {
    device_id: 'win-dev-1',
    device_hostname: 'win-dev-1',
    device_compliance: 'COMPLIANT',
    project_id: 'default',
  },
  policy: {
    snapshot: { limit_microcents: 10000000000, action: 'hard_deny' },
    price_book_version_id: 'price-book-v1',
  },
  dispatch: {
    provider: 'openai',
    model: 'gpt-4o',
  },
  economics: {
    reserved_microcents: 100000000,
    settled_microcents: 75000000,
    released_microcents: 25000000,
    currency: 'USD',
    events: [],
  },
  outcome: {
    state: 'SETTLED',
    started_at: new Date().toISOString(),
    duration_ms: 1250,
  },
  provenance: {
    data_freshness: new Date().toISOString(),
    evidence_source: 'postgresql_spend_reservations',
    confidence: 'observed',
  },
}

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      listRuns: vi.fn(),
      getRunDossier: vi.fn(),
    },
  }
})

import { api } from '../api/client'

beforeEach(() => {
  vi.clearAllMocks()
})

function renderView(initialEntries = ['/runs']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <RunExplorer />
    </MemoryRouter>
  )
}

describe('RunExplorer View', () => {
  it('shows loading state initially', () => {
    vi.mocked(api.listRuns).mockReturnValue(new Promise(() => {}))
    renderView()
    expect(screen.getByText('Loading run telemetry...')).toBeInTheDocument()
  })

  it('renders runs table with correct metrics after data loads', async () => {
    vi.mocked(api.listRuns).mockResolvedValue({
      organization_id: 'tenant-1',
      runs: mockRuns,
      data_freshness: new Date().toISOString(),
      confidence: 'observed',
    })

    renderView()

    await waitFor(() => {
      expect(screen.getByText('OPENAI')).toBeInTheDocument()
    })

    expect(screen.getByText('gpt-4o')).toBeInTheDocument()
    expect(screen.getAllByText('SETTLED').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText(/Confidence:/i)).toBeInTheDocument()
    expect(screen.getByText('observed')).toBeInTheDocument()
  })

  it('filters runs when changing provider or state', async () => {
    vi.mocked(api.listRuns).mockResolvedValue({
      organization_id: 'tenant-1',
      runs: mockRuns,
      data_freshness: new Date().toISOString(),
      confidence: 'observed',
    })

    renderView()

    await waitFor(() => {
      expect(screen.getByText('OPENAI')).toBeInTheDocument()
    })

    const providerSelect = screen.getByLabelText('Provider Filter')
    fireEvent.change(providerSelect, { target: { value: 'anthropic' } })

    await waitFor(() => {
      expect(api.listRuns).toHaveBeenCalledWith(expect.objectContaining({ provider: 'anthropic' }))
    })
  })

  it('opens dossier drawer on row click', async () => {
    vi.mocked(api.listRuns).mockResolvedValue({
      organization_id: 'tenant-1',
      runs: mockRuns,
      data_freshness: new Date().toISOString(),
      confidence: 'observed',
    })
    vi.mocked(api.getRunDossier).mockResolvedValue(mockDossier)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('OPENAI')).toBeInTheDocument()
    })

    const row = screen.getByText('OPENAI').closest('tr')!
    fireEvent.click(row)

    await waitFor(() => {
      expect(screen.getByText('Run Dossier')).toBeInTheDocument()
    })

    expect(screen.getByText('RESERVED (HOLD)')).toBeInTheDocument()
    expect(screen.getByText('SETTLED (ACTUAL)')).toBeInTheDocument()
    expect(screen.getByText('NET BILLED SPEND')).toBeInTheDocument()
  })
})
