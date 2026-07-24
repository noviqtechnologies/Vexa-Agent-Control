import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import PolicyInsights from './PolicyInsights'
import type { PolicyStatus, PolicySuggestion } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      getPolicyStatus: vi.fn(),
      getPolicySuggestions: vi.fn(),
    },
  }
})

import { api } from '../api/client'

const mockStatus: PolicyStatus = {
  enabled: true,
  decay_window_days: 30,
  tools: [
    { name: 'bash', confidence_decay: 0.95, last_seen: Date.now() * 1_000_000, stale: false },
    { name: 'http_request', confidence_decay: 0.3, last_seen: (Date.now() - 86400_000 * 20) * 1_000_000, stale: false },
    { name: 'old_tool', confidence_decay: 0.0, last_seen: (Date.now() - 86400_000 * 60) * 1_000_000, stale: true },
  ],
  pending_suggestions: [],
}

const mockSuggestions: PolicySuggestion[] = [
  {
    tool: 'bash',
    field: 'command',
    old_value: 'baseline',
    new_value: 'rm -rf /',
    anomaly_score: 0.98,
    timestamp_ns: Date.now() * 1_000_000,
    suggested_action: 'Review potential baseline deviation',
  },
  {
    tool: 'http_request',
    field: 'url',
    old_value: 'baseline',
    new_value: 'https://suspicious.example.com',
    anomaly_score: 0.85,
    timestamp_ns: Date.now() * 1_000_000,
    suggested_action: 'Review potential baseline deviation',
  },
]

beforeEach(() => {
  vi.clearAllMocks()
})

function renderView() {
  return render(
    <MemoryRouter>
      <PolicyInsights />
    </MemoryRouter>
  )
}

describe('PolicyInsights', () => {
  it('shows loading state', () => {
    vi.mocked(api.getPolicyStatus).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.getPolicySuggestions).mockReturnValue(new Promise(() => {}))

    renderView()
    expect(screen.getByText('Loading policy data')).toBeInTheDocument()
  })

  it('shows error state when gateway is unreachable', async () => {
    vi.mocked(api.getPolicyStatus).mockRejectedValue(new Error('API 502: bad gateway'))
    vi.mocked(api.getPolicySuggestions).mockRejectedValue(new Error('API 502'))

    renderView()

    await waitFor(() => {
      expect(screen.getByText(/Unable to reach the gateway/)).toBeInTheDocument()
    })
  })

  it('renders stat tiles after data loads', async () => {
    vi.mocked(api.getPolicyStatus).mockResolvedValue(mockStatus)
    vi.mocked(api.getPolicySuggestions).mockResolvedValue(mockSuggestions)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('Engine Status')).toBeInTheDocument()
    })
    // "Active" appears in both the stat tile and the engine config card.
    expect(screen.getAllByText('Active').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Monitored Tools')).toBeInTheDocument()
    // "Stale Tools" appears in both stat tile and engine config card.
    expect(screen.getAllByText('Stale Tools').length).toBe(2)
    expect(screen.getByText('Pending Suggestions')).toBeInTheDocument()
  })

  it('renders tool confidence table', async () => {
    vi.mocked(api.getPolicyStatus).mockResolvedValue(mockStatus)
    vi.mocked(api.getPolicySuggestions).mockResolvedValue([])

    renderView()

    await waitFor(() => {
      expect(screen.getByText('bash')).toBeInTheDocument()
    })
    expect(screen.getByText('http_request')).toBeInTheDocument()
    expect(screen.getByText('old_tool')).toBeInTheDocument()

    expect(screen.getByText('High')).toBeInTheDocument()
    // http_request (0.3) and old_tool (0.0) both show "Low".
    expect(screen.getAllByText('Low').length).toBe(2)
  })

  it('renders engine configuration card', async () => {
    vi.mocked(api.getPolicyStatus).mockResolvedValue(mockStatus)
    vi.mocked(api.getPolicySuggestions).mockResolvedValue([])

    renderView()

    await waitFor(() => {
      expect(screen.getByText('Engine Configuration')).toBeInTheDocument()
    })
    expect(screen.getByText('30 days')).toBeInTheDocument()
  })

  it('shows high anomaly alert banner for scores above 95%', async () => {
    vi.mocked(api.getPolicyStatus).mockResolvedValue(mockStatus)
    vi.mocked(api.getPolicySuggestions).mockResolvedValue(mockSuggestions)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('High Anomaly Alerts')).toBeInTheDocument()
    })
    expect(screen.getByText(/1 suggestion with anomaly score above 95%/)).toBeInTheDocument()
  })

  it('renders suggestions table', async () => {
    vi.mocked(api.getPolicyStatus).mockResolvedValue(mockStatus)
    vi.mocked(api.getPolicySuggestions).mockResolvedValue(mockSuggestions)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('rm -rf /')).toBeInTheDocument()
    })
    expect(screen.getByText('98.0%')).toBeInTheDocument()
    expect(screen.getByText('85.0%')).toBeInTheDocument()
  })

  it('shows clean baseline message when no suggestions', async () => {
    vi.mocked(api.getPolicyStatus).mockResolvedValue(mockStatus)
    vi.mocked(api.getPolicySuggestions).mockResolvedValue([])

    renderView()

    await waitFor(() => {
      expect(screen.getByText(/baseline is clean/)).toBeInTheDocument()
    })
  })

  it('refresh button reloads data', async () => {
    vi.mocked(api.getPolicyStatus).mockResolvedValue(mockStatus)
    vi.mocked(api.getPolicySuggestions).mockResolvedValue([])

    renderView()

    await waitFor(() => {
      expect(screen.getByText('Refresh')).toBeInTheDocument()
    })

    vi.mocked(api.getPolicyStatus).mockResolvedValue({ ...mockStatus, decay_window_days: 60 })
    vi.mocked(api.getPolicySuggestions).mockResolvedValue([])

    const user = userEvent.setup()
    await user.click(screen.getByText('Refresh'))

    await waitFor(() => {
      expect(screen.getByText('60 days')).toBeInTheDocument()
    })
    expect(api.getPolicyStatus).toHaveBeenCalledTimes(2)
  })
})
