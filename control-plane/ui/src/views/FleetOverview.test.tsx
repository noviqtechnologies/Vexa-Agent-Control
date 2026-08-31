import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import FleetOverview from './FleetOverview'
import type { FleetStats, AgentSummary, DecisionBreakdown, RedactedAlert } from '../api/client'

const mockStats: FleetStats = {
  total_agents: 5,
  active_agents: 3,
  total_events: 200,
  denied_events: 15,
  total_alerts: 8,
  critical_alerts: 2,
}

const mockAgents: AgentSummary[] = [
  {
    agent_id: 'agent-alpha',
    display_name: null,
    status: 'active',
    policy_version: 'v1',
    last_seen_at: new Date().toISOString(),
    event_count: 42,
    alert_count: 1,
  },
]

const mockHeatmap: DecisionBreakdown[] = [
  { hour: '2026-07-24 14:00', allowed: 10, denied: 2, warned: 1 },
]

const mockAlerts: RedactedAlert[] = [
  {
    alert_id: 'alert-1',
    severity: 'critical',
    event: {
      event_id: 'evt-1',
      timestamp_ms: Date.now(),
      session_id: 'sess-1',
      agent_id: 'agent-alpha',
      tool_name: 'bash',
      decision: 'denied',
      dlp_findings: [{ category: 'api_key', pattern_name: 'AWS Key', count: 1 }],
      injection_findings: [],
      semantic_findings: [],
    },
  },
]

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      getFleetOverview: vi.fn(),
      listAgents: vi.fn(),
      getHeatmap: vi.fn(),
      listRecentAlerts: vi.fn(),
      getLicenseStatus: vi.fn().mockResolvedValue(null),
    },
    subscribeAlerts: vi.fn(() => vi.fn()),
  }
})

import { api, subscribeAlerts } from '../api/client'

beforeEach(() => {
  vi.clearAllMocks()
})

function renderView() {
  return render(
    <MemoryRouter>
      <FleetOverview />
    </MemoryRouter>
  )
}

describe('FleetOverview', () => {
  it('shows loading state initially', () => {
    vi.mocked(api.getFleetOverview).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.listAgents).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.getHeatmap).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.listRecentAlerts).mockReturnValue(new Promise(() => {}))

    renderView()
    expect(screen.getByText('Loading fleet data')).toBeInTheDocument()
  })

  it('renders stat tiles after data loads', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument()
    })
    expect(screen.getByText('Total Agents')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('Active Agents')).toBeInTheDocument()
    expect(screen.getByText('200')).toBeInTheDocument()
    expect(screen.getByText('15')).toBeInTheDocument()
  })

  it('renders agent stat tiles with correct titles', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('Total Agents')).toBeInTheDocument()
    })

    const totalAgentsTile = screen.getByText('Total Agents').closest('.stat-tile')!
    const activeTile = screen.getByText('Active Agents').closest('.stat-tile')!

    expect(totalAgentsTile.getAttribute('title')).toBe('Total Registered AI Agents')
    expect(activeTile.getAttribute('title')).toBe('Active Compliant AI Agents')
  })

  it('renders agent table', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('agent-alpha')).toBeInTheDocument()
    })
    expect(screen.getByText('active')).toBeInTheDocument()
  })

  it('renders alert feed with DLP finding title', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('DLP: api_key')).toBeInTheDocument()
    })
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('subscribes to SSE alerts', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(subscribeAlerts).toHaveBeenCalled()
    })
  })

  it('shows empty states when no data', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue({
      ...mockStats, total_agents: 0, active_agents: 0,
    })
    vi.mocked(api.listAgents).mockResolvedValue([])
    vi.mocked(api.getHeatmap).mockResolvedValue([])
    vi.mocked(api.listRecentAlerts).mockResolvedValue([])

    renderView()

    await waitFor(() => {
      expect(screen.getByText('No agents registered')).toBeInTheDocument()
    })
    expect(screen.getByText('No events in the last 24 hours')).toBeInTheDocument()
    expect(screen.getByText('No alerts')).toBeInTheDocument()
  })

  it('updates data queries when clicking time range toggles', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument()
    })

    expect(api.getFleetOverview).toHaveBeenCalledWith(24)

    // Click 1H toggle
    const oneHourBtn = screen.getByText('1H')
    oneHourBtn.click()

    await waitFor(() => {
      expect(api.getFleetOverview).toHaveBeenCalledWith(1)
      expect(api.listAgents).toHaveBeenCalledWith(50, 0, 1)
      expect(api.getHeatmap).toHaveBeenCalledWith(1)
      expect(api.listRecentAlerts).toHaveBeenCalledWith(50, 1)
    })
  })
})
