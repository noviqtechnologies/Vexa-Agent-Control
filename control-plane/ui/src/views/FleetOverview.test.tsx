import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
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

const mockNavigate = vi.fn()
vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom')
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

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
      listVirtualKeys: vi.fn().mockResolvedValue({ virtual_keys: [] }),
      listPolicies: vi.fn().mockResolvedValue([]),
      getEffectiveSpendV2: vi.fn().mockResolvedValue({ organization_id: 'org-1', windows: [] }),
      listSpendPoliciesV2: vi.fn().mockResolvedValue({ organization_id: 'org-1', policies: [] }),
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

  it('renders agent stat tiles with correct titles and navigation/click actions', async () => {
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
    const totalEventsTile = screen.getByText('Total Events').closest('.stat-tile')!
    const deniedTile = screen.getByText('Denied').closest('.stat-tile')!

    expect(totalAgentsTile.getAttribute('title')).toBe('Click to view all registered AI agents')
    expect(activeTile.getAttribute('title')).toBe('Click to view active compliant AI agents')

    // Click Total Events -> navigate to /observability/logs?tab=security_logs
    fireEvent.click(totalEventsTile)
    expect(mockNavigate).toHaveBeenCalledWith('/observability/logs?tab=security_logs')

    // Click Denied -> navigate to /observability/logs?tab=security_logs&decision=denied
    fireEvent.click(deniedTile)
    expect(mockNavigate).toHaveBeenCalledWith('/observability/logs?tab=security_logs&decision=denied')

    // Click Total Agents & Active Agents
    fireEvent.click(activeTile)
    fireEvent.click(totalAgentsTile)
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
      expect(screen.getByText('Decision Heatmap (1H - Hourly)')).toBeInTheDocument()
    })

    // Click 7D toggle
    const sevenDayBtn = screen.getByText('7D')
    sevenDayBtn.click()

    await waitFor(() => {
      expect(api.getFleetOverview).toHaveBeenCalledWith(168)
      expect(api.getHeatmap).toHaveBeenCalledWith(168)
      expect(screen.getByText('Decision Heatmap (7D - Daily)')).toBeInTheDocument()
    })
  })

  it('renders hero banner with View Coverage Matrix action button', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument()
    })

    const matrixBtn = screen.getByRole('button', { name: /View Coverage Matrix/i })
    expect(matrixBtn).toBeInTheDocument()
    fireEvent.click(matrixBtn)
  })

  it('renders dynamic living capability snapshot cards', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument()
    })

    // Assert all 4 capability cards are rendered
    expect(screen.getByText('Device Governance')).toBeInTheDocument()
    expect(screen.getByText('Ed25519 & PKCE')).toBeInTheDocument()

    expect(screen.getByText('Policy Hub')).toBeInTheDocument()
    expect(screen.getByText('DLP & Guardrails')).toBeInTheDocument()

    expect(screen.getByText('Virtual Keys')).toBeInTheDocument()
    expect(screen.getByText('LLM Providers')).toBeInTheDocument()

    expect(screen.getByText('Spend Limits')).toBeInTheDocument()
    expect(screen.getByText('Budgets & Caps')).toBeInTheDocument()
  })

  it('renders AI gateway mesh ribbon with provider badges', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('GATEWAY MESH')).toBeInTheDocument()
    })

    expect(screen.getByText('OpenAI')).toBeInTheDocument()
    expect(screen.getByText('Claude')).toBeInTheDocument()
    expect(screen.getByText('Gemini')).toBeInTheDocument()
    expect(screen.getByText('Bedrock')).toBeInTheDocument()
    expect(screen.getByText('Local / Ollama')).toBeInTheDocument()
    expect(screen.getByText(/Semantic Cache: Active/i)).toBeInTheDocument()
  })

  it('toggles composite security posture breakdown popover', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('5')).toBeInTheDocument()
    })

    const factorBtn = screen.getByText(/Score Factors/i)
    fireEvent.click(factorBtn)

    expect(screen.getByText(/Composite Security & Governance Index Breakdown/i)).toBeInTheDocument()
    expect(screen.getByText(/Workstations & Sentry Compliance/i)).toBeInTheDocument()
    expect(screen.getByText(/Active Guardrails & 21 DLP Wire Rules/i)).toBeInTheDocument()
    expect(screen.getByText(/Universal AI Gateway & Key Custody/i)).toBeInTheDocument()
    expect(screen.getByText(/Spend Boundaries & Preflight Settlement/i)).toBeInTheDocument()
  })

  it('renders accurate zero metrics for fresh deployment with no virtual keys or spend', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)
    vi.mocked(api.listVirtualKeys).mockResolvedValue({ virtual_keys: [] } as any)
    vi.mocked(api.getEffectiveSpendV2).mockResolvedValue({ organization_id: 'org-1', windows: [] } as any)
    vi.mocked(api.listSpendPoliciesV2).mockResolvedValue({ organization_id: 'org-1', policies: [{ policy_id: 'sp-1', status: 'PUBLISHED', limit_microcents: 10000000000 }] } as any)
    vi.mocked(api.listPolicies).mockResolvedValue([{ id: 'pol-1', version: 1, is_active: true } as any])

    renderView()

    await waitFor(() => {
      expect(screen.getByText('0 Keys')).toBeInTheDocument()
      expect(screen.getByText('$0.00')).toBeInTheDocument()
      expect(screen.getByText('/ $100.00 Cap')).toBeInTheDocument()
      expect(screen.getByText('1 Policy')).toBeInTheDocument()
    })
  })

  it('navigates to Spend Analytics & Observatory (/spend/visualization) when Spend Limits card is clicked', async () => {
    vi.mocked(api.getFleetOverview).mockResolvedValue(mockStats)
    vi.mocked(api.listAgents).mockResolvedValue(mockAgents)
    vi.mocked(api.getHeatmap).mockResolvedValue(mockHeatmap)
    vi.mocked(api.listRecentAlerts).mockResolvedValue(mockAlerts)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('Spend Limits')).toBeInTheDocument()
    })

    const spendCard = screen.getByText('Spend Limits').closest('.soc-capability-card')
    expect(spendCard).not.toBeNull()
    fireEvent.click(spendCard!)

    expect(mockNavigate).toHaveBeenCalledWith('/spend/visualization')

    mockNavigate.mockClear()
    const spendFooter = screen.getByText('View Spend Analytics')
    fireEvent.click(spendFooter)

    expect(mockNavigate).toHaveBeenCalledWith('/spend/visualization')
  })
})

