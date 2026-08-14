import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ThreatIntelligence from './ThreatIntelligence'
import type { ThreatSummary, ThreatTimelinePoint, ThreatPattern } from '../api/client'

const mockSummary: ThreatSummary = {
  dlp_total: 25,
  injection_total: 10,
  semantic_total: 7,
  events_with_dlp: 18,
  events_with_injection: 8,
  events_with_semantic: 5,
}

const mockTimeline: ThreatTimelinePoint[] = [
  { hour: '2026-07-24 12:00', dlp: 5, injection: 2, semantic: 1 },
  { hour: '2026-07-24 13:00', dlp: 3, injection: 0, semantic: 2 },
]

const mockPatterns: ThreatPattern[] = [
  { type: 'dlp', pattern_name: 'ssn_pattern', category: 'pii', total_count: 15, event_count: 10 },
  { type: 'injection', pattern_name: 'sql_inject', total_count: 8, event_count: 6 },
]

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getThreatSummary: vi.fn(),
      getThreatTimeline: vi.fn(),
      getTopThreatPatterns: vi.fn(),
    },
  }
})

import { api } from '../api/client'

beforeEach(() => {
  vi.clearAllMocks()
})

function renderView() {
  return render(
    <MemoryRouter>
      <ThreatIntelligence />
    </MemoryRouter>
  )
}

describe('ThreatIntelligence', () => {
  it('shows loading state initially', () => {
    vi.mocked(api.getThreatSummary).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.getThreatTimeline).mockReturnValue(new Promise(() => {}))
    vi.mocked(api.getTopThreatPatterns).mockReturnValue(new Promise(() => {}))

    renderView()
    expect(screen.getByText('Loading threat data')).toBeInTheDocument()
  })

  it('renders stat tiles after data loads', async () => {
    vi.mocked(api.getThreatSummary).mockResolvedValue(mockSummary)
    vi.mocked(api.getThreatTimeline).mockResolvedValue(mockTimeline)
    vi.mocked(api.getTopThreatPatterns).mockResolvedValue(mockPatterns)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('42')).toBeInTheDocument()
    })
    expect(screen.getByText('Total Findings')).toBeInTheDocument()
    expect(screen.getByText('25')).toBeInTheDocument()
    expect(screen.getByText('DLP Violations')).toBeInTheDocument()
    expect(screen.getByText('Injection Attempts')).toBeInTheDocument()
    expect(screen.getByText('7')).toBeInTheDocument()
    expect(screen.getByText('Semantic Anomalies')).toBeInTheDocument()
    // "10" appears in both stat tile and patterns table, so use getAllByText
    expect(screen.getAllByText('10')).toHaveLength(2)
  })

  it('renders threat patterns table', async () => {
    vi.mocked(api.getThreatSummary).mockResolvedValue(mockSummary)
    vi.mocked(api.getThreatTimeline).mockResolvedValue(mockTimeline)
    vi.mocked(api.getTopThreatPatterns).mockResolvedValue(mockPatterns)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('ssn_pattern')).toBeInTheDocument()
    })
    expect(screen.getByText('sql_inject')).toBeInTheDocument()
    expect(screen.getByText('pii')).toBeInTheDocument()
    expect(screen.getByText('15')).toBeInTheDocument()
  })

  it('shows empty states when no data', async () => {
    vi.mocked(api.getThreatSummary).mockResolvedValue({
      dlp_total: 0, injection_total: 0, semantic_total: 0,
      events_with_dlp: 0, events_with_injection: 0, events_with_semantic: 0,
    })
    vi.mocked(api.getThreatTimeline).mockResolvedValue([])
    vi.mocked(api.getTopThreatPatterns).mockResolvedValue([])

    renderView()

    await waitFor(() => {
      expect(screen.getByText('No threat data in this period')).toBeInTheDocument()
    })
    expect(screen.getByText('No patterns detected')).toBeInTheDocument()
  })

  it('renders the time range selector', async () => {
    vi.mocked(api.getThreatSummary).mockResolvedValue(mockSummary)
    vi.mocked(api.getThreatTimeline).mockResolvedValue(mockTimeline)
    vi.mocked(api.getTopThreatPatterns).mockResolvedValue(mockPatterns)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('Threat Intelligence')).toBeInTheDocument()
    })
    expect(screen.getByRole('group', { name: /telemetry time range/i })).toBeInTheDocument()
    expect(screen.getByText('24H')).toBeInTheDocument()
  })

  it('renders page header', async () => {
    vi.mocked(api.getThreatSummary).mockResolvedValue(mockSummary)
    vi.mocked(api.getThreatTimeline).mockResolvedValue(mockTimeline)
    vi.mocked(api.getTopThreatPatterns).mockResolvedValue(mockPatterns)

    renderView()

    await waitFor(() => {
      expect(screen.getByText('Threat Intelligence')).toBeInTheDocument()
    })
    expect(screen.getByText('DLP violations, injection attempts, and semantic anomalies')).toBeInTheDocument()
  })
})
