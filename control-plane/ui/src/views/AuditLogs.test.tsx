import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import AuditLogs from './AuditLogs'
import type { RedactedEvent } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      listEvents: vi.fn(),
    },
  }
})

import { api } from '../api/client'

const mockEvents: RedactedEvent[] = [
  {
    event_id: 'evt-001',
    timestamp_ms: Date.now() - 5000,
    session_id: 'sess-123',
    agent_id: 'cursor@workstation-alpha',
    tool_name: 'read_file',
    decision: 'allowed',
    dlp_findings: [],
    injection_findings: [],
    semantic_findings: [],
  },
  {
    event_id: 'evt-002',
    timestamp_ms: Date.now() - 3000,
    session_id: 'sess-456',
    agent_id: 'claude@workstation-alpha',
    tool_name: '<unlisted_tool>',
    decision: 'denied',
    dlp_findings: [{ category: 'API_KEY', pattern_name: 'OpenAI Secret', count: 1 }],
    injection_findings: [{ pattern_name: 'Prompt Override', count: 1 }],
    semantic_findings: [],
  },
]

beforeEach(() => {
  vi.clearAllMocks()
})

function renderView() {
  return render(
    <MemoryRouter>
      <AuditLogs />
    </MemoryRouter>
  )
}

describe('AuditLogs View', () => {
  it('renders summary KPI cards and table headers correctly', async () => {
    vi.mocked(api.listEvents).mockResolvedValue(mockEvents)
    renderView()

    expect(await screen.findByText('Audit Logs')).toBeInTheDocument()
    expect(screen.getByText('Total Invocations')).toBeInTheDocument()
    expect(screen.getByText('Violations (Denied/Warned)')).toBeInTheDocument()

    // Check table headers & labels
    expect(screen.getAllByText('Agent ID / Subject').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Tool Name').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Decision').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('DLP Findings')).toBeInTheDocument()
    expect(screen.getByText('Injection')).toBeInTheDocument()

    // Check rows data
    expect(await screen.findByText('cursor@workstation-alpha')).toBeInTheDocument()
    expect(screen.getByText('claude@workstation-alpha')).toBeInTheDocument()
    expect(screen.getByText('read_file')).toBeInTheDocument()
  })

  it('filters by agent name search', async () => {
    vi.mocked(api.listEvents).mockResolvedValue(mockEvents)
    const user = userEvent.setup()
    renderView()

    expect(await screen.findByText('cursor@workstation-alpha')).toBeInTheDocument()

    const searchInput = screen.getByPlaceholderText('Search by agent ID or subject…')
    await user.type(searchInput, 'cursor')

    expect(screen.getByText('cursor@workstation-alpha')).toBeInTheDocument()
    expect(screen.queryByText('claude@workstation-alpha')).not.toBeInTheDocument()
  })

  it('opens event detail modal upon inspect click', async () => {
    vi.mocked(api.listEvents).mockResolvedValue(mockEvents)
    const user = userEvent.setup()
    renderView()

    expect(await screen.findByText('cursor@workstation-alpha')).toBeInTheDocument()

    const inspectButtons = screen.getAllByText('Inspect')
    await user.click(inspectButtons[0])

    expect(await screen.findByText('Event Inspection')).toBeInTheDocument()
    expect(screen.getByText('ID: evt-001')).toBeInTheDocument()
    expect(screen.getByText('Raw Event Telemetry JSON')).toBeInTheDocument()
  })
})
