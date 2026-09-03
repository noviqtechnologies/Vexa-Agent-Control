import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import SessionTraceDrawer from './SessionTraceDrawer'
import type { SessionTraceResponse } from '../../api/client'

const mockSessionData: SessionTraceResponse = {
  session_id: 'sess-test-uuid-999',
  summary: {
    total_llm_calls: 2,
    total_tool_calls: 1,
    total_tokens: 4500,
    total_cached_tokens: 1200,
    total_settled_microcents: 5000000,
    policy_interventions_count: 1,
    started_at: new Date().toISOString(),
    ended_at: new Date().toISOString(),
    duration_ms: 3200,
  },
  timeline: [
    {
      type: 'llm_completion',
      timestamp: new Date().toISOString(),
      llm_run: {
        run_id: 'run-001',
        request_id: 'req-001',
        device_id: 'dev-1',
        project_id: 'default',
        provider: 'openai',
        model: 'gpt-4o',
        state: 'SETTLED',
        reserved_microcents: 5000000,
        settled_microcents: 5000000,
        started_at: new Date().toISOString(),
        duration_ms: 1200,
        input_tokens: 1000,
        output_tokens: 500,
        cached_tokens: 1200,
        total_tokens: 2700,
      },
    },
    {
      type: 'tool_call',
      timestamp: new Date().toISOString(),
      tool_event: {
        event_id: 'evt-001',
        timestamp_ms: Date.now(),
        session_id: 'sess-test-uuid-999',
        agent_id: 'agent-alice',
        tool_name: 'bash_exec',
        decision: 'deny',
        injection_findings: { prompt_injection: true },
      },
    },
  ],
}

vi.mock('../../api/client', async () => {
  const actual = await vi.importActual<typeof import('../../api/client')>('../../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getSessionTrace: vi.fn(),
    },
  }
})

describe('SessionTraceDrawer', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    const { api } = await import('../../api/client')
    vi.mocked(api.getSessionTrace).mockResolvedValue(mockSessionData)
  })

  it('renders session summary rollups and chronological items', async () => {
    render(<SessionTraceDrawer sessionId="sess-test-uuid-999" onClose={() => {}} />)

    expect(await screen.findByText('Multi-Turn Session Forensics')).toBeInTheDocument()
    expect(screen.getByText('LLM TURNS')).toBeInTheDocument()
    expect(screen.getByText('MCP TOOLS CALLED')).toBeInTheDocument()
    expect(screen.getByText(/LLM Request/)).toBeInTheDocument()
    expect(screen.getByText(/MCP Tool Call: bash_exec/)).toBeInTheDocument()
    expect(screen.getByText('DENY')).toBeInTheDocument()
  })
})
