import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import CoverageControlHealth from './CoverageControlHealth'
import type { CoverageHealthResponse } from '../api/client'

const mockCoverageData: CoverageHealthResponse = {
  summary: {
    total_workstations: 2,
    protected_workstations: 1,
    exposed_workstations: 1,
    stale_workstations: 0,
    revoked_workstations: 0,
    total_active_ides: 3,
    tamper_alerts_24h: 1,
    fleet_protection_score: 50.0,
  },
  workstations: [
    {
      device_id: 'dev-001',
      hostname: 'dev-macbook-pro',
      user_identifier: 'alice@corp.local',
      os: 'macos',
      os_version: '14.2',
      health_state: 'PROTECTED',
      overall_compliance: 'COMPLIANT',
      last_heartbeat_at: new Date().toISOString(),
      tamper_count_24h: 0,
      active_ides: ['cursor', 'vscode'],
      ide_coverage: [
        { id: 'cursor', name: 'Cursor', status: 'ENFORCED', is_wrapped: true },
        { id: 'vscode', name: 'VS Code', status: 'ENFORCED', is_wrapped: true },
        { id: 'claude', name: 'Claude Desktop', status: 'NOT_DETECTED', is_wrapped: false },
      ],
    },
    {
      device_id: 'dev-002',
      hostname: 'dev-win-station',
      user_identifier: 'bob@corp.local',
      os: 'windows',
      os_version: '11.0',
      health_state: 'EXPOSED',
      overall_compliance: 'NON_COMPLIANT',
      last_heartbeat_at: new Date().toISOString(),
      tamper_count_24h: 1,
      active_ides: ['cursor'],
      ide_coverage: [
        { id: 'cursor', name: 'Cursor', status: 'ENFORCED', is_wrapped: true },
        { id: 'vscode', name: 'VS Code', status: 'NOT_DETECTED', is_wrapped: false },
        { id: 'claude', name: 'Claude Desktop', status: 'NOT_DETECTED', is_wrapped: false },
      ],
    },
  ],
  generated_at: new Date().toISOString(),
}

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      ...actual.api,
      getCoverageHealth: vi.fn(),
    },
  }
})

describe('CoverageControlHealth View', () => {
  beforeEach(async () => {
    vi.clearAllMocks()
    const { api } = await import('../api/client')
    vi.mocked(api.getCoverageHealth).mockResolvedValue(mockCoverageData)
  })

  it('renders coverage score and KPI metrics correctly', async () => {
    render(<CoverageControlHealth />)

    expect(await screen.findByText('50.0%')).toBeInTheDocument()
    expect(screen.getByText('FLEET PROTECTION SCORE')).toBeInTheDocument()
    expect(screen.getByText('PROTECTED WORKSTATIONS')).toBeInTheDocument()
    expect(screen.getByText('dev-macbook-pro')).toBeInTheDocument()
    expect(screen.getByText('dev-win-station')).toBeInTheDocument()
  })

  it('displays enforced IDE badges for protected workstations', async () => {
    render(<CoverageControlHealth />)

    await waitFor(() => {
      expect(screen.getAllByText(/Cursor/).length).toBeGreaterThan(0)
    })
  })
})
