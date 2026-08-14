import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import IdentityGovernance from './IdentityGovernance'
import type { CredentialMeta } from '../api/client'

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      listCredentials: vi.fn(),
    },
  }
})

import { api } from '../api/client'

const futureMs = Date.now() + 86400_000
const pastMs = Date.now() - 86400_000
const soonMs = Date.now() + 1800_000

const mockCredentials: CredentialMeta[] = [
  {
    credential_id: 'cred-active',
    agent_id: 'agent-1',
    scope: ['read', 'write'],
    ttl_seconds: 3600,
    created_at_ms: Date.now() - 7200_000,
    expires_at_ms: futureMs,
    last_rotated_at_ms: null,
    rotation_history: [],
  },
  {
    credential_id: 'cred-expired',
    agent_id: 'agent-2',
    scope: ['admin'],
    ttl_seconds: 86400,
    created_at_ms: Date.now() - 172800_000,
    expires_at_ms: pastMs,
    last_rotated_at_ms: Date.now() - 86400_000,
    rotation_history: [
      { rotated_at_ms: Date.now() - 86400_000, reason: 'scheduled' },
    ],
  },
  {
    credential_id: 'cred-expiring',
    agent_id: 'agent-3',
    scope: ['read'],
    ttl_seconds: 1800,
    created_at_ms: Date.now() - 3600_000,
    expires_at_ms: soonMs,
    last_rotated_at_ms: null,
    rotation_history: [],
  },
]

beforeEach(() => {
  vi.clearAllMocks()
})

function renderView() {
  return render(
    <MemoryRouter>
      <IdentityGovernance />
    </MemoryRouter>
  )
}

describe('IdentityGovernance', () => {
  it('shows loading state', () => {
    vi.mocked(api.listCredentials).mockReturnValue(new Promise(() => {}))
    renderView()
    expect(screen.getByText('Loading identity data')).toBeInTheDocument()
  })

  it('renders credential cards with correct status badges', async () => {
    vi.mocked(api.listCredentials).mockResolvedValue(mockCredentials)
    renderView()

    await waitFor(() => {
      expect(screen.getByText('cred-active')).toBeInTheDocument()
    })
    expect(screen.getByText('cred-expired')).toBeInTheDocument()
    expect(screen.getByText('cred-expiring')).toBeInTheDocument()

    // Status badges appear on cards; stat labels also use "Active"/"Expired".
    expect(screen.getAllByText('Active').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Expired').length).toBeGreaterThanOrEqual(1)
    expect(screen.getByText('Expiring soon')).toBeInTheDocument()
  })

  it('renders scope tags', async () => {
    vi.mocked(api.listCredentials).mockResolvedValue(mockCredentials)
    renderView()

    await waitFor(() => {
      // "read" appears on two credential cards (agent-1 and agent-3).
      expect(screen.getAllByText('read').length).toBeGreaterThanOrEqual(2)
    })
    expect(screen.getByText('write')).toBeInTheDocument()
    expect(screen.getByText('admin')).toBeInTheDocument()
  })

  it('renders summary stat tiles', async () => {
    vi.mocked(api.listCredentials).mockResolvedValue(mockCredentials)
    renderView()

    await waitFor(() => {
      expect(screen.getByText('Total Credentials')).toBeInTheDocument()
    })
    // 3 total, 2 active (future + expiring soon), 1 expired
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('renders rotation history', async () => {
    vi.mocked(api.listCredentials).mockResolvedValue(mockCredentials)
    renderView()

    await waitFor(() => {
      expect(screen.getByText('Rotation History')).toBeInTheDocument()
    })
    expect(screen.getByText('Scheduled')).toBeInTheDocument()
  })

  it('shows empty state when no credentials', async () => {
    vi.mocked(api.listCredentials).mockResolvedValue([])
    renderView()

    await waitFor(() => {
      expect(screen.getByText('No agent credentials registered yet.')).toBeInTheDocument()
    })
  })
})
