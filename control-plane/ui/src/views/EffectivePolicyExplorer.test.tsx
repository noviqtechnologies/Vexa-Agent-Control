import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import EffectivePolicyExplorer from './EffectivePolicyExplorer'
import type { EffectivePolicyResponse } from '../api/client'

const mockEffectiveResponse: EffectivePolicyResponse = {
  queried_at: new Date().toISOString(),
  query_params: {
    device_id: 'win-dev-1',
    provider: 'openai',
    model: 'gpt-4o',
  },
  provenance_ladder: [
    { level: 'organization', source: 'policy_mgmt', confidence: 'observed', policy: { tenant_id: 'tenant-1' } },
    { level: 'group', source: 'group_policies', confidence: 'not_configured' },
    { level: 'spend', source: 'spend_v2', confidence: 'observed', policies: [{ limit_microcents: 10000000000, action: 'hard_deny' }] },
    { level: 'virtual_key', source: 'virtual_keys', confidence: 'not_configured' },
    { level: 'device', source: 'device_governance', confidence: 'observed', state: { device_id: 'win-dev-1' } },
  ],
  effective: {
    spend_limit_microcents: 10000000000,
    action: 'hard_deny',
    allowed_models: ['*'],
    allowed_routes: ['*'],
    policy_version_ids: ['pol-v1'],
  },
  confidence: 'observed',
  provenance: {
    data_freshness: new Date().toISOString(),
    evidence_source: 'control_plane_multi_layer_resolution',
    confidence: 'observed',
  },
}

vi.mock('../api/client', async () => {
  const actual = await vi.importActual<typeof import('../api/client')>('../api/client')
  return {
    ...actual,
    api: {
      getEffectivePolicy: vi.fn(),
    },
  }
})

import { api } from '../api/client'

beforeEach(() => {
  vi.clearAllMocks()
})

function renderView(initialEntries = ['/policy/effective-explorer']) {
  return render(
    <MemoryRouter initialEntries={initialEntries}>
      <EffectivePolicyExplorer />
    </MemoryRouter>
  )
}

describe('EffectivePolicyExplorer View', () => {
  it('renders query form with all inputs', () => {
    vi.mocked(api.getEffectivePolicy).mockResolvedValue(mockEffectiveResponse)
    renderView()

    expect(screen.getByLabelText('Device ID')).toBeInTheDocument()
    expect(screen.getByLabelText('Agent ID')).toBeInTheDocument()
    expect(screen.getByLabelText('Virtual Key ID')).toBeInTheDocument()
    expect(screen.getByLabelText('Provider')).toBeInTheDocument()
    expect(screen.getByLabelText('Model')).toBeInTheDocument()
  })

  it('renders 5-level provenance ladder and effective constraints on resolution', async () => {
    vi.mocked(api.getEffectivePolicy).mockResolvedValue(mockEffectiveResponse)
    renderView()

    await waitFor(() => {
      expect(screen.getByText('5-Level Provenance Ladder')).toBeInTheDocument()
    })

    expect(screen.getByText('LEVEL 1:')).toBeInTheDocument()
    expect(screen.getByText('LEVEL 2:')).toBeInTheDocument()
    expect(screen.getByText('LEVEL 3:')).toBeInTheDocument()
    expect(screen.getByText('LEVEL 4:')).toBeInTheDocument()
    expect(screen.getByText('LEVEL 5:')).toBeInTheDocument()

    expect(screen.getByText('ACTION: HARD_DENY')).toBeInTheDocument()
    expect(screen.getByText('$100.00/mo')).toBeInTheDocument()
  })

  it('pre-populates query inputs when deep-linked with URL query parameters', async () => {
    vi.mocked(api.getEffectivePolicy).mockResolvedValue(mockEffectiveResponse)
    renderView(['/policy/effective-explorer?device_id=win-endpoint-99&provider=anthropic'])

    const deviceInput = screen.getByLabelText('Device ID') as HTMLInputElement
    const providerInput = screen.getByLabelText('Provider') as HTMLInputElement

    expect(deviceInput.value).toBe('win-endpoint-99')
    expect(providerInput.value).toBe('anthropic')
  })
})
