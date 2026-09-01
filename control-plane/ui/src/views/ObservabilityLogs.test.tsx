import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import ObservabilityLogs from './ObservabilityLogs'

vi.mock('../api/client', () => ({
  api: {
    listRequestLogs: vi.fn().mockResolvedValue({
      organization_id: 'tenant-1',
      request_logs: [
        {
          run_id: 'run-101',
          request_id: '099b5405-e9fe-4b53-8326-e9102c918342',
          session_id: '73fc9665-6112-4c6d-9781-37dfd125fa0a',
          device_id: 'dev-1',
          project_id: 'default',
          provider: 'openai',
          model: 'gpt-4o',
          state: 'SETTLED',
          reserved_microcents: 200000,
          settled_microcents: 180000,
          started_at: '2026-08-31T15:02:05Z',
          duration_ms: 820,
          ttft_ms: 240,
          input_tokens: 1000,
          output_tokens: 250,
          total_tokens: 1250,
          virtual_key_prefix: 'vk-abc12',
          request_type: 'LLM',
        },
      ],
      total: 1,
      data_freshness: '2026-08-31T15:02:10Z',
      confidence: 'observed',
    }),
    listAuditLogs: vi.fn().mockResolvedValue({
      organization_id: 'tenant-1',
      audit_logs: [
        {
          id: 'audit-1',
          tenant_id: 'tenant-1',
          timestamp: '2026-08-31T15:00:00Z',
          table_name: 'virtual_keys',
          action: 'created',
          changed_by: 'admin@vexa.ai',
          actor_role: 'admin',
          affected_item_id: 'vk-12345',
          before_value: null,
          updated_value: { name: 'Production Key', budget: 50000000 },
        },
      ],
      total: 1,
      page: 1,
      limit: 50,
    }),
    listDeletedVirtualKeys: vi.fn().mockResolvedValue({
      organization_id: 'tenant-1',
      deleted_virtual_keys: [
        {
          id: 'vk-del-1',
          tenant_id: 'tenant-1',
          key_prefix: 'vk-old99',
          name: 'Old Staging Key',
          team_id: 'default',
          created_by: 'dev@vexa.ai',
          created_at: '2026-08-01T10:00:00Z',
          deleted_at: '2026-08-31T12:00:00Z',
          deleted_by: 'admin@vexa.ai',
          deleted_reason: 'manual_revocation',
          monthly_budget_microcents: 100000000,
          spent_microcents: 45000000,
          allowed_models: ['gpt-4o'],
          status: 'revoked',
        },
      ],
      total: 1,
    }),
    listDeletedTeams: vi.fn().mockResolvedValue({
      organization_id: 'tenant-1',
      deleted_teams: [],
      total: 0,
    }),
  },
}))

describe('ObservabilityLogs View', () => {
  it('renders Observability & Logs tabs header and loads Request Logs by default', async () => {
    render(
      <MemoryRouter initialEntries={['/observability/logs']}>
        <ObservabilityLogs />
      </MemoryRouter>
    )

    expect(screen.getByText('Observability & Logs')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Request Logs' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Audit Logs' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Deleted Keys' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Deleted Teams' })).toBeInTheDocument()

    // Verifies Request Logs tab table content loaded
    await waitFor(() => {
      expect(screen.getByText('099b5405-e...')).toBeInTheDocument()
      expect(screen.getByText('gpt-4o')).toBeInTheDocument()
      expect(screen.getByText('vk-abc12')).toBeInTheDocument()
    })
  })

  it('switches to Audit Logs tab and renders expandable before/after records', async () => {
    render(
      <MemoryRouter initialEntries={['/observability/logs']}>
        <ObservabilityLogs />
      </MemoryRouter>
    )

    const auditTabBtn = screen.getByRole('button', { name: 'Audit Logs' })
    fireEvent.click(auditTabBtn)

    await waitFor(() => {
      expect(screen.getByText('virtual_keys')).toBeInTheDocument()
      expect(screen.getByText('admin@vexa.ai')).toBeInTheDocument()
      expect(screen.getByText('vk-12345')).toBeInTheDocument()
    })

    // Click row to expand before/after diff
    const row = screen.getByText('virtual_keys').closest('tr')!
    fireEvent.click(row)

    expect(screen.getByText('Before Value:')).toBeInTheDocument()
    expect(screen.getByText('Updated Value:')).toBeInTheDocument()
  })

  it('switches to Deleted Keys tab and displays tombstoned key compliance records', async () => {
    render(
      <MemoryRouter initialEntries={['/observability/logs']}>
        <ObservabilityLogs />
      </MemoryRouter>
    )

    const deletedKeysTabBtn = screen.getByRole('button', { name: 'Deleted Keys' })
    fireEvent.click(deletedKeysTabBtn)

    await waitFor(() => {
      expect(screen.getByText('Enterprise Audit & Compliance Suite')).toBeInTheDocument()
      expect(screen.getByText('vk-old99')).toBeInTheDocument()
      expect(screen.getByText('$0.45')).toBeInTheDocument()
      expect(screen.getByText('manual_revocation')).toBeInTheDocument()
    })
  })
})
