import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import PolicyEditor from './PolicyEditor'
import { api } from '../api/client'

vi.mock('../api/client', () => ({
  api: {
    listPolicies: vi.fn(),
    getActivePolicy: vi.fn(),
    savePolicy: vi.fn(),
    listTemplates: vi.fn(),
  },
}))

describe('PolicyEditor View', () => {
  const mockActivePolicy = {
    id: 'pol-123',
    version: '1.0.0',
    content: 'version: "1.0.0"\ndefault_action: deny\nenforce_safe_mode: true\n',
    is_active: true,
    created_at: '2026-10-01T10:00:00Z',
    updated_at: '2026-10-01T10:00:00Z',
  }

  const mockPastPolicy = {
    id: 'pol-099',
    version: '0.9.0',
    content: 'version: "0.9.0"\ndefault_action: allow\n',
    is_active: false,
    created_at: '2026-09-01T10:00:00Z',
    updated_at: '2026-09-01T10:00:00Z',
  }

  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(api.listPolicies).mockResolvedValue([mockActivePolicy, mockPastPolicy])
    vi.mocked(api.getActivePolicy).mockResolvedValue(mockActivePolicy)
    vi.mocked(api.listTemplates).mockResolvedValue([])
  })

  it('renders active policy revision in header and sidebar by default', async () => {
    render(
      <MemoryRouter>
        <PolicyEditor />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Policy Editor')).toBeInTheDocument()
    })

    // Header active revision pill
    expect(screen.getByText('Active Revision:')).toBeInTheDocument()
    const activeRevs = screen.getAllByText('1.0.0')
    expect(activeRevs.length).toBeGreaterThanOrEqual(1)

    // Historical version dropdown should select the active policy by default
    const historySelect = screen.getByRole('combobox', { name: /Load Historical Version/i }) as HTMLSelectElement
    expect(historySelect.value).toBe('pol-123')

    // Revision input should be populated with active revision
    const revInput = screen.getByLabelText(/Policy Revision \(for new save\)/i) as HTMLInputElement
    expect(revInput.value).toBe('1.0.0')

    // Editor textarea should contain active policy content
    const textarea = document.getElementById('textarea-policy-content') as HTMLTextAreaElement
    expect(textarea.value).toContain('enforce_safe_mode: true')
  })

  it('allows selecting a past historical version and then reverting to active', async () => {
    render(
      <MemoryRouter>
        <PolicyEditor />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Policy Editor')).toBeInTheDocument()
    })

    const historySelect = screen.getByRole('combobox', { name: /Load Historical Version/i })
    fireEvent.change(historySelect, { target: { value: 'pol-099' } })

    // Revision input should update to past version
    const revInput = screen.getByLabelText(/Policy Revision \(for new save\)/i) as HTMLInputElement
    expect(revInput.value).toBe('0.9.0')

    // Editor textarea should update
    const textarea = document.getElementById('textarea-policy-content') as HTMLTextAreaElement
    expect(textarea.value).toContain('default_action: allow')

    // Revert button should appear
    const revertBtn = screen.getByRole('button', { name: /Reload Active Policy/i })
    expect(revertBtn).toBeInTheDocument()

    // Click revert
    fireEvent.click(revertBtn)

    expect(revInput.value).toBe('1.0.0')
    expect(textarea.value).toContain('enforce_safe_mode: true')
  })

  it('saves and applies new policy revision', async () => {
    vi.mocked(api.savePolicy).mockResolvedValue({
      id: 'pol-124',
      version: '1.0.1',
      content: 'version: "1.0.1"\ndefault_action: deny\n',
      is_active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    })

    render(
      <MemoryRouter>
        <PolicyEditor />
      </MemoryRouter>
    )

    await waitFor(() => {
      expect(screen.getByText('Policy Editor')).toBeInTheDocument()
    })

    const revInput = screen.getByLabelText(/Policy Revision \(for new save\)/i)
    fireEvent.change(revInput, { target: { value: '1.0.1' } })

    const saveBtn = screen.getByRole('button', { name: /Save & Apply/i })
    fireEvent.click(saveBtn)

    await waitFor(() => {
      expect(api.savePolicy).toHaveBeenCalledWith(
        expect.objectContaining({
          version: '1.0.1',
          is_active: true,
        })
      )
    })
  })
})
