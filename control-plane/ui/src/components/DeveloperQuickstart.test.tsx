import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import DeveloperQuickstart from './DeveloperQuickstart'

const mockUser = {
  id: 'dev.user@example.com',
  organization_id: 'org-123',
  tenant_id: 'org-123',
  is_admin: false,
  is_saas_operator: false,
}

vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({
    user: mockUser,
    authenticated: true,
  }),
}))

describe('DeveloperQuickstart Component', () => {
  let store: Record<string, string> = {}

  beforeEach(() => {
    store = {}
    const localStorageMock = {
      getItem: vi.fn((key: string) => store[key] || null),
      setItem: vi.fn((key: string, value: string) => {
        store[key] = value.toString()
      }),
      removeItem: vi.fn((key: string) => {
        delete store[key]
      }),
      clear: vi.fn(() => {
        store = {}
      }),
    }
    Object.defineProperty(window, 'localStorage', {
      value: localStorageMock,
      writable: true,
    })

    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn().mockResolvedValue(undefined),
      },
    })
    vi.clearAllMocks()
  })

  it('renders quickstart guide with title, step pills, and code snippet', () => {
    render(
      <MemoryRouter>
        <DeveloperQuickstart />
      </MemoryRouter>
    )

    expect(screen.getByText(/Developer Quickstart Guide/i)).toBeInTheDocument()
    expect(screen.getByText(/Zero-Touch Proxy/i)).toBeInTheDocument()
    expect(screen.getByTestId('os-tab-windows')).toBeInTheDocument()
    expect(screen.getByTestId('os-tab-macos')).toBeInTheDocument()
    expect(screen.getByTestId('os-tab-linux')).toBeInTheDocument()
    expect(screen.getByTestId('copy-snippet-btn')).toBeInTheDocument()
  })

  it('switches between OS tabs and updates CLI installation commands', () => {
    render(
      <MemoryRouter>
        <DeveloperQuickstart />
      </MemoryRouter>
    )

    // Click Windows tab
    fireEvent.click(screen.getByTestId('os-tab-windows'))
    const snippetWin = screen.getByTestId('code-snippet-content')
    expect(snippetWin.textContent).toContain('install.ps1')
    expect(snippetWin.textContent).toContain('agentcontrol login')

    // Click macOS tab
    fireEvent.click(screen.getByTestId('os-tab-macos'))
    const snippetMac = screen.getByTestId('code-snippet-content')
    expect(snippetMac.textContent).toContain('install.sh')
    expect(snippetMac.textContent).toContain('agentcontrol login')

    // Click Linux tab
    fireEvent.click(screen.getByTestId('os-tab-linux'))
    const snippetLinux = screen.getByTestId('code-snippet-content')
    expect(snippetLinux.textContent).toContain('install.sh')
  })

  it('switches between AI tool tabs (Cursor, Claude Code, Python, Node.js)', () => {
    render(
      <MemoryRouter>
        <DeveloperQuickstart />
      </MemoryRouter>
    )

    // Switch to Cursor IDE
    fireEvent.click(screen.getByTestId('tool-tab-cursor'))
    expect(screen.getByTestId('code-snippet-content').textContent).toContain('cursor.openAiBaseUrl')

    // Switch to Claude Code
    fireEvent.click(screen.getByTestId('tool-tab-claude'))
    expect(screen.getByTestId('code-snippet-content').textContent).toContain('ANTHROPIC_BASE_URL')

    // Switch to Python SDK
    fireEvent.click(screen.getByTestId('tool-tab-python'))
    expect(screen.getByTestId('code-snippet-content').textContent).toContain('from openai import OpenAI')

    // Switch to Node.js
    fireEvent.click(screen.getByTestId('tool-tab-node'))
    expect(screen.getByTestId('code-snippet-content').textContent).toContain("import OpenAI from 'openai'")
  })

  it('copies snippet to clipboard when clicking copy button', async () => {
    render(
      <MemoryRouter>
        <DeveloperQuickstart />
      </MemoryRouter>
    )

    const copyBtn = screen.getByTestId('copy-snippet-btn')
    fireEvent.click(copyBtn)

    expect(navigator.clipboard.writeText).toHaveBeenCalled()
    await waitFor(() => {
      expect(screen.getByText(/✓ Copied to Clipboard!/i)).toBeInTheDocument()
    })
  })

  it('persists dismissal in localStorage and hides banner', () => {
    const { unmount } = render(
      <MemoryRouter>
        <DeveloperQuickstart />
      </MemoryRouter>
    )

    const dismissBtn = screen.getByText(/✕ Dismiss/i)
    fireEvent.click(dismissBtn)

    expect(window.localStorage.setItem).toHaveBeenCalledWith(
      'agentwall_dev_onboarding_dismissed_dev.user@example.com',
      'true'
    )

    unmount()

    // Re-rendering should return null since it is dismissed
    const { container } = render(
      <MemoryRouter>
        <DeveloperQuickstart />
      </MemoryRouter>
    )
    expect(container.querySelector('.dev-quickstart-card')).toBeNull()
  })

  it('renders when forceOpen is true even if previously dismissed in localStorage', () => {
    store['agentwall_dev_onboarding_dismissed_dev.user@example.com'] = 'true'

    render(
      <MemoryRouter>
        <DeveloperQuickstart forceOpen={true} />
      </MemoryRouter>
    )

    expect(screen.getByTestId('dev-quickstart-card')).toBeInTheDocument()
  })
})
