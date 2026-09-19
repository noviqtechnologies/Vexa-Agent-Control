import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import Login from './Login'

const mockLogin = vi.fn()
let mockAuthError: string | null = null

vi.mock('../auth/AuthContext', () => ({
  useAuth: () => ({
    login: mockLogin,
    error: mockAuthError,
  }),
}))

describe('Login View', () => {
  beforeEach(() => {
    mockLogin.mockReset()
    mockAuthError = null
    vi.stubGlobal('fetch', vi.fn((url: string) => {
      if (url === '/api/v1/auth/providers') {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([
            { id: 'entra-1', type: 'entra', name: 'Microsoft Entra ID' },
            { id: 'google-1', type: 'google', name: 'Google Workspace' },
          ]),
        })
      }
      return Promise.reject(new Error('Unknown URL: ' + url))
    }))
  })

  async function renderLogin(initialEntry = '/login') {
    render(
      <MemoryRouter initialEntries={[initialEntry]}>
        <Login />
      </MemoryRouter>
    )
    // Wait until providers are loaded and form is visible
    await waitFor(() => {
      expect(screen.queryByText(/Verifying authentication providers/i)).toBeNull()
    })
  }

  it('renders brand identity, major capabilities, and customer workspace console', async () => {
    await renderLogin()

    // Check brand header (may appear in both desktop brand column and mobile header)
    expect(screen.getAllByText('Vexa').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('Agent Control').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Autonomous AI Security Gateway/i).length).toBeGreaterThanOrEqual(1)

    // Check core capabilities in pills & highlights
    expect(screen.getAllByText(/CORE AI GOVERNANCE CAPABILITIES/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Zero-Trust MCP Firewall/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Dual-Pass Inline DLP/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Prompt Injection Shield/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Semantic Vector Cache/i).length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText(/Fail-Closed Spend Caps/i).length).toBeGreaterThanOrEqual(1)

    // Check Customer Workspace console form elements
    expect(screen.getByText(/Dedicated Control Hub/i)).toBeDefined()
    expect(screen.getByRole('heading', { name: /Sign in to your organization/i })).toBeDefined()
    expect(screen.getByPlaceholderText(/name@company.com or username/i)).toBeDefined()
    expect(screen.getByRole('button', { name: /Sign In to (Control Hub|Customer Workspace) →/i })).toBeDefined()

    // Check vexasec.io links and contact email
    const websiteLinks = screen.getAllByRole('link', { name: /vexasec\.io/i })
    expect(websiteLinks.length).toBeGreaterThanOrEqual(1)
    const emailLink = screen.getByRole('link', { name: /contact@vexasec\.io/i })
    expect(emailLink.getAttribute('href')).toBe('mailto:contact@vexasec.io')

    // Ensure SaaS operator tab/button is NOT present
    expect(screen.queryByRole('tab', { name: /SaaS Operator/i })).toBeNull()
    expect(screen.queryByText(/Platform Super-Admin Mode/i)).toBeNull()

    // Ensure hardware security key button is NOT present
    expect(screen.queryByText(/Sign in with Hardware Security Key/i)).toBeNull()

    // Verify OAuth buttons
    expect(screen.getByText(/Continue with Microsoft Entra ID/i)).toBeDefined()
    expect(screen.getByText(/Continue with Google Workspace/i)).toBeDefined()
  })

  it('allows typing credentials and submitting the login form', async () => {
    mockLogin.mockResolvedValueOnce(undefined)
    await renderLogin()

    const emailInput = screen.getByPlaceholderText(/name@company.com or username/i)
    const passwordInput = screen.getByPlaceholderText('••••••••••••')
    const submitBtn = screen.getByRole('button', { name: /Sign In to (Control Hub|Customer Workspace) →/i })

    fireEvent.change(emailInput, { target: { value: 'secops@enterprise.com' } })
    fireEvent.change(passwordInput, { target: { value: 'SecretToken123!' } })
    fireEvent.click(submitBtn)

    expect(mockLogin).toHaveBeenCalledWith('secops@enterprise.com', 'SecretToken123!')
  })

  it('toggles password visibility when eye toggle is clicked', async () => {
    await renderLogin()

    const passwordInput = screen.getByPlaceholderText('••••••••••••') as HTMLInputElement
    expect(passwordInput.type).toBe('password')

    const toggleBtn = screen.getByRole('button', { name: /Show password/i })
    fireEvent.click(toggleBtn)

    expect(passwordInput.type).toBe('text')

    const hideBtn = screen.getByRole('button', { name: /Hide password/i })
    fireEvent.click(hideBtn)

    expect(passwordInput.type).toBe('password')
  })

  it('opens and closes the access assistance modal with contact info', async () => {
    await renderLogin()

    const helpBtn = screen.getByRole('button', { name: /Need help\?/i })
    fireEvent.click(helpBtn)

    expect(screen.getByText('Console Access Assistance')).toBeDefined()
    expect(screen.getByText(/Customer Workspace Administrators/i)).toBeDefined()
    expect(screen.getByText(/Enterprise Technical Support/i)).toBeDefined()

    const closeBtn = screen.getByRole('button', { name: /Return to Login/i })
    fireEvent.click(closeBtn)

    expect(screen.queryByText('Console Access Assistance')).toBeNull()
  })

  it('displays session timeout notice when reason is idle_timeout', async () => {
    await renderLogin('/login?reason=idle_timeout')

    expect(screen.getByText(/Your session expired due to 15 minutes of inactivity/i)).toBeDefined()
  })

  it('triggers OAuth login with prompt=select_account when OAuth button is clicked', async () => {
    await renderLogin()

    const originalLocation = window.location
    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: { ...originalLocation, href: '' },
    })

    const msButton = screen.getByRole('button', { name: /Continue with Microsoft Entra ID/i })
    fireEvent.click(msButton)

    expect(window.location.href).toBe('/api/v1/auth/oauth/entra-1/login?prompt=select_account')

    Object.defineProperty(window, 'location', {
      configurable: true,
      writable: true,
      value: originalLocation,
    })
  })
})

