import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react'

export interface UserProfile {
  id: string
  organization_id: string
  tenant_id: string // Alias for compatibility
  organization_name?: string
  license_tier?: string
  max_devices?: number
  enrolled_devices?: number
  is_admin: boolean
  is_saas_operator: boolean
  needs_password_setup?: boolean
}

export interface AuthState {
  authenticated: boolean
  loading: boolean
  error: string | null
  user: UserProfile | null
  needsAuthProviderConfig: boolean
  needsPasswordSetup: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  checkSession: () => Promise<void>
}

const AuthContext = createContext<AuthState>({
  authenticated: false,
  loading: true,
  error: null,
  user: null,
  needsAuthProviderConfig: false,
  needsPasswordSetup: false,
  login: async () => {},
  logout: () => {},
  checkSession: async () => {},
})

export function useAuth() {
  return useContext(AuthContext)
}

interface Props {
  children: ReactNode
}

export function AuthProvider({ children }: Props) {
  const [authenticated, setAuthenticated] = useState(false)
  const [user, setUser] = useState<UserProfile | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [needsAuthProviderConfig, setNeedsAuthProviderConfig] = useState(false)
  const [needsPasswordSetup, setNeedsPasswordSetup] = useState(false)

  const checkSession = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/auth/me')
      if (res.ok) {
        const userData = await res.json()
        const isOperator = !!userData.is_saas_operator
        const orgID = userData.organization_id || userData.tenant_id || '00000000-0000-0000-0000-000000000001'
        setAuthenticated(true)
        setUser({
          id: userData.user_id || 'user',
          organization_id: orgID,
          tenant_id: orgID,
          organization_name: userData.organization_name || 'Primary Organization',
          license_tier: userData.license_tier || 'developer',
          max_devices: userData.max_devices ?? 1,
          enrolled_devices: userData.enrolled_devices ?? 0,
          is_admin: !!userData.is_admin,
          is_saas_operator: isOperator,
          needs_password_setup: !isOperator && !!userData.needs_password_setup,
        })
        setNeedsPasswordSetup(!isOperator && !!userData.needs_password_setup)
        
        try {
          const authRes = await fetch('/api/v1/auth_providers')
          if (authRes.ok) {
            const data = await authRes.json()
            if (Array.isArray(data) && data.filter((p: any) => p.enabled).length === 0) {
              setNeedsAuthProviderConfig(true)
            } else {
              setNeedsAuthProviderConfig(false)
            }
          }
        } catch {
          // Ignore fetch error for providers
        }
      } else {
        // Fallback check to fleet overview if /auth/me is not ready
        const fleetRes = await fetch('/api/v1/fleet/overview')
        if (fleetRes.ok) {
          setAuthenticated(true)
          setUser({
            id: 'user',
            organization_id: '00000000-0000-0000-0000-000000000001',
            tenant_id: '00000000-0000-0000-0000-000000000001',
            organization_name: 'Primary Organization',
            license_tier: 'developer',
            max_devices: 1,
            enrolled_devices: 0,
            is_admin: true,
            is_saas_operator: false,
          })
        } else {
          setAuthenticated(false)
          setUser(null)
        }
      }
    } catch {
      setAuthenticated(false)
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    checkSession()
  }, [checkSession])

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      })

      if (res.ok) {
        const data = await res.json().catch(() => ({}))
        const isOperator = !!data.is_saas_operator
        const orgID = data.organization_id || data.tenant_id || '00000000-0000-0000-0000-000000000001'
        setAuthenticated(true)
        setUser({
          id: data.user_id || 'user',
          organization_id: orgID,
          tenant_id: orgID,
          organization_name: data.organization_name || 'Primary Organization',
          license_tier: data.license_tier || 'developer',
          max_devices: data.max_devices ?? 1,
          enrolled_devices: data.enrolled_devices ?? 0,
          is_admin: !!data.is_admin,
          is_saas_operator: isOperator,
          needs_password_setup: !isOperator && !!data.needs_password_setup,
        })
        setNeedsPasswordSetup(!isOperator && !!data.needs_password_setup)
        await checkSession()
      } else {
        if (res.status === 429) {
          setError('Too many login attempts. Please wait a few moments and try again.')
        } else if (res.status === 401) {
          setError('Invalid email, username, or password.')
        } else if (res.status === 403) {
          setError('Access denied. You do not have permission to access this portal.')
        } else if (res.status === 502) {
          setError('502 Bad Gateway: The Control Plane API backend is currently unreachable or starting up. Please check service health and try again.')
        } else if (res.status === 503 || res.status === 504) {
          setError(`Service unavailable (${res.status}). The Control Plane is temporarily unreachable.`)
        } else if (res.status >= 500) {
          setError(`Server error (${res.status}). Please check control plane logs or try again shortly.`)
        } else {
          try {
            const data = await res.text()
            if (!data || data.trim().startsWith('<') || data.toLowerCase().includes('<!doctype') || data.toLowerCase().includes('<html')) {
              setError(`Authentication failed with status ${res.status} (${res.statusText || 'Error'})`)
            } else {
              setError(data)
            }
          } catch {
            setError(`Login failed (${res.status})`)
          }
        }
      }
    } catch {
      setError('Network error')
    } finally {
      setLoading(false)
    }
  }, [checkSession])

  const logout = useCallback(async () => {
    try {
      await fetch('/api/v1/auth/logout', { method: 'POST' })
    } catch {
      // Ignore network errors on logout
    } finally {
      setAuthenticated(false)
      setUser(null)
    }
  }, [])

  const state: AuthState = {
    authenticated,
    loading,
    error,
    user,
    needsAuthProviderConfig,
    needsPasswordSetup,
    login,
    logout,
    checkSession,
  }

  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>
}
