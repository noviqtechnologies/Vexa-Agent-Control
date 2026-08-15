import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react'

export interface UserProfile {
  id: string
  tenant_id: string
  organization_name?: string
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
        setAuthenticated(true)
        setUser({
          id: userData.user_id || 'user',
          tenant_id: userData.tenant_id || '00000000-0000-0000-0000-000000000001',
          organization_name: userData.organization_name,
          is_admin: !!userData.is_admin,
          is_saas_operator: !!userData.is_saas_operator,
          needs_password_setup: !!userData.needs_password_setup,
        })
        setNeedsPasswordSetup(!!userData.needs_password_setup)
        
        // Also check if any auth providers are configured
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
            tenant_id: '00000000-0000-0000-0000-000000000001',
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
        setAuthenticated(true)
        setUser({
          id: data.user_id || 'user',
          tenant_id: data.tenant_id || '00000000-0000-0000-0000-000000000001',
          organization_name: data.organization_name,
          is_admin: !!data.is_admin,
          is_saas_operator: !!data.is_saas_operator,
        })
        // Refresh session context
        await checkSession()
      } else {
        const data = await res.text()
        setError(data || 'Login failed')
      }
    } catch (e) {
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
