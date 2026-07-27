import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react'

export interface AuthState {
  authenticated: boolean
  loading: boolean
  error: string | null
  user: { id: string; is_admin: boolean } | null
  login: (email: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthState>({
  authenticated: false,
  loading: true,
  error: null,
  user: null,
  login: async () => {},
  logout: () => {},
})

export function useAuth() {
  return useContext(AuthContext)
}

interface Props {
  children: ReactNode
}

export function AuthProvider({ children }: Props) {
  const [authenticated, setAuthenticated] = useState(false)
  const [user, setUser] = useState<AuthState['user']>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const checkSession = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/fleet/overview') // Quick auth check
      if (res.ok) {
        setAuthenticated(true)
        setUser({ id: 'user', is_admin: true }) // We can get real user details from /me if implemented
      } else {
        setAuthenticated(false)
        setUser(null)
      }
    } catch {
      setAuthenticated(false)
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
        setAuthenticated(true)
        // Redirection handled by component
      } else {
        const data = await res.text()
        setError(data || 'Login failed')
      }
    } catch (e) {
      setError('Network error')
    } finally {
      setLoading(false)
    }
  }, [])

  const logout = useCallback(async () => {
    await fetch('/api/v1/auth/logout', { method: 'POST' })
    setAuthenticated(false)
    setUser(null)
  }, [])

  const state: AuthState = {
    authenticated,
    loading,
    error,
    user,
    login,
    logout,
  }

  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>
}
