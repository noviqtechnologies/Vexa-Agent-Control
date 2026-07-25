import { createContext, useContext, useEffect, useState, useCallback, type ReactNode } from 'react'

export interface AuthConfig {
  issuer: string
  clientId: string
  redirectUri: string
}

export interface AuthState {
  authenticated: boolean
  loading: boolean
  token: string | null
  user: { sub: string; email?: string } | null
  login: () => void
  logout: () => void
}

const AuthContext = createContext<AuthState>({
  authenticated: false,
  loading: true,
  token: null,
  user: null,
  login: () => {},
  logout: () => {},
})

export function useAuth() {
  return useContext(AuthContext)
}

function generateCodeVerifier(): string {
  const arr = new Uint8Array(32)
  crypto.getRandomValues(arr)
  return btoa(String.fromCharCode(...arr))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function generateCodeChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function parseJwt(token: string): Record<string, unknown> | null {
  try {
    const payload = token.split('.')[1]
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
  } catch {
    return null
  }
}

interface Props {
  config: AuthConfig | null
  children: ReactNode
}

export function AuthProvider({ config, children }: Props) {
  const [token, setToken] = useState<string | null>(null)
  const [user, setUser] = useState<AuthState['user']>(null)
  const [loading, setLoading] = useState(true)

  const login = useCallback(async () => {
    if (!config) return
    const verifier = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    sessionStorage.setItem('oidc_verifier', verifier)

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: config.clientId,
      redirect_uri: config.redirectUri,
      scope: 'openid email profile',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    })

    window.location.href = `${config.issuer}/authorize?${params}`
  }, [config])

  const logout = useCallback(() => {
    setToken(null)
    setUser(null)
    sessionStorage.removeItem('oidc_verifier')
  }, [])

  useEffect(() => {
    if (!config) {
      setLoading(false)
      return
    }

    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')

    if (code) {
      const verifier = sessionStorage.getItem('oidc_verifier')
      sessionStorage.removeItem('oidc_verifier')

      if (verifier) {
        fetch(`${config.issuer}/token`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({
            grant_type: 'authorization_code',
            code,
            redirect_uri: config.redirectUri,
            client_id: config.clientId,
            code_verifier: verifier,
          }),
        })
          .then((res) => res.json())
          .then((data) => {
            const idToken = data.id_token as string
            if (idToken) {
              setToken(idToken)
              const claims = parseJwt(idToken)
              if (claims) {
                setUser({ sub: claims.sub as string, email: claims.email as string })
              }
            }
            window.history.replaceState({}, '', window.location.pathname)
            setLoading(false)
          })
          .catch(() => setLoading(false))
      } else {
        setLoading(false)
      }
    } else {
      setLoading(false)
    }
  }, [config])

  // Dev mode: no config means auth is disabled, all routes accessible
  const devMode = !config
  const state: AuthState = {
    authenticated: devMode || !!token,
    loading,
    token,
    user: devMode ? { sub: 'dev-user', email: 'dev@localhost' } : user,
    login,
    logout,
  }

  return <AuthContext.Provider value={state}>{children}</AuthContext.Provider>
}
