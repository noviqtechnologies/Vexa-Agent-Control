import { useState, useEffect } from 'react'
import { useAuth } from '../auth/AuthContext'
import './Login.css'

interface PublicProvider {
  id: string
  type: string
  name: string
}

export default function Login() {
  const { login, error: authError } = useAuth()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  
  const [providers, setProviders] = useState<PublicProvider[]>([])
  const [loadingProviders, setLoadingProviders] = useState(true)

  useEffect(() => {
    async function fetchProviders() {
      try {
        const res = await fetch('/api/v1/auth/providers')
        if (res.ok) {
          const data = await res.json()
          setProviders(Array.isArray(data) ? data : [])
        }
      } catch (err) {
        console.error('Failed to fetch providers', err)
      } finally {
        setLoadingProviders(false)
      }
    }
    fetchProviders()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    await login(email, password)
  }

  const oauthProviders = providers.filter(p => p.type !== 'local')
  const hasLocal = providers.some(p => p.type === 'local')
  const noProviders = providers.length === 0

  return (
    <div className="login-container">
      <div className="login-card glass">
        <h2>AgentWall Login</h2>
        <p>Sign in to your dashboard</p>
        
        {authError && <div className="login-error">{authError}</div>}
        
        {loadingProviders ? (
          <div style={{ textAlign: 'center', padding: '20px', color: 'var(--text-muted)' }}>Loading...</div>
        ) : (
          <div className="login-methods">
            {(hasLocal || noProviders) && (
              <form onSubmit={handleSubmit} className="local-login-form">
                <div className="form-group">
                  <label>Email / Username</label>
                  <input 
                    type="text" 
                    value={email} 
                    onChange={e => setEmail(e.target.value)}
                    placeholder="admin or user@example.com"
                    required 
                  />
                </div>
                <div className="form-group">
                  <label>{noProviders ? "Password or Bootstrap Token" : "Password"}</label>
                  <input 
                    type="password" 
                    value={password} 
                    onChange={e => setPassword(e.target.value)}
                    required 
                  />
                </div>
                <button type="submit" className="login-btn">Sign In</button>
              </form>
            )}

            {oauthProviders.length > 0 && (
              <>
                {(hasLocal || noProviders) && <div className="login-divider"><span>OR</span></div>}
                <div className="oauth-buttons">
                  {oauthProviders.map(p => (
                    <button 
                      key={p.id}
                      type="button" 
                      className={`oauth-btn oauth-btn-${p.type}`}
                      onClick={() => { window.location.href = `/api/v1/auth/oauth/${p.id}/login` }}
                    >
                      <ProviderIcon type={p.type} />
                      <span>Sign in with {p.name}</span>
                    </button>
                  ))}
                </div>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function ProviderIcon({ type }: { type: string }) {
  if (type === 'github') {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
        <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
      </svg>
    )
  }
  if (type === 'google') {
    return (
      <svg width="20" height="20" viewBox="0 0 24 24">
        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
      </svg>
    )
  }
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
      <circle cx="12" cy="7" r="4" />
    </svg>
  )
}
