import { type ReactNode } from 'react'
import { useAuth } from './AuthContext'

interface Props {
  children: ReactNode
}

export default function RequireAuth({ children }: Props) {
  const { authenticated, loading, login } = useAuth()

  if (loading) {
    return <div className="loading">Authenticating</div>
  }

  if (!authenticated) {
    return (
      <div style={{ textAlign: 'center', padding: 64 }}>
        <h2 style={{ marginBottom: 16 }}>Sign in required</h2>
        <p style={{ color: 'var(--text-secondary)', marginBottom: 24 }}>
          You must authenticate to access the AgentWall dashboard.
        </p>
        <button className="refresh-btn" onClick={login}>
          Sign in with OIDC
        </button>
      </div>
    )
  }

  return <>{children}</>
}
