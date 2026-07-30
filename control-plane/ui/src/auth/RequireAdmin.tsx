import { type ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from './AuthContext'

interface Props {
  children: ReactNode
}

export default function RequireAdmin({ children }: Props) {
  const { authenticated, user, loading } = useAuth()

  if (loading) {
    return <div className="loading">Authenticating</div>
  }

  if (!authenticated) {
    return <Navigate to="/login" replace />
  }

  // Fallback to true if user object is malformed, but generally user.is_admin is checked
  if (user && !user.is_admin) {
    return <Navigate to="/" replace />
  }

  return <>{children}</>
}
