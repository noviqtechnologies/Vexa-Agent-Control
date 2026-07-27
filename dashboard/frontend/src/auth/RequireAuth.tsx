import { type ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from './AuthContext'

interface Props {
  children: ReactNode
}

export default function RequireAuth({ children }: Props) {
  const { authenticated, loading } = useAuth()

  if (loading) {
    return <div className="loading">Authenticating</div>
  }

  if (!authenticated) {
    return <Navigate to="/login" replace />
  }

  return <>{children}</>
}
