import { type ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from './AuthContext'

interface Props {
  children: ReactNode
}

export default function RequireOperator({ children }: Props) {
  const { authenticated, user, loading } = useAuth()

  if (loading) {
    return <div className="loading">Verifying Platform Permissions...</div>
  }

  if (!authenticated) {
    return <Navigate to="/login" replace />
  }

  // Only users flagged as SaaS Operator can access platform administration
  if (!user || !user.is_saas_operator) {
    return <Navigate to="/fleet" replace />
  }

  return <>{children}</>
}
