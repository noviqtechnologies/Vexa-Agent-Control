import { type ReactNode } from 'react'
import { Navigate } from 'react-router-dom'
import { useAuth } from './AuthContext'
import AccessDenied from '../views/AccessDenied'

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

  if (user && !user.is_admin) {
    return <AccessDenied />
  }

  return <>{children}</>
}

