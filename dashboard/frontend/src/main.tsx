import React from 'react'
import ReactDOM from 'react-dom/client'
import { BrowserRouter } from 'react-router-dom'
import { AuthProvider, type AuthConfig } from './auth/AuthContext'
import App from './App'
import './index.css'

const oidcIssuer = import.meta.env.VITE_OIDC_ISSUER as string | undefined
const oidcClientId = import.meta.env.VITE_OIDC_CLIENT_ID as string | undefined

const authConfig: AuthConfig | null =
  oidcIssuer && oidcClientId
    ? { issuer: oidcIssuer, clientId: oidcClientId, redirectUri: window.location.origin }
    : null

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <BrowserRouter>
      <AuthProvider config={authConfig}>
        <App />
      </AuthProvider>
    </BrowserRouter>
  </React.StrictMode>,
)
