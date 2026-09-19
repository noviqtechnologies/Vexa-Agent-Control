import { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import DeveloperQuickstart from '../components/DeveloperQuickstart'

export default function DeveloperGuide() {
  const { user } = useAuth()
  const hubOrigin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'
  const proxyEndpoint = `${typeof window !== 'undefined' ? window.location.protocol : 'http:'}//${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8080/v1`

  const [copiedField, setCopiedField] = useState<string | null>(null)

  const copyToClipboard = (text: string, field: string) => {
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(text)
      }
    } catch {}
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  return (
    <div className="soc-developer-guide-page" style={{ maxWidth: '1200px', margin: '0 auto', paddingBottom: '40px' }}>
      {/* Page Header */}
      <div className="page-header soc-page-header" style={{ marginBottom: '20px' }}>
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <span>🚀</span>
            <span>Developer Quickstart &amp; Gateway Setup</span>
          </h1>
          <p style={{ marginTop: '4px', color: 'var(--text-muted, #94a3b8)', fontSize: '13.5px' }}>
            Welcome to the Vexa Agent Control Developer Workspace. Configure your local AI tools, IDEs, and scripts to route securely through the DLP proxy.
          </p>
        </div>
        <div className="soc-header-controls">
          <div
            style={{
              padding: '6px 12px',
              borderRadius: '20px',
              background: 'rgba(99, 102, 241, 0.1)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              color: '#c7d2fe',
              fontSize: '12px',
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
            }}
          >
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22c55e' }} />
            <span>Member Access • {user?.organization_name || 'Organization Workspace'}</span>
          </div>
        </div>
      </div>

      {/* Connection Endpoint Quick Reference Card */}
      <div
        style={{
          marginBottom: '24px',
          padding: '16px 20px',
          borderRadius: '10px',
          background: 'rgba(15, 23, 42, 0.6)',
          border: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '16px',
          alignItems: 'center',
        }}
      >
        <div>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>
            Proxy Gateway Base URL
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
            <code style={{ fontSize: '13px', color: '#38bdf8', background: 'rgba(56, 189, 248, 0.1)', padding: '3px 8px', borderRadius: '4px', fontFamily: 'var(--font-mono, monospace)' }}>
              {proxyEndpoint}
            </code>
            <button
              type="button"
              onClick={() => copyToClipboard(proxyEndpoint, 'endpoint')}
              style={{
                background: 'transparent',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#fff',
                borderRadius: '4px',
                padding: '2px 8px',
                fontSize: '11px',
                cursor: 'pointer',
              }}
            >
              {copiedField === 'endpoint' ? '✓ Copied' : 'Copy'}
            </button>
          </div>
        </div>

        <div>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>
            Control Hub URL
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
            <code style={{ fontSize: '13px', color: '#a78bfa', background: 'rgba(167, 139, 250, 0.1)', padding: '3px 8px', borderRadius: '4px', fontFamily: 'var(--font-mono, monospace)' }}>
              {hubOrigin}
            </code>
            <button
              type="button"
              onClick={() => copyToClipboard(hubOrigin, 'hub')}
              style={{
                background: 'transparent',
                border: '1px solid rgba(255, 255, 255, 0.15)',
                color: '#fff',
                borderRadius: '4px',
                padding: '2px 8px',
                fontSize: '11px',
                cursor: 'pointer',
              }}
            >
              {copiedField === 'hub' ? '✓ Copied' : 'Copy'}
            </button>
          </div>
        </div>

        <div>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted, #94a3b8)', fontWeight: 600 }}>
            Developer Identity
          </div>
          <div style={{ marginTop: '4px', fontSize: '13px', color: '#f1f5f9', fontWeight: 500 }}>
            {user?.id || 'Authenticated Member'}
          </div>
        </div>
      </div>

      {/* Primary OS-Aware Quickstart Component */}
      <DeveloperQuickstart forceOpen={true} />

      {/* Developer FAQ / Security Best Practices */}
      <div
        style={{
          marginTop: '24px',
          padding: '18px 22px',
          borderRadius: '10px',
          background: 'rgba(15, 23, 42, 0.4)',
          border: '1px solid rgba(255, 255, 255, 0.06)',
        }}
      >
        <h3 style={{ margin: '0 0 12px', fontSize: '14px', fontWeight: 600, color: '#fff', display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span>🛡️</span> Security &amp; Compliance Notes for Developers
        </h3>
        <ul style={{ margin: 0, paddingLeft: '20px', fontSize: '12.5px', color: 'var(--text-muted, #94a3b8)', lineHeight: 1.7 }}>
          <li>
            <strong style={{ color: '#e2e8f0' }}>Zero-Touch Authentication:</strong> Running <code>agentcontrol login</code> authenticates your developer session directly with Microsoft Entra ID or Google Workspace SSO.
          </li>
          <li>
            <strong style={{ color: '#e2e8f0' }}>Automated PII &amp; Secret Redaction:</strong> All outgoing requests are scanned locally and on the proxy for API keys, passwords, and sensitive client PII before reaching external LLM providers.
          </li>
          <li>
            <strong style={{ color: '#e2e8f0' }}>Need Admin Privileges?</strong> If you require access to configure organization spend limits or auth providers, contact your organization administrator to elevate your account role.
          </li>
        </ul>
      </div>
    </div>
  )
}
