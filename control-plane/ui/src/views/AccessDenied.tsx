import { useAuth } from '../auth/AuthContext'

export default function AccessDenied() {
  const { user, logout } = useAuth()

  return (
    <div className="soc-access-denied-viewport" style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      width: '100%',
      padding: '24px',
      background: 'var(--bg-primary, #090d16)',
      color: 'var(--text-primary, #f8fafc)',
      fontFamily: 'system-ui, -apple-system, sans-serif'
    }}>
      <div style={{
        maxWidth: '520px',
        width: '100%',
        background: 'rgba(15, 23, 42, 0.85)',
        border: '1px solid rgba(239, 68, 68, 0.35)',
        borderRadius: '16px',
        padding: '36px 32px',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.5), 0 0 30px rgba(239, 68, 68, 0.1)',
        backdropFilter: 'blur(12px)',
        textAlign: 'center'
      }}>
        <div style={{
          width: '64px',
          height: '64px',
          margin: '0 auto 20px auto',
          borderRadius: '50%',
          background: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#ef4444'
        }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2"></rect>
            <path d="M7 11V7a5 5 0 0 1 10 0v4"></path>
          </svg>
        </div>

        <h2 style={{
          fontSize: '22px',
          fontWeight: 700,
          margin: '0 0 8px 0',
          color: '#f8fafc',
          letterSpacing: '-0.02em'
        }}>
          Access Restricted: Administrator Role Required
        </h2>

        <p style={{
          fontSize: '14px',
          color: 'var(--text-muted, #94a3b8)',
          lineHeight: '1.6',
          margin: '0 0 24px 0'
        }}>
          Access to the Vexa Agent Control <strong>SOC Console &amp; Control Hub</strong> is restricted exclusively to users with the <strong>Administrator</strong> role. Standard member accounts cannot view or modify fleet governance controls.
        </p>

        {user && (
          <div style={{
            background: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '10px',
            padding: '16px',
            marginBottom: '24px',
            textAlign: 'left',
            fontSize: '13px'
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted, #94a3b8)' }}>Authenticated Account:</span>
              <span style={{ fontWeight: 600, color: '#f8fafc' }}>{user.id}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
              <span style={{ color: 'var(--text-muted, #94a3b8)' }}>Organization:</span>
              <span style={{ color: '#cbd5e1' }}>{user.organization_name || 'Primary Organization'}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: 'var(--text-muted, #94a3b8)' }}>Assigned Role:</span>
              <span style={{
                background: 'rgba(148, 163, 184, 0.15)',
                color: '#cbd5e1',
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '12px',
                fontWeight: 600,
                border: '1px solid rgba(148, 163, 184, 0.3)'
              }}>
                Member (Non-Admin)
              </span>
            </div>
          </div>
        )}

        <div style={{
          fontSize: '13px',
          color: 'var(--text-muted, #94a3b8)',
          marginBottom: '28px',
          lineHeight: '1.5'
        }}>
          If you require access to the SOC Console, please contact your organization administrator to update your user role.
        </div>

        <button
          type="button"
          onClick={logout}
          style={{
            width: '100%',
            padding: '12px 20px',
            background: 'linear-gradient(180deg, #3b82f6 0%, #2563eb 100%)',
            border: '1px solid rgba(59, 130, 246, 0.4)',
            borderRadius: '8px',
            color: '#ffffff',
            fontWeight: 600,
            fontSize: '14px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '8px',
            transition: 'all 0.15s ease'
          }}
        >
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
            <polyline points="16 17 21 12 16 7" />
            <line x1="21" y1="12" x2="9" y2="12" />
          </svg>
          Sign Out / Switch Account
        </button>
      </div>
    </div>
  )
}
