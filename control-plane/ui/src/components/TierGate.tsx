import React from 'react'

export type LicenseTier = 'developer' | 'team' | 'enterprise'

interface TierGateProps {
  currentTier?: LicenseTier | string
  requiredTier: LicenseTier
  featureName: string
  children: React.ReactNode
  fallback?: React.ReactNode
}

const tierLevels: Record<string, number> = {
  developer: 1,
  team: 2,
  enterprise: 3,
}

export const TierGate: React.FC<TierGateProps> = ({
  currentTier = 'developer',
  requiredTier,
  featureName,
  children,
  fallback,
}) => {
  const currentLevel = tierLevels[currentTier?.toLowerCase()] || 1
  const requiredLevel = tierLevels[requiredTier.toLowerCase()] || 1

  if (currentLevel >= requiredLevel) {
    return <>{children}</>
  }

  if (fallback) {
    return <>{fallback}</>
  }

  return (
    <div style={{
      padding: '24px',
      margin: '16px 0',
      borderRadius: '8px',
      border: '1px solid #334155',
      background: 'linear-gradient(180deg, #1e293b 0%, #0f172a 100%)',
      color: '#f8fafc',
      textAlign: 'center',
    }}>
      <div style={{ fontSize: '24px', marginBottom: '8px' }}>🔒</div>
      <h3 style={{ fontSize: '16px', fontWeight: 600, margin: '0 0 8px 0', color: '#e2e8f0' }}>
        {featureName} Requires {requiredTier.toUpperCase()} Tier
      </h3>
      <p style={{ fontSize: '13px', color: '#94a3b8', maxWidth: '480px', margin: '0 auto 16px auto', lineHeight: '1.5' }}>
        Your organization is currently running on the <strong>{currentTier.toUpperCase()}</strong> tier.
        To unlock {featureName}, upgrade your organization license.
      </p>
      <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '6px 12px', background: '#3b82f620', border: '1px solid #3b82f640', borderRadius: '6px', fontSize: '12px', color: '#60a5fa' }}>
        <span>Navigate to <strong>Settings &gt; License</strong> to apply a valid license key.</span>
      </div>
    </div>
  )
}
