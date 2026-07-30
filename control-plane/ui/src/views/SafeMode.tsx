import { useEffect, useState } from 'react'

interface SafeModeRule {
  name: string
  category: 'Sensitive File Paths' | 'Dangerous Commands' | 'Network / SSRF'
  pattern: string
  riskLevel: 'critical' | 'high' | 'medium'
}

const SAFE_MODE_RULES: SafeModeRule[] = [
  // Sensitive File Paths (10)
  { name: 'Block SSH keys dir', category: 'Sensitive File Paths', pattern: '.ssh/', riskLevel: 'critical' },
  { name: 'Block id_rsa', category: 'Sensitive File Paths', pattern: 'id_rsa', riskLevel: 'critical' },
  { name: 'Block id_ed25519', category: 'Sensitive File Paths', pattern: 'id_ed25519', riskLevel: 'critical' },
  { name: 'Block id_ecdsa', category: 'Sensitive File Paths', pattern: 'id_ecdsa', riskLevel: 'critical' },
  { name: 'Block .env files', category: 'Sensitive File Paths', pattern: '.env', riskLevel: 'high' },
  { name: 'Block AWS credentials', category: 'Sensitive File Paths', pattern: '.aws/credentials', riskLevel: 'critical' },
  { name: 'Block kubeconfig', category: 'Sensitive File Paths', pattern: '.kube/config', riskLevel: 'critical' },
  { name: 'Block /etc/shadow', category: 'Sensitive File Paths', pattern: '/etc/shadow', riskLevel: 'critical' },
  { name: 'Block Docker config', category: 'Sensitive File Paths', pattern: '.docker/config.json', riskLevel: 'high' },
  { name: 'Block Docker socket', category: 'Sensitive File Paths', pattern: 'docker.sock', riskLevel: 'critical' },
  // Dangerous Commands (4)
  { name: 'Block curl|bash', category: 'Dangerous Commands', pattern: 'curl … | bash', riskLevel: 'critical' },
  { name: 'Block wget|sh', category: 'Dangerous Commands', pattern: 'wget … | sh/python/perl/ruby', riskLevel: 'critical' },
  { name: 'Block nc listener', category: 'Dangerous Commands', pattern: 'nc -l / nc -e', riskLevel: 'critical' },
  { name: 'Block rm -rf /', category: 'Dangerous Commands', pattern: 'rm -rf /', riskLevel: 'critical' },
  // Network / SSRF (1)
  { name: 'Block IMDS endpoint', category: 'Network / SSRF', pattern: '169.254.169.254 / metadata.google.internal', riskLevel: 'high' },
]

const CATEGORY_ORDER = ['Sensitive File Paths', 'Dangerous Commands', 'Network / SSRF'] as const

const RISK_BADGE: Record<string, string> = {
  critical: 'badge-danger',
  high: 'badge-warning',
  medium: 'badge-info',
}

export default function SafeMode() {
  const [isActive, setIsActive] = useState<boolean | null>(null)

  useEffect(() => {
    fetch('/api/v1/policy/safe-mode/status')
      .then(r => r.ok ? r.json() : null)
      .then(data => setIsActive(data?.active ?? true))
      .catch(() => setIsActive(true)) // Safe mode defaults to ON
  }, [])

  const byCategory = CATEGORY_ORDER.map(cat => ({
    category: cat,
    rules: SAFE_MODE_RULES.filter(r => r.category === cat),
  }))

  return (
    <>
      <div className="page-header">
        <h1>Safe Mode</h1>
        <p>
          15 high-signal built-in rules that block dangerous tool calls without any policy
          configuration. Safe Mode runs before the policy engine.
        </p>
      </div>

      {/* Status tiles */}
      <div className="stats-grid" style={{ marginBottom: 24 }}>
        <div className="card stat-tile">
          {isActive === null ? (
            <div className="stat-value" style={{ fontSize: 18 }}>—</div>
          ) : (
            <div className="stat-value" style={{ color: isActive ? 'var(--success)' : 'var(--danger)', fontSize: 22 }}>
              {isActive ? '● Active' : '○ Disabled'}
            </div>
          )}
          <div className="stat-label">Safe Mode Status</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value">15</div>
          <div className="stat-label">Total Rules</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--danger)' }}>10</div>
          <div className="stat-label">File Path Rules</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--warning)' }}>4</div>
          <div className="stat-label">Command Rules</div>
        </div>
        <div className="card stat-tile">
          <div className="stat-value" style={{ color: 'var(--accent)' }}>1</div>
          <div className="stat-label">Network / SSRF Rules</div>
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div className="card-title">How Safe Mode Works</div>
        <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
          Safe Mode is <strong style={{ color: 'var(--text-primary)' }}>enabled by default</strong> and
          cannot be disabled at runtime. It applies before the policy engine — it protects agents even
          in shadow mode (<code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, background: 'rgba(255,255,255,0.07)', padding: '1px 5px', borderRadius: 3 }}>agentwall dev</code>)
          where no policy file is loaded. Each rule targets only the relevant parameter type (file
          path, command, or URL), minimizing false positives.
        </p>
        <p style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 8 }}>
          Source: <code style={{ fontFamily: 'var(--font-mono)', fontSize: 11 }}>src/policy/safe_mode.rs</code>
        </p>
      </div>

      {byCategory.map(({ category, rules }) => (
        <div className="card" key={category} style={{ marginBottom: 16 }}>
          <div className="card-title">{category} ({rules.length})</div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Rule Name</th>
                  <th>Blocked Pattern</th>
                  <th>Risk Level</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rules.map(rule => (
                  <tr key={rule.name}>
                    <td style={{ fontWeight: 500, color: 'var(--text-primary)', fontSize: 13 }}>{rule.name}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-secondary)' }}>
                      {rule.pattern}
                    </td>
                    <td>
                      <span className={`badge ${RISK_BADGE[rule.riskLevel]}`}>
                        {rule.riskLevel}
                      </span>
                    </td>
                    <td>
                      <span className="badge badge-success">Enforced</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </>
  )
}
