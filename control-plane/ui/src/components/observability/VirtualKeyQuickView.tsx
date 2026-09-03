import { useEffect, useState } from 'react'
import { api, type VirtualKey } from '../../api/client'

interface Props {
  keyPrefixOrId: string
  onClose: () => void
}

function microcentsToUSD(m: number): number {
  return m / 100_000_000
}

export default function VirtualKeyQuickView({ keyPrefixOrId, onClose }: Props) {
  const [keys, setKeys] = useState<VirtualKey[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.listVirtualKeys()
      .then((res) => {
        setKeys(res.virtual_keys || [])
      })
      .catch((err) => console.error(err))
      .finally(() => setLoading(false))
  }, [])

  const matchedKey = keys.find(
    (k) => k.id === keyPrefixOrId || k.key_prefix === keyPrefixOrId || (k.name && k.name.toLowerCase() === keyPrefixOrId.toLowerCase())
  )

  return (
    <div className="dossier-overlay" onClick={onClose} style={{ zIndex: 1100 }}>
      <div
        className="dossier-drawer"
        style={{ width: 'min(480px, 90vw)' }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Virtual Key Quick View"
      >
        <div className="dossier-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 18 }}>🔑</span>
            <div>
              <h3 style={{ fontSize: 15, margin: 0 }}>Virtual Key Context</h3>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                {matchedKey?.name || keyPrefixOrId}
              </div>
            </div>
          </div>
          <button
            type="button"
            className="soc-btn-secondary"
            style={{ fontSize: 14, padding: '2px 6px' }}
            onClick={onClose}
          >
            ✕
          </button>
        </div>

        <div className="drawer-body" style={{ padding: 20 }}>
          {loading ? (
            <div className="loading" style={{ height: 120 }}>Resolving key context...</div>
          ) : matchedKey ? (
            <div className="dossier-kv-grid" style={{ gap: '12px 16px' }}>
              <span className="dossier-k">Alias / Name</span>
              <span className="dossier-v" style={{ fontWeight: 600 }}>{matchedKey.name || 'Unnamed Key'}</span>

              <span className="dossier-k">Prefix</span>
              <span className="dossier-v"><code className="obs-key-pill">{matchedKey.key_prefix}</code></span>

              <span className="dossier-k">Status</span>
              <span className="dossier-v">
                <span className={`badge ${matchedKey.status === 'active' ? 'green' : 'red'}`}>
                  {matchedKey.status.toUpperCase()}
                </span>
              </span>

              <span className="dossier-k">Monthly Budget</span>
              <span className="dossier-v" style={{ color: '#38bdf8' }}>
                ${microcentsToUSD(matchedKey.monthly_budget_microcents).toFixed(2)}
              </span>

              <span className="dossier-k">Spend to Date</span>
              <span className="dossier-v" style={{ color: '#10b981', fontWeight: 600 }}>
                ${microcentsToUSD(matchedKey.spent_microcents).toFixed(4)}
              </span>

              <span className="dossier-k">Allowed Models</span>
              <span className="dossier-v" style={{ fontSize: 12 }}>
                {matchedKey.allowed_models && matchedKey.allowed_models.length > 0
                  ? matchedKey.allowed_models.join(', ')
                  : 'All Authorized Models'}
              </span>

              <span className="dossier-k">Created By</span>
              <span className="dossier-v">{matchedKey.created_by}</span>
            </div>
          ) : (
            <div style={{ padding: 20, textAlign: 'center', color: 'var(--text-muted)' }}>
              Virtual Key <code>{keyPrefixOrId}</code> not found or may belong to an unauthenticated origin.
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
