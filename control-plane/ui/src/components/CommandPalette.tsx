import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'

export interface CommandItem {
  id: string
  title: string
  category: 'Navigation' | 'Policy' | 'Security & Audit' | 'Governance' | 'Integrations' | 'Actions'
  description?: string
  action: () => void
  shortcut?: string
}

interface CommandPaletteProps {
  isOpen?: boolean
  onClose?: () => void
}

export default function CommandPalette({ isOpen: controlledIsOpen, onClose }: CommandPaletteProps) {
  const [internalIsOpen, setInternalIsOpen] = useState(false)
  const isControlled = controlledIsOpen !== undefined
  const isOpen = isControlled ? controlledIsOpen : internalIsOpen

  const [query, setQuery] = useState('')
  const [selectedIndex, setSelectedIndex] = useState(0)
  const [copiedNotification, setCopiedNotification] = useState<string | null>(null)
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)

  const handleClose = () => {
    if (isControlled && onClose) {
      onClose()
    } else {
      setInternalIsOpen(false)
    }
    setQuery('')
    setSelectedIndex(0)
  }

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        if (isControlled && onClose) {
          if (isOpen) onClose()
        } else {
          setInternalIsOpen((prev) => !prev)
        }
      } else if (e.key === 'Escape' && isOpen) {
        e.preventDefault()
        handleClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, isControlled, onClose])

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [isOpen])

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text)
    setCopiedNotification(label)
    setTimeout(() => setCopiedNotification(null), 2000)
    handleClose()
  }

  const commands: CommandItem[] = [
    {
      id: 'nav-fleet',
      title: 'Fleet Overview & Command',
      category: 'Navigation',
      description: 'Real-time agent health, telemetry velocity, and live threat feed',
      action: () => navigate('/fleet'),
      shortcut: 'G F',
    },
    {
      id: 'nav-identity',
      title: 'Agent Identity & PKI Governance',
      category: 'Governance',
      description: 'Ed25519 secure enclave credentials and rotation status',
      action: () => navigate('/identity'),
      shortcut: 'G I',
    },
    {
      id: 'nav-policy-active',
      title: 'Active Policies & Rules',
      category: 'Policy',
      description: 'Tool invocation and LLM egress schema enforcement',
      action: () => navigate('/policy'),
      shortcut: 'G P',
    },
    {
      id: 'nav-policy-edit',
      title: 'Policy Editor',
      category: 'Policy',
      description: 'Interactive YAML policy authoring and validation',
      action: () => navigate('/policy/edit'),
    },
    {
      id: 'nav-policy-group',
      title: 'Group Policies',
      category: 'Policy',
      description: 'Multi-tenant role-based policy templates',
      action: () => navigate('/policy/group'),
    },
    {
      id: 'nav-safe-mode',
      title: 'Safe Mode & Air-Gap Toggles',
      category: 'Policy',
      description: 'Emergency isolation and egress circuit breaking',
      action: () => navigate('/policy/safe-mode'),
    },
    {
      id: 'nav-threats',
      title: 'Threat Intelligence & Injection Matrix',
      category: 'Security & Audit',
      description: 'DLP findings, prompt injections, and semantic anomalies',
      action: () => navigate('/threats'),
      shortcut: 'G T',
    },
    {
      id: 'nav-audit',
      title: 'Cryptographic Audit Trail',
      category: 'Security & Audit',
      description: 'HMAC verifiable event log and tamper-evident stream',
      action: () => navigate('/audit'),
      shortcut: 'G A',
    },
    {
      id: 'nav-audit-denied',
      title: 'Filtered Audit: Blocked Denials',
      category: 'Security & Audit',
      description: 'Jump to filtered view of all policy violations and blocked tool calls',
      action: () => navigate('/audit?decision=denied'),
    },
    {
      id: 'nav-devices',
      title: 'Device Governance & Token Enrollment',
      category: 'Governance',
      description: 'Workstation fleet governance, IDE Sentry locking, and PKI enrollment',
      action: () => navigate('/devices'),
      shortcut: 'G D',
    },
    {
      id: 'nav-users',
      title: 'User Management & Roles',
      category: 'Governance',
      description: 'Enterprise RBAC, SOC operators, and admin privileges',
      action: () => navigate('/admin/users'),
    },
    {
      id: 'nav-auth-providers',
      title: 'Auth Providers & SSO',
      category: 'Governance',
      description: 'OIDC, SAML 2.0, GitHub, and Google OAuth setup',
      action: () => navigate('/admin/auth-providers'),
    },
    {
      id: 'nav-spend-limits',
      title: 'LLM Spend Limits & Budgets',
      category: 'Governance',
      description: 'Token spend thresholds and monthly cost caps',
      action: () => navigate('/spend/limits'),
    },
    {
      id: 'nav-spend-requests',
      title: 'Spend Increase Requests',
      category: 'Governance',
      description: 'Approve or deny developer budget escalation requests',
      action: () => navigate('/spend/requests'),
    },
    {
      id: 'nav-spend-status',
      title: 'Real-Time Spend Status',
      category: 'Governance',
      description: 'Fleet-wide token consumption and balance tracking',
      action: () => navigate('/spend/status'),
    },
    {
      id: 'nav-spend-vis',
      title: 'Spend Visualizations',
      category: 'Governance',
      description: 'Cost breakdowns by agent, team, and LLM model',
      action: () => navigate('/spend/visualization'),
    },
    {
      id: 'nav-mcp',
      title: 'MCP Server Registry',
      category: 'Integrations',
      description: 'Model Context Protocol endpoints and schema controls',
      action: () => navigate('/integrations/mcp-servers'),
    },
    {
      id: 'nav-llm',
      title: 'LLM Egress Gateways',
      category: 'Integrations',
      description: 'Anthropic, OpenAI, AWS Bedrock, and Azure routing',
      action: () => navigate('/integrations/llm-providers'),
    },
    {
      id: 'act-copy-linux',
      title: 'Copy Linux / macOS Quickstart Script',
      category: 'Actions',
      description: 'curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash',
      action: () => copyToClipboard('curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash', 'Linux/macOS install script copied!'),
    },
    {
      id: 'act-copy-win',
      title: 'Copy Windows Quickstart Script',
      category: 'Actions',
      description: 'irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex',
      action: () => copyToClipboard('irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex', 'Windows install script copied!'),
    },
  ]

  const filteredCommands = commands.filter((c) => {
    const q = query.toLowerCase()
    return (
      c.title.toLowerCase().includes(q) ||
      c.category.toLowerCase().includes(q) ||
      (c.description && c.description.toLowerCase().includes(q))
    )
  })

  const handleKeyDownInList = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSelectedIndex((prev) => (prev + 1) % Math.max(1, filteredCommands.length))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSelectedIndex((prev) => (prev - 1 + filteredCommands.length) % Math.max(1, filteredCommands.length))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (filteredCommands[selectedIndex]) {
        filteredCommands[selectedIndex].action()
        handleClose()
      }
    }
  }

  if (!isOpen) return null

  return (
    <div className="command-palette-backdrop" onClick={handleClose} role="dialog" aria-modal="true" aria-label="Global Command Palette">
      <div className="command-palette-modal" onClick={(e) => e.stopPropagation()} onKeyDown={handleKeyDownInList}>
        <div className="command-palette-header">
          <div className="command-search-icon">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
          </div>
          <input
            ref={inputRef}
            className="command-palette-input"
            placeholder="Search policies, agents, audit logs, or actions... (ESC to exit)"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setSelectedIndex(0)
            }}
          />
          <span className="command-kbd-badge">ESC</span>
        </div>

        {copiedNotification && (
          <div className="command-palette-notification">
            ✓ {copiedNotification}
          </div>
        )}

        <div className="command-palette-results">
          {filteredCommands.length === 0 ? (
            <div className="command-palette-empty">
              <div className="empty-icon">🔍</div>
              <p>No matching commands or routes found for &ldquo;{query}&rdquo;</p>
              <span>Try searching for &ldquo;policy&rdquo;, &ldquo;denied&rdquo;, &ldquo;install&rdquo;, or &ldquo;devices&rdquo;</span>
            </div>
          ) : (
            filteredCommands.map((cmd, idx) => {
              const isSelected = idx === selectedIndex
              return (
                <div
                  key={cmd.id}
                  className={`command-item ${isSelected ? 'selected' : ''}`}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  onClick={() => {
                    cmd.action()
                    handleClose()
                  }}
                >
                  <div className="command-item-main">
                    <div className="command-title-row">
                      <span className="command-title">{cmd.title}</span>
                      <span className={`command-category-pill cat-${cmd.category.toLowerCase().replace(/[^a-z0-9]/g, '')}`}>
                        {cmd.category}
                      </span>
                    </div>
                    {cmd.description && (
                      <span className="command-desc">{cmd.description}</span>
                    )}
                  </div>
                  <div className="command-item-trail">
                    {cmd.shortcut && <span className="command-shortcut">{cmd.shortcut}</span>}
                    <span className="command-enter-icon">↵</span>
                  </div>
                </div>
              )
            })
          )}
        </div>

        <div className="command-palette-footer">
          <div className="footer-keys">
            <span><kbd>↑</kbd> <kbd>↓</kbd> to navigate</span>
            <span><kbd>↵</kbd> to select</span>
            <span><kbd>ESC</kbd> to dismiss</span>
          </div>
          <span className="footer-brand">Vexa Agent Control SOC</span>
        </div>
      </div>
    </div>
  )
}
