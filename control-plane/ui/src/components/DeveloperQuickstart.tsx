import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export type OSType = 'windows' | 'macos' | 'linux'
export type ToolType = 'cli' | 'cursor' | 'claude' | 'python' | 'node'

function detectUserOS(): OSType {
  if (typeof window === 'undefined' || !window.navigator) return 'windows'
  const userAgent = (window.navigator.userAgent || '').toLowerCase()
  const platform = ((window.navigator as any).userAgentData?.platform || window.navigator.platform || '').toLowerCase()

  if (platform.includes('win') || userAgent.includes('windows')) {
    return 'windows'
  }
  if (platform.includes('mac') || userAgent.includes('macintosh') || userAgent.includes('mac os')) {
    return 'macos'
  }
  if (platform.includes('linux') || userAgent.includes('linux') || userAgent.includes('x11')) {
    return 'linux'
  }
  return 'windows'
}

interface DeveloperQuickstartProps {
  forceOpen?: boolean
  onClose?: () => void
}

function safeGetItem(key: string): string | null {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined' && window.localStorage?.getItem) {
      return window.localStorage.getItem(key)
    }
  } catch {
    // Ignore storage exceptions in restricted test / sandboxed environments
  }
  return null
}

function safeSetItem(key: string, value: string): void {
  try {
    if (typeof window !== 'undefined' && typeof window.localStorage !== 'undefined' && window.localStorage?.setItem) {
      window.localStorage.setItem(key, value)
    }
  } catch {
    // Ignore storage exceptions
  }
}

export default function DeveloperQuickstart({ forceOpen, onClose }: DeveloperQuickstartProps) {
  let user: any = null
  try {
    const auth = useAuth()
    user = auth?.user
  } catch {
    // Component rendered outside AuthProvider in isolated tests
  }

  const [os, setOs] = useState<OSType>('windows')
  const [tool, setTool] = useState<ToolType>('cli')
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [dismissed, setDismissed] = useState<boolean>(false)

  const storageKey = user?.id ? `agentwall_dev_onboarding_dismissed_${user.id}` : 'agentwall_dev_onboarding_dismissed'

  useEffect(() => {
    setOs(detectUserOS())
    if (safeGetItem(storageKey) === 'true') {
      setDismissed(true)
    }
  }, [storageKey])

  const handleDismiss = () => {
    safeSetItem(storageKey, 'true')
    setDismissed(true)
    if (onClose) onClose()
  }

  const copyToClipboard = (text: string, key: string) => {
    try {
      if (navigator?.clipboard?.writeText) {
        navigator.clipboard.writeText(text)
      }
    } catch {
      // Ignore clipboard failure in testing environments
    }
    setCopiedKey(key)
    setTimeout(() => setCopiedKey(null), 2000)
  }

  if (dismissed && !forceOpen) {
    return null
  }

  const hubOrigin = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000'
  const proxyEndpoint = `${typeof window !== 'undefined' ? window.location.protocol : 'http:'}//${typeof window !== 'undefined' ? window.location.hostname : 'localhost'}:8080/v1`

  // CLI Install & Login Snippets
  const getCliInstallSnippet = () => {
    switch (os) {
      case 'windows':
        return `# Step 1: Install Vexa Agent Control CLI (PowerShell)
irm https://vexasec.io/install.ps1 | iex

# Step 2: Zero-Touch SSO / Workstation Enrollment
agentcontrol login --hub ${hubOrigin}

# Step 3: Start the local zero-trust proxy daemon
agentcontrol start`
      case 'macos':
        return `# Step 1: Install Vexa Agent Control CLI (Terminal/zsh)
curl -fsSL https://vexasec.io/install.sh | bash

# Step 2: Zero-Touch SSO / Workstation Enrollment
agentcontrol login --hub ${hubOrigin}

# Step 3: Start the local zero-trust proxy daemon
agentcontrol start`
      case 'linux':
        return `# Step 1: Install Vexa Agent Control CLI (bash)
curl -fsSL https://vexasec.io/install.sh | bash

# Step 2: Zero-Touch SSO / Workstation Enrollment
agentcontrol login --hub ${hubOrigin}

# Step 3: Start the local zero-trust proxy daemon
agentcontrol start`
    }
  }

  // Tool specific configurations
  const getToolSnippet = () => {
    switch (tool) {
      case 'cli':
        return getCliInstallSnippet()

      case 'cursor':
        return `// Add to your Cursor Settings (Settings -> Models -> OpenAI API Key / Base URL)
// Or in your workspace .cursor/settings.json:
{
  "cursor.openAiBaseUrl": "${proxyEndpoint}",
  "cursor.anthropicBaseUrl": "${proxyEndpoint}"
}`

      case 'claude':
        if (os === 'windows') {
          return `# Configure Claude Code CLI in Windows PowerShell
$env:ANTHROPIC_BASE_URL="${proxyEndpoint}"
claude "Review security policies for our workspace"`
        }
        return `# Configure Claude Code CLI in macOS / Linux (bash/zsh)
export ANTHROPIC_BASE_URL="${proxyEndpoint}"
claude "Review security policies for our workspace"`

      case 'python':
        return `# Python SDK Integration (OpenAI & Anthropic)
from openai import OpenAI

client = OpenAI(
    base_url="${proxyEndpoint}",
    api_key="vw_live_your_key_here"  # Or local agentcontrol token
)

response = client.chat.completions.create(
    model="gpt-4o",
    messages=[{"role": "user", "content": "Hello Vexa Agent Control!"}]
)
print(response.choices[0].message.content)`

      case 'node':
        return `// Node.js / TypeScript SDK Integration
import OpenAI from 'openai';

const client = new OpenAI({
  baseURL: '${proxyEndpoint}',
  apiKey: process.env.AGENTCONTROL_TOKEN || 'vw_live_your_key_here',
});

const response = await client.chat.completions.create({
  model: 'gpt-4o',
  messages: [{ role: 'user', content: 'Hello Vexa Agent Control!' }],
});
console.log(response.choices[0].message.content);`
    }
  }

  return (
    <div
      className="dev-quickstart-card"
      data-testid="dev-quickstart-card"
      style={{
        marginBottom: '24px',
        padding: '20px 24px',
        borderRadius: '12px',
        background: 'linear-gradient(135deg, rgba(30, 27, 75, 0.45) 0%, rgba(15, 23, 42, 0.75) 100%)',
        border: '1px solid rgba(99, 102, 241, 0.35)',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.25)',
        position: 'relative',
      }}
    >
      {/* Header Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #6366f1 0%, #4f46e5 100%)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '18px',
              boxShadow: '0 2px 10px rgba(99, 102, 241, 0.4)',
            }}
          >
            🚀
          </div>
          <div>
            <h2 style={{ margin: 0, fontSize: '16px', fontWeight: 600, color: '#fff', display: 'flex', alignItems: 'center', gap: '8px' }}>
              Developer Quickstart Guide
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 500,
                  padding: '2px 8px',
                  borderRadius: '12px',
                  background: 'rgba(99, 102, 241, 0.2)',
                  color: '#a5b4fc',
                  border: '1px solid rgba(99, 102, 241, 0.4)',
                }}
              >
                Zero-Touch Proxy
              </span>
            </h2>
            <p style={{ margin: '3px 0 0', fontSize: '12.5px', color: '#94a3b8' }}>
              Welcome to the Workspace! Route your local AI coding tools and LLM requests through Vexa Agent Control's secure DLP gateway.
            </p>
          </div>
        </div>

        {/* Dismiss / Close Action */}
        <button
          type="button"
          onClick={handleDismiss}
          style={{
            background: 'transparent',
            border: 'none',
            color: '#64748b',
            cursor: 'pointer',
            padding: '4px 8px',
            fontSize: '12px',
            borderRadius: '4px',
            display: 'flex',
            alignItems: 'center',
            gap: '4px',
          }}
          title="Dismiss quickstart banner"
        >
          <span>✕ Dismiss</span>
        </button>
      </div>

      {/* 3 Step Interactive Workflow */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px', marginBottom: '18px' }}>
        
        {/* Step 1: OS Selection */}
        <div style={{ padding: '12px 14px', borderRadius: '8px', background: 'rgba(15, 23, 42, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#c7d2fe', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span>1️⃣ Select Operating System</span>
          </div>
          <div style={{ display: 'flex', gap: '6px' }}>
            <button
              type="button"
              data-testid="os-tab-windows"
              onClick={() => setOs('windows')}
              style={{
                flex: 1,
                padding: '6px 8px',
                fontSize: '11.5px',
                borderRadius: '6px',
                border: os === 'windows' ? '1px solid #6366f1' : '1px solid rgba(255, 255, 255, 0.1)',
                background: os === 'windows' ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255, 255, 255, 0.03)',
                color: os === 'windows' ? '#fff' : '#94a3b8',
                cursor: 'pointer',
                fontWeight: os === 'windows' ? 600 : 400,
              }}
            >
              🪟 Windows
            </button>
            <button
              type="button"
              data-testid="os-tab-macos"
              onClick={() => setOs('macos')}
              style={{
                flex: 1,
                padding: '6px 8px',
                fontSize: '11.5px',
                borderRadius: '6px',
                border: os === 'macos' ? '1px solid #6366f1' : '1px solid rgba(255, 255, 255, 0.1)',
                background: os === 'macos' ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255, 255, 255, 0.03)',
                color: os === 'macos' ? '#fff' : '#94a3b8',
                cursor: 'pointer',
                fontWeight: os === 'macos' ? 600 : 400,
              }}
            >
              🍎 macOS
            </button>
            <button
              type="button"
              data-testid="os-tab-linux"
              onClick={() => setOs('linux')}
              style={{
                flex: 1,
                padding: '6px 8px',
                fontSize: '11.5px',
                borderRadius: '6px',
                border: os === 'linux' ? '1px solid #6366f1' : '1px solid rgba(255, 255, 255, 0.1)',
                background: os === 'linux' ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255, 255, 255, 0.03)',
                color: os === 'linux' ? '#fff' : '#94a3b8',
                cursor: 'pointer',
                fontWeight: os === 'linux' ? 600 : 400,
              }}
            >
              🐧 Linux
            </button>
          </div>
        </div>

        {/* Step 2: Tool Selection */}
        <div style={{ padding: '12px 14px', borderRadius: '8px', background: 'rgba(15, 23, 42, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#c7d2fe', marginBottom: '8px' }}>
            2️⃣ Choose Tool / Framework
          </div>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {[
              { id: 'cli', label: 'AgentControl CLI' },
              { id: 'cursor', label: 'Cursor IDE' },
              { id: 'claude', label: 'Claude Code' },
              { id: 'python', label: 'Python SDK' },
              { id: 'node', label: 'Node.js' },
            ].map((t) => (
              <button
                key={t.id}
                type="button"
                data-testid={`tool-tab-${t.id}`}
                onClick={() => setTool(t.id as ToolType)}
                style={{
                  padding: '4px 8px',
                  fontSize: '11px',
                  borderRadius: '5px',
                  border: tool === t.id ? '1px solid #6366f1' : '1px solid rgba(255, 255, 255, 0.08)',
                  background: tool === t.id ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255, 255, 255, 0.03)',
                  color: tool === t.id ? '#fff' : '#94a3b8',
                  cursor: 'pointer',
                  fontWeight: tool === t.id ? 600 : 400,
                }}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {/* Step 3: Real-Time Verification */}
        <div style={{ padding: '12px 14px', borderRadius: '8px', background: 'rgba(15, 23, 42, 0.6)', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
          <div style={{ fontSize: '12px', fontWeight: 600, color: '#c7d2fe', marginBottom: '6px' }}>
            3️⃣ Verify In Observability
          </div>
          <p style={{ margin: '0 0 8px', fontSize: '11.5px', color: '#94a3b8', lineHeight: 1.4 }}>
            Once your client sends a request, inspect real-time DLP inspection &amp; audit trails.
          </p>
          <Link
            to="/observability/logs"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              fontSize: '11.5px',
              color: '#818cf8',
              textDecoration: 'none',
              fontWeight: 600,
            }}
          >
            <span>View Observability Logs &rarr;</span>
          </Link>
        </div>
      </div>

      {/* Code Snippet Box */}
      <div
        style={{
          borderRadius: '8px',
          background: '#090d16',
          border: '1px solid rgba(255, 255, 255, 0.1)',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            padding: '8px 14px',
            background: 'rgba(255, 255, 255, 0.03)',
            borderBottom: '1px solid rgba(255, 255, 255, 0.06)',
          }}
        >
          <div style={{ fontSize: '12px', fontFamily: 'var(--font-mono, monospace)', color: '#94a3b8', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />
            <span>
              {tool === 'cli'
                ? `Terminal (${os === 'windows' ? 'PowerShell' : 'bash/zsh'})`
                : tool === 'cursor'
                ? 'Cursor Configuration'
                : tool === 'claude'
                ? `Claude Code Environment (${os === 'windows' ? 'PowerShell' : 'bash/zsh'})`
                : tool === 'python'
                ? 'Python Script (main.py)'
                : 'TypeScript / JavaScript'}
            </span>
          </div>
          <button
            type="button"
            data-testid="copy-snippet-btn"
            onClick={() => copyToClipboard(getToolSnippet(), 'snippet')}
            style={{
              padding: '3px 10px',
              fontSize: '11px',
              borderRadius: '4px',
              background: copiedKey === 'snippet' ? '#10b981' : 'rgba(99, 102, 241, 0.25)',
              border: '1px solid rgba(99, 102, 241, 0.4)',
              color: '#fff',
              cursor: 'pointer',
              fontWeight: 500,
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
            }}
          >
            {copiedKey === 'snippet' ? '✓ Copied to Clipboard!' : '📋 Copy Snippet'}
          </button>
        </div>
        <pre
          data-testid="code-snippet-content"
          style={{
            margin: 0,
            padding: '14px',
            fontSize: '12px',
            lineHeight: 1.6,
            color: '#e2e8f0',
            fontFamily: 'var(--font-mono, monospace)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
            overflowX: 'auto',
          }}
        >
          {getToolSnippet()}
        </pre>
      </div>
    </div>
  )
}
