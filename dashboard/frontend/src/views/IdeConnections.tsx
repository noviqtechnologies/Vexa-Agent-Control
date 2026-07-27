const IDE_INTEGRATIONS = [
  {
    id: 'claude',
    name: 'Claude Desktop',
    wrapCmd: 'agentwall wrap claude',
    unwrapCmd: 'agentwall unwrap claude',
    description: 'Wraps Claude Desktop to route all MCP traffic through AgentWall.',
  },
  {
    id: 'cursor',
    name: 'Cursor',
    wrapCmd: 'agentwall wrap cursor',
    unwrapCmd: 'agentwall unwrap cursor',
    description: 'Patches Cursor IDE configuration to use AgentWall as an MCP proxy.',
  },
  {
    id: 'vscode',
    name: 'VS Code',
    wrapCmd: 'agentwall wrap vscode',
    unwrapCmd: 'agentwall unwrap vscode',
    description: 'Configures VS Code extensions to route agent traffic through the proxy.',
  },
  {
    id: 'jetbrains',
    name: 'JetBrains IDEs',
    wrapCmd: 'agentwall wrap jetbrains',
    unwrapCmd: 'agentwall unwrap jetbrains',
    description: 'Supports IntelliJ, PyCharm, GoLand, and other JetBrains products.',
  },
  {
    id: 'zed',
    name: 'Zed Editor',
    wrapCmd: 'agentwall wrap zed',
    unwrapCmd: 'agentwall unwrap zed',
    description: 'Patches Zed\'s agent configuration to use AgentWall.',
  },
  {
    id: 'cline',
    name: 'Cline',
    wrapCmd: 'agentwall wrap cline',
    unwrapCmd: 'agentwall unwrap cline',
    description: 'Wraps Cline (AI coding assistant) to intercept MCP tool calls.',
  },
  {
    id: 'opencode',
    name: 'OpenCode',
    wrapCmd: 'agentwall wrap opencode',
    unwrapCmd: 'agentwall unwrap opencode',
    description: 'Routes OpenCode agent traffic through the AgentWall proxy.',
  },
  {
    id: 'antigravity',
    name: 'Antigravity',
    wrapCmd: 'agentwall wrap antigravity',
    unwrapCmd: 'agentwall unwrap antigravity',
    description: 'Integrates with the Antigravity IDE for full egress observation.',
  },
]

function IDEIcon({ id }: { id: string }) {
  const color = 'currentColor'
  if (id === 'vscode') return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.75">
      <polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" />
    </svg>
  )
  if (id === 'cursor') return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.75">
      <rect x="3" y="3" width="18" height="18" rx="2" /><path d="M8 12h8m-4-4v8" />
    </svg>
  )
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.75">
      <rect x="2" y="3" width="20" height="14" rx="2" /><path d="M8 21h8m-4-4v4" />
    </svg>
  )
}

export default function IdeConnections() {
  return (
    <>
      <div className="page-header">
        <h1>Ecosystem Integrations</h1>
        <p>
          AgentWall automatically discovers and patches your local IDE to route traffic through the
          secure proxy. Use <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, background: 'rgba(255,255,255,0.08)', padding: '1px 6px', borderRadius: 3 }}>--dry-run</code> to preview changes safely.
        </p>
      </div>

      <div className="card" style={{ marginBottom: 20, padding: '14px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2">
            <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            Start AgentWall in shadow mode first (<code style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>agentwall dev</code>), then run the wrap command.
            All IDE integrations are reversible with the unwrap command.
          </p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 16 }}>
        {IDE_INTEGRATIONS.map(ide => (
          <div key={ide.id} className="card" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)', flexShrink: 0 }}>
                <IDEIcon id={ide.id} />
              </div>
              <div>
                <div style={{ fontWeight: 600, fontSize: 14, color: 'var(--text-primary)' }}>{ide.name}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{ide.description}</div>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.18)', borderRadius: 6, padding: '8px 12px' }}>
                <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--success)' }}>{ide.wrapCmd}</code>
                <button
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 11, padding: '2px 6px' }}
                  onClick={() => navigator.clipboard?.writeText(ide.wrapCmd)}
                  title="Copy"
                >
                  Copy
                </button>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(239,68,68,0.04)', border: '1px solid rgba(239,68,68,0.15)', borderRadius: 6, padding: '8px 12px' }}>
                <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--danger)' }}>{ide.unwrapCmd}</code>
                <button
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 11, padding: '2px 6px' }}
                  onClick={() => navigator.clipboard?.writeText(ide.unwrapCmd)}
                  title="Copy"
                >
                  Copy
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </>
  )
}
