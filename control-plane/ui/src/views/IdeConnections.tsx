const IDE_INTEGRATIONS = [
  {
    id: 'claude',
    name: 'Claude Desktop',
    wrapCmd: 'agentcontrol wrap claude',
    unwrapCmd: 'agentcontrol unwrap claude',
    description: 'Wraps Claude Desktop to route all MCP traffic through Agent Control.',
  },
  {
    id: 'cursor',
    name: 'Cursor',
    wrapCmd: 'agentcontrol wrap cursor',
    unwrapCmd: 'agentcontrol unwrap cursor',
    description: 'Patches Cursor IDE configuration to use Agent Control as an MCP proxy.',
  },
  {
    id: 'codex',
    name: 'ChatGPT Codex',
    wrapCmd: 'agentcontrol wrap codex',
    unwrapCmd: 'agentcontrol unwrap codex',
    description: 'Intercepts ChatGPT Codex agent environment configuration.',
  },
  {
    id: 'vscode',
    name: 'VS Code',
    wrapCmd: 'agentcontrol wrap vscode',
    unwrapCmd: 'agentcontrol unwrap vscode',
    description: 'Configures VS Code extensions to route agent traffic through the proxy.',
  },
  {
    id: 'jetbrains',
    name: 'JetBrains IDEs',
    wrapCmd: 'agentcontrol wrap jetbrains',
    unwrapCmd: 'agentcontrol unwrap jetbrains',
    description: 'Supports IntelliJ, PyCharm, GoLand, and other JetBrains products.',
  },
  {
    id: 'zed',
    name: 'Zed Editor',
    wrapCmd: 'agentcontrol wrap zed',
    unwrapCmd: 'agentcontrol unwrap zed',
    description: 'Patches Zed\'s agent configuration to use Agent Control.',
  },
  {
    id: 'cline',
    name: 'Cline',
    wrapCmd: 'agentcontrol wrap cline',
    unwrapCmd: 'agentcontrol unwrap cline',
    description: 'Wraps Cline (AI coding assistant) to intercept MCP tool calls.',
  },
  {
    id: 'opencode',
    name: 'OpenCode',
    wrapCmd: 'agentcontrol wrap opencode',
    unwrapCmd: 'agentcontrol unwrap opencode',
    description: 'Routes OpenCode agent traffic through the Agent Control proxy.',
  },
  {
    id: 'antigravity',
    name: 'Antigravity',
    wrapCmd: 'agentcontrol wrap antigravity',
    unwrapCmd: 'agentcontrol unwrap antigravity',
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
          Agent Control automatically discovers and patches your local IDE to route traffic through the
          secure proxy. Use <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, background: 'rgba(255,255,255,0.08)', padding: '1px 6px', borderRadius: 3 }}>--dry-run</code> to preview changes safely.
        </p>
      </div>

      <div className="card" style={{ marginBottom: 20, padding: '14px 20px', display: 'flex', flexDirection: 'column', gap: 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" strokeWidth="2">
            <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <p style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
            Start Agent Control in shadow mode first (<code style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>agentcontrol dev</code>), then run individual target wrap commands or run bulk sweep: <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--success)' }}>agentcontrol wrap --all</code>.
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

      {/* Programmatic Client SDKs */}
      <div className="page-header" style={{ marginTop: 40 }}>
        <h2>Programmatic Client SDKs (Thin Proxy Mode)</h2>
        <p>
          Govern custom agent runtimes (LangChain, CrewAI, AutoGen, or native scripts) by routing tool calls through the out-of-process Agent Control proxy.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(420px, 1fr))', gap: 16 }}>
        {/* Python SDK */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(56,189,248,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#38bdf8', fontWeight: 700, fontSize: 16 }}>
              Py
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: 15, color: 'var(--text-primary)' }}>Python Client SDK (<code>agentcontrol</code>)</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>MIT-licensed lightweight proxy client with <code>@client.governed</code> decorator</div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px' }}>
            <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#38bdf8' }}>pip install agentcontrol</code>
            <button
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 11, padding: '2px 6px' }}
              onClick={() => navigator.clipboard?.writeText('pip install agentcontrol')}
              title="Copy"
            >
              Copy
            </button>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', borderRadius: 6, padding: '12px', fontSize: 12, fontFamily: 'var(--font-mono)', overflowX: 'auto', color: 'var(--text-secondary)' }}>
            <span style={{ color: '#ec4899' }}>from</span> agentwall <span style={{ color: '#ec4899' }}>import</span> AgentControlClient, AgentControlDenied<br/><br/>
            client = AgentControlClient()  <span style={{ color: 'var(--text-muted)' }}># Connects to 127.0.0.1:8080</span><br/><br/>
            <span style={{ color: '#38bdf8' }}>@client.governed</span><br/>
            <span style={{ color: '#ec4899' }}>def</span> <span style={{ color: '#22c55e' }}>execute_query</span>(sql: <span style={{ color: '#eab308' }}>str</span>):<br/>
            &nbsp;&nbsp;<span style={{ color: '#ec4899' }}>return</span> db.run(sql)<br/>
          </div>
        </div>

        {/* TypeScript SDK */}
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 40, height: 40, borderRadius: 10, background: 'rgba(49,120,198,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#60a5fa', fontWeight: 700, fontSize: 16 }}>
              TS
            </div>
            <div>
              <div style={{ fontWeight: 600, fontSize: 15, color: 'var(--text-primary)' }}>TypeScript Client SDK (<code>@vexa/agentcontrol</code>)</div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>Zero-dependency TypeScript/Node.js client for AI agent pipelines</div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px' }}>
            <code style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: '#60a5fa' }}>npm install @vexa/agentcontrol</code>
            <button
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 11, padding: '2px 6px' }}
              onClick={() => navigator.clipboard?.writeText('npm install @vexa/agentcontrol')}
              title="Copy"
            >
              Copy
            </button>
          </div>

          <div style={{ background: 'rgba(0,0,0,0.3)', border: '1px solid var(--border)', borderRadius: 6, padding: '12px', fontSize: 12, fontFamily: 'var(--font-mono)', overflowX: 'auto', color: 'var(--text-secondary)' }}>
            <span style={{ color: '#ec4899' }}>import</span> &#123; AgentControlClient &#125; <span style={{ color: '#ec4899' }}>from</span> <span style={{ color: '#a78bfa' }}>"@vexa/agentcontrol"</span>;<br/><br/>
            <span style={{ color: '#ec4899' }}>const</span> client = <span style={{ color: '#ec4899' }}>new</span> AgentControlClient();<br/><br/>
            <span style={{ color: '#ec4899' }}>const</span> governedTool = client.governed(<span style={{ color: '#a78bfa' }}>"read_file"</span>, <span style={{ color: '#ec4899' }}>async</span> (args) =&gt; &#123;<br/>
            &nbsp;&nbsp;<span style={{ color: '#ec4899' }}>return</span> fs.readFile(args.path, <span style={{ color: '#a78bfa' }}>"utf-8"</span>);<br/>
            &#125;);
          </div>
        </div>
      </div>
    </>
  )
}
