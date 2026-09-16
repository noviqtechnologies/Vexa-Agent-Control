# Claude Desktop Integration Guide

This guide details how Vexa Agent Control intercepts, sandboxes, and audits Model Context Protocol (MCP) server invocations and governs LLM traffic within Anthropic's Claude Desktop application across macOS, Linux, and Windows.

---

## Configuration File Locations

Claude Desktop defines its configuration and MCP servers in `claude_desktop_config.json`:

| Operating System | Configuration File Path |
|---|---|
| **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` (e.g. `C:\Users\<username>\AppData\Roaming\Claude\claude_desktop_config.json`) |
| **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| **Linux** | `~/.config/Claude/claude_desktop_config.json` |

---

## 1. MCP Tool Sentry Wrapping

When Claude Desktop invokes tools via the Model Context Protocol, Agent Control intercepts each call via `stdio-proxy`.

### Original Configuration
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "C:\\Projects"]
    }
  }
}
```

### Wrapped Configuration
Running `agentcontrol wrap claude` automatically transforms the configuration into:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentcontrol",
      "args": [
        "stdio-proxy",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "C:\\Projects"
      ]
    }
  }
}
```

All tool calls pass through the local proxy where they are evaluated against Data Loss Prevention (DLP) patterns, prompt injection checks, rate limits, and approval policies.

---

## 2. Configuring Virtual Keys in MCP Server Environments

If your Claude Desktop MCP servers (e.g., custom code execution engines, autonomous sub-agents, or database query runners) make outbound LLM calls, you can inject Agent Control **Virtual Keys** (`sk-vex-...`) and redirect calls to the local gateway using the `env` block in `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "code-agent": {
      "command": "agentcontrol",
      "args": [
        "stdio-proxy",
        "--",
        "node",
        "C:\\tools\\agent-runner.js"
      ],
      "env": {
        "OPENAI_BASE_URL": "http://127.0.0.1:18080/v1",
        "OPENAI_API_KEY": "sk-vex-YOUR_VIRTUAL_KEY_HERE",
        "ANTHROPIC_BASE_URL": "http://127.0.0.1:18080/v1",
        "HTTP_PROXY": "http://127.0.0.1:18080",
        "HTTPS_PROXY": "http://127.0.0.1:18080"
      }
    }
  }
}
```

> [!NOTE]
> The Agent Control gateway accepts both Anthropic and OpenAI protocols on port `18080`. When passing an Agent Control Virtual Key (`sk-vex-...`), the gateway enforces your spend cap, rates, and allowed models, then securely injects the real provider key before dispatching upstream.

---

## 3. Step-by-Step Setup

1. **Verify Claude Desktop Config Exists:**
   ```bash
   agentcontrol status
   ```
   Confirm `Claude Desktop` shows `[verified]` and `EXISTS: ✔`.

2. **Connect Claude Desktop:**
   ```bash
   agentcontrol connect claude
   ```
   - Automatically creates an atomic, timestamped baseline backup: `claude_desktop_config.json.bak.<timestamp>`.
   - Wraps each MCP server with `agentcontrol stdio-proxy --`.
   - Records all mutations in `~/.agentcontrol/manifests/claude.manifest.json`.

3. **Start Local Security Gateway:**
   ```bash
   agentcontrol start
   # Or with a custom policy:
   agentcontrol start --listen 127.0.0.1:18080 --policy agentcontrol-policy.yaml
   ```

4. **Restart Claude Desktop:**
   - **Windows:** Exit Claude Desktop completely from the system tray/taskbar and relaunch.
   - **macOS:** Press `Cmd+Q` and relaunch from Applications.
   - **Linux:** Terminate the process and relaunch.

5. **Verify Live Traffic:**
   Invoke any tool in Claude Desktop. Inspect live events in the Local Developer Dashboard at `http://127.0.0.1:18080`.

---

## 4. Reversion

To restore the original Claude Desktop configuration from the ownership manifest:
```bash
agentcontrol disconnect claude
```
Or disconnect all managed targets across the workstation:
```bash
agentcontrol disconnect --all
```
