# AI Client & IDE Integrations Matrix

This document provides the authoritative integration matrix and cross-platform configuration guide for all supported AI development environments, desktop clients, and autonomous coding agents.

---

## Dual-Pillar Governance Model

Vexa Agent Control protects developer workstations through two complementary pillars:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       VEXA AGENT CONTROL ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ PILLAR 1: MCP Tool Sentry & Sandboxing (Local Stdio Interception)           │
│   • Automated wrapping of `mcp.json` / `config.toml` / `config.json`        │
│   • Injects `agentcontrol stdio-proxy --` before MCP servers                │
│   • Enforces DLP, prompt injection defense, and tool call authorization     │
├─────────────────────────────────────────────────────────────────────────────┤
│ PILLAR 2: LLM Proxy & Server-Side Provider Key Custody (Zero Secrets on Disk)│
│   • Route completion traffic to `http://127.0.0.1:18080/v1`                  │
│   • Zero raw provider keys or static secrets stored in developer IDE configs │
│   • Sessions bound to Google Workspace / Entra ID via `agentcontrol login`   │
│   • Authoritative spend caps, team allowlists, and audit attribution         │
│   • Real provider credentials (OpenAI/Anthropic) remain strictly in KMS Vault│
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Integrations Support & Enforcement Matrix

| Client / IDE | Trust Level | Routing Method | Interception Scope | MCP Sandboxing | Config Path |
|---|---|---|---|---|---|
| **Cursor IDE** | **Verified** | `settings.json` (`http.proxy`) | **Full Proxying** (Completions & Tools) | `agentcontrol connect cursor` | `~/.cursor/mcp.json` & `settings.json` |
| **Claude Code CLI** | **Verified** | `settings.json` (`env.ANTHROPIC_BASE_URL`) | **Full Proxying** (CLI commands & Tools) | `agentcontrol connect claude-code` | `~/.claude/settings.json` |
| **Claude Desktop** | **Verified** | `claude_desktop_config.json` | **Tool Boundary Only** (Completions Direct) | `agentcontrol connect claude` | `claude_desktop_config.json` |
| **ChatGPT Codex** | **Verified** | `config.toml` + Shell Wrapper | **Wrapper Execution** (Intercepted Shell) | `agentcontrol connect codex` | `~/.codex/config.toml` |
| **Antigravity IDE** | **Verified** | `mcp_config.json` (`proxy_url`) | **Full Proxying** (Configured Workspaces) | `agentcontrol connect antigravity` | `~/.gemini/antigravity/mcp_config.json` |
| **VS Code / Continue** | **Verified** | `settings.json` (`apiBase`) | **Full Proxying** (Extension Requests) | `agentcontrol connect vscode-continue` | `User/settings.json` |

> [!IMPORTANT]
> **Boundary Model Disclosure:**
> Protection is strictly enforced at the client configuration and proxy layer (`127.0.0.1:18080`). Agent Control does **not** perform kernel-level packet inspection or OS raw socket capture. Unconfigured terminal commands or arbitrary child processes run outside wrapped configurations will connect directly to destination endpoints without hitting the gateway.

---

## Cross-Platform Configuration Quick Reference

### 1. Codex Desktop & CLI
- **Windows:** `%USERPROFILE%\.codex\config.toml`
- **macOS / Linux:** `~/.codex/config.toml`
```toml
[shell_environment_policy.set]
OPENAI_BASE_URL = "http://127.0.0.1:18080/v1"
OPENAI_API_KEY = "sk-vex-YOUR_VIRTUAL_KEY_HERE"
OPENAI_MODEL = "o3-mini"
HTTP_PROXY = "http://127.0.0.1:18080"
HTTPS_PROXY = "http://127.0.0.1:18080"
```
*(⚠️ Never place `openai_api_key` under `[features]` or top-level; it causes a fatal `config_load` error).*

### 2. Claude Desktop (Tool Boundary Only)
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`
```json
{
  "mcpServers": {
    "agent": {
      "command": "agentcontrol",
      "args": ["stdio-proxy", "--", "node", "runner.js"]
    }
  }
}
```

### 3. Cursor IDE
- **Windows:** `%APPDATA%\Cursor\User\settings.json`
- **macOS:** `~/Library/Application Support/Cursor/User/settings.json`
- **Linux:** `~/.config/Cursor/User/settings.json`
```json
{
  "http.proxy": "http://127.0.0.1:18080",
  "cursor.general.disableHttp2": true
}
```

### 4. Terminal Agents & SDKs (Aider, Continue, Python, Node.js)
- **Windows (PowerShell):**
  ```powershell
  $env:OPENAI_BASE_URL = "http://127.0.0.1:18080/v1"
  $env:OPENAI_API_KEY  = "sk-vex-YOUR_VIRTUAL_KEY_HERE"
  ```
- **macOS & Linux (Bash / Zsh):**
  ```bash
  export OPENAI_BASE_URL="http://127.0.0.1:18080/v1"
  export OPENAI_API_KEY="sk-vex-YOUR_VIRTUAL_KEY_HERE"
  ```

---

## Detailed Guides for Verified Integrations

- [ChatGPT Codex Integration Guide](codex.md)
- [Claude Desktop Integration Guide](claude-desktop.md)
- [Cursor IDE Integration Guide](cursor.md)
- [Antigravity IDE Integration Guide](antigravity.md)
