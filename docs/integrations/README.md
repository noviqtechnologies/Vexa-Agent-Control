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
│ PILLAR 2: LLM Proxy & Virtual Key Governance (HTTP / SSE Redirection)       │
│   • Route completion traffic to `http://127.0.0.1:8080/v1`                  │
│   • Developers configure scoped Virtual Keys (`sk-vex-...`)                 │
│   • Authoritative token spend caps, rate limits (RPM/TPM), model governance │
│   • Real provider credentials remain securely in the central Key Vault      │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Integrations Support Matrix

| Client / IDE | Trust Level | MCP Wrapping Support | Virtual Key / LLM Proxy Method | Config Path (macOS) | Config Path (Linux) | Config Path (Windows) |
|---|---|---|---|---|---|---|
| **ChatGPT Codex** | **Verified** | `agentcontrol wrap codex` | `[shell_environment_policy.set]` | `~/.codex/config.toml` | `~/.codex/config.toml` | `%USERPROFILE%\.codex\config.toml` |
| **Claude Desktop** | **Verified** | `agentcontrol wrap claude` | `mcpServers.<srv>.env` block | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Cursor IDE** | **Verified** | `agentcontrol wrap cursor` | `cursor.openAI.baseUrl` + `apiKey` | `~/.cursor/mcp.json` & `User/settings.json` | `~/.cursor/mcp.json` & `User/settings.json` | `%USERPROFILE%\.cursor\mcp.json` & `%APPDATA%\Cursor\User\settings.json` |
| **Antigravity** | **Verified** | `agentcontrol wrap antigravity` | IDE Settings & Environment | `~/.gemini/antigravity/mcp_config.json` | `~/.gemini/antigravity/mcp_config.json` | `%USERPROFILE%\.gemini\antigravity\mcp_config.json` |
| **VS Code / Copilot**| *Experimental* | `agentcontrol wrap vscode` | `User/settings.json` proxy | `~/Library/Application Support/Code/User/settings.json` | `~/.config/Code/User/settings.json` | `%APPDATA%\Code\User\settings.json` |
| **Cline / Roo Code** | **Verified** | Automated via Extension | Direct `baseURL` + Virtual Key | Extension Global Storage | Extension Global Storage | Extension Global Storage |
| **OpenCode** | *Experimental* | `agentcontrol wrap opencode`| `provider.baseUrl` in config | `~/.config/opencode/config.json` | `~/.config/opencode/config.json` | `%USERPROFILE%\.config\opencode\config.json` |
| **CLI / SDKs** | **Verified** | Process Environment | `OPENAI_BASE_URL` env var | Shell Profile (`.zshrc` / `.bashrc`) | Shell Profile (`.bashrc`) | Windows User Environment / PowerShell Profile |

---

## Cross-Platform Configuration Quick Reference

### 1. Codex Desktop & CLI
- **Windows:** `%USERPROFILE%\.codex\config.toml`
- **macOS / Linux:** `~/.codex/config.toml`
```toml
[shell_environment_policy.set]
OPENAI_BASE_URL = "http://127.0.0.1:8080/v1"
OPENAI_API_KEY = "sk-vex-YOUR_VIRTUAL_KEY_HERE"
OPENAI_MODEL = "o3-mini"
HTTP_PROXY = "http://127.0.0.1:8080"
HTTPS_PROXY = "http://127.0.0.1:8080"
```
*(⚠️ Never place `openai_api_key` under `[features]` or top-level; it causes a fatal `config_load` error).*

### 2. Claude Desktop
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`
```json
{
  "mcpServers": {
    "agent": {
      "command": "agentcontrol",
      "args": ["stdio-proxy", "--", "node", "runner.js"],
      "env": {
        "OPENAI_BASE_URL": "http://127.0.0.1:8080/v1",
        "OPENAI_API_KEY": "sk-vex-YOUR_VIRTUAL_KEY_HERE"
      }
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
  "cursor.openAI.baseUrl": "http://127.0.0.1:8080/v1",
  "cursor.openAI.apiKey": "sk-vex-YOUR_VIRTUAL_KEY_HERE",
  "cursor.openAI.model": "gpt-4o"
}
```

### 4. Terminal Agents & SDKs (Aider, Continue, Python, Node.js)
- **Windows (PowerShell):**
  ```powershell
  $env:OPENAI_BASE_URL = "http://127.0.0.1:8080/v1"
  $env:OPENAI_API_KEY  = "sk-vex-YOUR_VIRTUAL_KEY_HERE"
  ```
- **macOS & Linux (Bash / Zsh):**
  ```bash
  export OPENAI_BASE_URL="http://127.0.0.1:8080/v1"
  export OPENAI_API_KEY="sk-vex-YOUR_VIRTUAL_KEY_HERE"
  ```

---

## Detailed Guides for Verified Integrations

- [ChatGPT Codex Integration Guide](codex.md)
- [Claude Desktop Integration Guide](claude-desktop.md)
- [Cursor IDE Integration Guide](cursor.md)
- [Antigravity IDE Integration Guide](antigravity.md)
