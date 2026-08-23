# AI Client & IDE Integrations Matrix

This document provides the authoritative integration matrix for all supported AI development environments and desktop clients.

---

## Integration Trust Levels

| Trust Level | Definition | What Vexa Guarantees |
|---|---|---|
| **Verified** | Release-tested across macOS, Linux, and Windows. Configuration file schema and backup/restore paths are automated and tested. | Atomic wrapping, timestamped backup, automated unprotect, live verification. |
| **Experimental** | Path resolution is heuristic or requires manual verification. | Status inspection supported; user should verify config path with `agentcontrol status` before wrapping. |
| **Manual / Proxy** | No automated file wrapping; integration occurs via standard proxy environment variables. | Full policy enforcement on routed HTTP/JSON-RPC traffic. |

---

## Integrations Support Matrix

| Client / IDE | Category | Trust Level | Config Path (macOS) | Config Path (Linux) | Config Path (Windows) |
|---|---|---|---|---|---|
| **Claude Desktop** | Desktop App | **Verified** | `~/Library/Application Support/Claude/claude_desktop_config.json` | `~/.config/Claude/claude_desktop_config.json` | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Cursor** | IDE | **Verified** | `~/.cursor/mcp.json` | `~/.cursor/mcp.json` | `%USERPROFILE%\.cursor\mcp.json` |
| **Codex** | CLI / Agent | **Verified** | `~/.codex/config.json` | `~/.codex/config.json` | `%USERPROFILE%\.codex\config.json` |
| **Antigravity** | IDE | **Verified** | `~/.gemini/antigravity/mcp_config.json` | `~/.gemini/antigravity/mcp_config.json` | `%USERPROFILE%\.gemini\antigravity\mcp_config.json` |
| **VS Code** | IDE | *Experimental* | `~/Library/Application Support/Code/User/settings.json` | `~/.config/Code/User/settings.json` | `%APPDATA%\Code\User\settings.json` |
| **JetBrains** | IDE | *Experimental* | `~/Library/Application Support/JetBrains/*/mcp.json` | `~/.config/JetBrains/*/mcp.json` | `%APPDATA%\JetBrains\*\mcp.json` |
| **Zed** | Editor | *Experimental* | `~/.config/zed/settings.json` | `~/.config/zed/settings.json` | `%USERPROFILE%\.config\zed\settings.json` |
| **Cline** | Extension | *Experimental* | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/...` | `~/.config/Code/...` | `%APPDATA%\Code\...` |
| **OpenCode** | Open Source | *Experimental* | `~/.config/opencode/config.json` | `~/.config/opencode/config.json` | `%USERPROFILE%\.config\opencode\config.json` |

---

## Detailed Guides for Verified Integrations

- [Claude Desktop Integration Guide](claude-desktop.md)
- [Cursor IDE Integration Guide](cursor.md)
- [ChatGPT Codex Integration Guide](codex.md)
- [Antigravity IDE Integration Guide](antigravity.md)
