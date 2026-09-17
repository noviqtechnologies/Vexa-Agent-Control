# CLI Reference Guide

Comprehensive reference for all `agentcontrol` subcommands, options, flags, and default values.

---

## Core Commands

### `agentcontrol start`
Starts the local security gateway proxy daemon on `127.0.0.1:18080` (default) and auto-generates a local bearer token at `~/.agentcontrol/local.token`.

```bash
agentcontrol start [OPTIONS]
```

**Options:**
- `--listen <ADDR>`: Gateway listen address (default: `127.0.0.1:18080`).
- `--policy <PATH>`: Path to YAML policy file (default: `agentcontrol-policy.yaml`).
- `--shadow-mode`: Start in observation/audit mode without actively blocking calls.

---

### `agentcontrol connect <TARGET>`
Connects a specific IDE or coding assistant (`codex`, `claude`, `claude-code`, `cursor`, `antigravity`, `vscode-continue`) by discovering its configuration, creating a baseline backup, injecting local or virtual key proxy endpoints, wrapping MCP configurations with `stdio-proxy`, and writing an ownership manifest.

```bash
agentcontrol connect <codex|claude|claude-code|cursor|antigravity|vscode-continue> [OPTIONS]
```

**Options:**
- `-k, --key <KEY>`: Virtual key or authentication token (e.g. `sk-vex-...`) [env: `AGENTCONTROL_VIRTUAL_KEY`].
- `--mode <MODE>`: Connection mode: `local` or `cloud-direct`.
- `--force`: Force connection even if client version is outside pinned supported range.

#### Target Configuration Matrix:
| Target | Config File | Injected Endpoint Keys | Auth Token Keys | MCP Wrapping |
|---|---|---|---|---|
| `codex` | `config.toml`<br>`auth.json` | `openai_base_url`<br>`shell_environment_policy.set.OPENAI_BASE_URL` | `shell_environment_policy.set.OPENAI_API_KEY`<br>`auth.json: OPENAI_API_KEY` | `mcp_servers.<name>` |
| `claude` | `claude_desktop_config.json` | ℹ️ Direct Cloud Route | 🔒 Preserved | `mcpServers.<name>` |
| `claude-code` | `~/.claude/settings.json` | `env.ANTHROPIC_BASE_URL` | `env.ANTHROPIC_API_KEY` | `mcpServers.<name>` |
| `cursor` | `User/settings.json`<br>`mcp.json` | `http.proxy`<br>`cursor.general.disableHttp2` | `cursor.general.openaiApiKey` | `mcpServers.<name>` |
| `antigravity` | `mcp_config.json` | `proxy_url`<br>`antigravity.proxy.baseUrl` | `api_key`<br>`antigravity.proxy.apiKey` | `mcpServers.<name>` |
| `vscode-continue` | `User/settings.json` | `continue.models[].apiBase` | `continue.models[].apiKey` | — |

---

### `agentcontrol disconnect <TARGET>`
Non-destructively disconnects a client using its ownership manifest, removing injected proxy/token keys and unwrapping MCP servers while preserving all user customizations.

```bash
agentcontrol disconnect <codex|claude|claude-code|cursor|antigravity|vscode-continue>
```

---

### `agentcontrol doctor`
Runs a read-only 7-point health diagnostic checking binary integrity, daemon reachability, token health, database status, and configuration validity.

```bash
agentcontrol doctor [--json]
```

---

### `agentcontrol status`
Inspects all supported AI IDE configurations, displaying path, existence, connection status, and verification trust level.

```bash
agentcontrol status
```

---

### `agentcontrol verify`
Executes a 3-point live smoke test probe against the active local gateway:
1. Benign tool call execution (`read_file`) &rarr; `ALLOW`
2. DLP exfiltration detection (AWS Key Leak) &rarr; `BLOCK [DLP-01-HIGH-ENTROPY]`
3. Prompt injection detection (System Override) &rarr; `BLOCK [INJ-04-OVERRIDE]`

```bash
agentcontrol verify [OPTIONS]
```

**Options:**
- `--gateway <URL>`: Target gateway URL (default: `http://127.0.0.1:18080`).
- `--json`: Output probe results as JSON.

---

### `agentcontrol login`
Authenticates with a Team Control Hub via browser OAuth 2.0 PKCE.

```bash
agentcontrol login [--no-browser]
```

---

### `agentcontrol watch`
Runs the event-driven filesystem watcher daemon to automatically wrap newly added MCP servers.

```bash
agentcontrol watch [TARGET]
```
