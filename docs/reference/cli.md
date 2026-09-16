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
Connects a specific IDE or coding assistant by discovering its config, creating a timestamped backup, wrapping MCP configurations with `stdio-proxy`, and writing an ownership manifest.

```bash
agentcontrol connect <claude|cursor|codex|antigravity|vscode|jetbrains|zed|cline|opencode> [OPTIONS]
```

**Options:**
- `--dry-run`: Preview config changes without modifying files.
- `--scan-responses`: Enable response scanning for secret detection.
- `--block-on-secrets`: Block entire response on secret detection instead of redacting.

---

### `agentcontrol disconnect <TARGET>`
Restores configuration for a specific IDE target from its ownership manifest.

```bash
agentcontrol disconnect <claude|cursor|codex|antigravity|vscode|jetbrains|zed|cline|opencode> [OPTIONS]
agentcontrol disconnect --all
```

**Options:**
- `--force`: Force restoration even if backup metadata warnings occur.

---

### `agentcontrol login`
Authenticates with a Team Control Hub via browser OAuth 2.0 PKCE. *Required for enterprise/team users with a Control Hub. Optional for standalone workstation users (who use `agentcontrol start` directly).*

```bash
agentcontrol login [--no-browser]
```

---

### `agentcontrol status`
Inspects all supported AI IDE configurations, displaying path, existence, connection status, and verification trust level (`[verified]` vs `[unverified]`).

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

## Legacy Aliases (Still Functional)

> [!NOTE]
> The following commands are functional legacy aliases. The canonical commands above are preferred for new workflows.

### `agentcontrol protect` *(Legacy: use `agentcontrol start` + `agentcontrol connect`)*
Discovers installed AI IDEs, creates timestamped backups, wraps MCP configurations with `stdio-proxy`, and starts the local security gateway.

```bash
agentcontrol protect [--dry-run] [--shadow] [--enforce] [--listen <ADDR>] [--policy <PATH>]
```

### `agentcontrol unprotect` *(Legacy: use `agentcontrol disconnect --all`)*
Restores all IDE configurations from their most recent timestamped backups.

```bash
agentcontrol unprotect [--dry-run] [--force]
```

### `agentcontrol wrap <TARGET>` *(Legacy: use `agentcontrol connect`)*
Wraps MCP configurations for a specific IDE target.

```bash
agentcontrol wrap <claude|cursor|codex|antigravity|vscode|jetbrains|zed|cline|opencode> [--dry-run]
```

### `agentcontrol unwrap <TARGET>` *(Legacy: use `agentcontrol disconnect`)*
Restores configuration for a specific IDE target.

```bash
agentcontrol unwrap <claude|cursor|codex|antigravity|vscode|jetbrains|zed|cline|opencode> [--force]
```

---

### `agentcontrol watch`
Runs the event-driven filesystem watcher daemon to automatically wrap newly added MCP servers.

```bash
agentcontrol watch [--all] [<TARGET>]
```

---

### `agentcontrol dev`
Starts the local development proxy in standalone mode.

```bash
agentcontrol dev [OPTIONS] [-- <DOWNSTREAM_CMD...>]
```

**Options:**
- `--listen <ADDR>`: Socket address (default: `127.0.0.1:8080`).
- `--mcp-url <URL>`: Upstream MCP server URL (default: `http://127.0.0.1:3000`).
- `--stdio`: Enable stdio proxying.
- `--enforce`: Enable active blocking (default is shadow mode).
- `--learn`: Enable policy learning mode.
- `--no-browser`: Disable browser opening.

---

### `agentcontrol generate-policy`
Synthesizes a lint-passing `agentcontrol-policy.yaml` from observed shadow traffic in `events.db`.

```bash
agentcontrol generate-policy [--output <PATH>] [--decay-window <DAYS>]
```

---

### `agentcontrol lint <POLICY_FILE>`
Lints a YAML policy file against Schema v2 and security best practices.

```bash
agentcontrol lint agentcontrol-policy.yaml
```

---

### `agentcontrol enroll`
Enrolls the workstation with a central Control Hub using a One-Time Enrollment Token.

```bash
agentcontrol enroll --token <OTET> [--hub-url <URL>]
```

---

### `agentcontrol service <install|uninstall|start|stop|status>`
Manages the persistent OS background sentry service (systemd on Linux, Launchd on macOS, Windows SCM).
