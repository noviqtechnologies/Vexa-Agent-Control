# CLI Reference Guide

Comprehensive reference for all `agentcontrol` subcommands, options, flags, and default values.

---

## Core Commands

### `agentcontrol protect`
Discovers installed AI IDEs, creates timestamped backups, wraps MCP configurations with `stdio-proxy`, starts the local security gateway, and launches the dashboard.

```bash
agentcontrol protect [OPTIONS]
```

**Options:**
- `--dry-run`: Preview config changes without modifying files or starting the gateway.
- `--shadow`: Start in observation/audit mode without actively blocking calls.
- `--enforce`: Enable active blocking (default: `true`).
- `--listen <ADDR>`: Gateway listen address (default: `127.0.0.1:8080`).
- `--policy <PATH>`: Path to YAML policy file (default: `agentcontrol-policy.yaml`).
- `--no-browser`: Suppress automatic opening of local dashboard.

---

### `agentcontrol unprotect`
Restores all IDE configurations from their most recent timestamped backups.

```bash
agentcontrol unprotect [OPTIONS]
```

**Options:**
- `--dry-run`: Preview restoration actions without touching disk.
- `--force`: Force restoration even if backup metadata warnings occur.

---

### `agentcontrol status`
Inspects all 9 AI IDE configurations, displaying path, existence, wrap status, and verification trust level (`[verified]` vs `[unverified]`).

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
- `--gateway <URL>`: Target gateway URL (default: `http://127.0.0.1:8080`).
- `--json`: Output probe results as JSON.

---

### `agentcontrol wrap <TARGET>`
Wraps MCP configurations for a specific IDE target.

```bash
agentcontrol wrap <claude|cursor|codex|antigravity|vscode|jetbrains|zed|cline|opencode> [--dry-run]
```

---

### `agentcontrol unwrap <TARGET>`
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
