# CLI Reference Guide

Comprehensive reference for all `agentcontrol` subcommands, options, flags, and default values.

---

## Core Commands

### `agentcontrol protect`
One-command protection for your entire workstation. Discovers all installed coding assistants, binds and verifies the listener port, records pre-mutation states in `~/.agentcontrol/protect_journal.json`, applies atomic configuration updates, and generates `OwnershipManifest` records. Halts immediately and executes fail-closed rollback if any target fails.

```bash
agentcontrol protect [OPTIONS]
```

**Options:**
- `--policy <PATH>`: Path to custom YAML policy file.
- `--shadow`: Run in observation-only mode without blocking requests.
- `--dry-run`: Preview planned modifications without altering files.

---

### `agentcontrol unprotect`
One-command complete reversal. Reads ownership manifests for all protected assistants and restores original configurations cleanly, unwrapping MCP stdio proxies and removing injected proxy settings while preserving user themes, fonts, and keybindings.

```bash
agentcontrol unprotect
```

---

### `agentcontrol start`
Starts the local security gateway proxy daemon on `127.0.0.1:18080` (default) and auto-generates a local bearer token at `~/.agentcontrol/local.token`.

```bash
agentcontrol start [OPTIONS]
```

**Options:**
- `--listen <ADDR>`: Gateway listen address (default: `127.0.0.1:18080`).
- `--policy <PATH>`: Path to YAML policy file (default: `agentcontrol-policy.yaml`).
- `--profile <PROFILE>`: Deployment profile: `local-gateway`, `local-firewall`, `team-gateway`, `container-sidecar`.
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

### `agentcontrol backup`
Creates an atomic, consistent online backup of local data stores without interrupting running proxies.
- Executes `PRAGMA wal_checkpoint(TRUNCATE);` and `VACUUM INTO` on `events.db` to produce a fully compacted database snapshot.
- Copies `audit.jsonl`, `audit.key`, active ownership manifests, and `profile.json` into a timestamped directory with `0700`/`0600` permissions.

```bash
agentcontrol backup [--output-dir <PATH>]
```

---

### `agentcontrol verify-db`
Performs comprehensive offline cryptographic and relational integrity checks:
- Runs SQLite `PRAGMA integrity_check;` on `events.db`.
- Recomputes HMAC-SHA256 signatures for every entry in `audit.jsonl` from line 0 to EOF using `audit.key` to verify tamper-evidence.

```bash
agentcontrol verify-db [--audit-path <PATH>] [--db-path <PATH>]
```

---

### `agentcontrol login`
Authenticates with a Team Control Hub via browser OAuth 2.0 PKCE and transitions the operational profile from `local-gateway` to `team-gateway` in `~/.agentcontrol/profile.json` without modifying wrapped IDE client configurations.

```bash
agentcontrol login [--hub <URL>] [--no-browser]
```

---

### `agentcontrol enroll`
Enrolls the workstation in Team fleet governance headlessly using a One-Time Enrollment Token (OTET).

```bash
agentcontrol enroll --token <OTET> [--hub-url <URL>]
```

---

### `agentcontrol logout`
Flushes local team credentials, invalidates active sessions, and transitions the runtime profile back to `local-gateway` while preserving all connected IDE client settings.

```bash
agentcontrol logout
```

---

### `agentcontrol watch`
Runs the event-driven filesystem watcher daemon to automatically wrap newly added MCP servers.

```bash
agentcontrol watch [TARGET]
```

---

## Service Management Commands

### `agentcontrol service install`
Installs Agent Control as an always-on background OS service using the authoritative supervisor for your platform. Writes a self-contained, secure configuration file (`0600` permissions) to `~/.agentcontrol/daemon.json` (or system directory if `--enterprise`).

```bash
agentcontrol service install [OPTIONS]
```

**Options:**
- `--hub-url <URL>`: Control Hub URL (default: `https://app.vexasec.io`).
- `--enterprise`: Install as system-level daemon (requires root / Administrator). Uses Windows SCM Service, macOS LaunchDaemon, or Linux system-level systemd unit.
- `--config <PATH>`: Custom path for saving daemon configuration JSON.
- `--gateway-secret <SECRET>`: Optional upstream gateway secret for webhook HMAC validation.
- `--policy-read-secret <SECRET>`: Optional secret for fetching policies from the Control Hub.
- `--agent-id <ID>`: Friendly identifier for this workstation sent in telemetry.

**Platform Supervisors:**
| OS Platform | Standard User Mode (Default) | Enterprise / System Mode (`--enterprise`) |
|---|---|---|
| **Windows** | Windows User Startup (`HKCU\Run`) / Task Scheduler | Windows SCM Service (`AgentControlSentry`) |
| **macOS** | user `LaunchAgent` (`gui/<uid>/io.vexasec.agentcontrol`) | system `LaunchDaemon` (`/Library/LaunchDaemons/`) |
| **Linux** | user `systemd` unit (`~/.config/systemd/user/`) | system `systemd` unit (`/etc/systemd/system/`) |

---

### `agentcontrol service status`
Performs an authenticated local health handshake against `http://127.0.0.1:18080/api/v1/health` and queries the authoritative OS service manager. Reports a streamlined, high-signal 5-line diagnostic summary.

```bash
agentcontrol service status
```

**Example Output:**
```text
● Vexa Agent Control Daemon Health Inspection
  OS Platform:        windows (x86_64)
  Supervisor Type:    Windows User Startup (HKCU\Run) (ACTIVE / SUPERVISED)
  Daemon Process:     PID 25936 (v1.0.89) | Up 23s
  Listener Binding:   127.0.0.1:18080 (20 ms RTT)
  Hub Connection:     ENROLLED (http://127.0.0.1:8081) | Policy: ACTIVE (local-safe-mode)
```

**Output States:**
- `ACTIVE / SUPERVISED`: Service is supervised by the OS service manager and the daemon handshake is responsive.
- `DEGRADED (Unmanaged)`: Daemon is running interactively or detached, but is not managed by an OS supervisor.
- `DEGRADED (Closed)`: Daemon is stopped or unreachable on `127.0.0.1:18080`.

---

### `agentcontrol service uninstall`
Completely and non-destructively removes background daemon registrations across all scopes (stops running daemon, unregisters systemd/launchd/SCM/Task Scheduler/registry keys, and deletes supervisor manifests).

```bash
agentcontrol service uninstall
```

---

## Administrative Companion CLI (`agentcontrol-admin`)

The `agentcontrol-admin` CLI is provided for server hosts and container environments running the Vexa Control Hub control plane.

### `agentcontrol-admin break-glass`
Generates a host-bound single-use emergency recovery token valid for 15 minutes. Use this tool if IdP misconfiguration or SSO outages lock administrators out of the Control Hub.

```bash
# Generate emergency break-glass token on the server host
agentcontrol-admin break-glass --email admin@agentcontrol.local

# Specify custom database URL
agentcontrol-admin break-glass --email admin@agentcontrol.local --db-url "postgres://vexa:secret@localhost:5432/vexa_control_plane?sslmode=disable"
```

**Redeeming the Break-Glass Token:**
- Via Web UI: Navigate to `http://<hub-host>:8081/break-glass` and enter the 64-character token.
- Via REST API:
  ```bash
  curl -X POST http://localhost:8081/api/v1/auth/break-glass \
    -H "Content-Type: application/json" \
    -d '{"token": "<BREAK_GLASS_TOKEN>"}'
  ```

