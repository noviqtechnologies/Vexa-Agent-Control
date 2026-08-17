# IDE & Ecosystem Integrations

Agent Control provides seamless integrations with the most popular AI-powered IDEs and coding assistants. 

Instead of manually setting up environment variables, you can use the `agentcontrol wrap` command to automatically patch your local IDE configurations to route traffic through the Agent Control proxy.

---

## One-Command Protection (FR-1.3)

The `agentcontrol protect` command is the recommended way to secure your entire AI development environment in a single step. It automatically:

1. **Auto-generates** a baseline `agentcontrol-policy.yaml` with P0 DLP secret rules if no policy exists in the current directory
2. **Discovers** all supported IDEs and their MCP server configurations on your machine
3. **Creates timestamped backups** of every config before modifying it (atomic, zero-loss)
4. **Injects the Agent Control proxy** into each discovered IDE configuration
5. **Starts the local security gateway** on `http://127.0.0.1:8080` (audit log → `~/.agentcontrol/audit.jsonl`)
6. **Opens the Local Dashboard** in your default browser for instant observability

> [!NOTE]
> **`agentcontrol init` is deprecated.** All zero-config setup is now handled by `agentcontrol protect` in a single step.

```bash
# macOS / Linux
agentcontrol protect

# Windows (PowerShell)
agentcontrol.exe protect

# Preview changes without writing to disk (--dry-run)
agentcontrol protect --dry-run

# Start in Enforce mode (active blocking enabled immediately)
agentcontrol protect --enforce

# Use a custom listen address
agentcontrol protect --listen 127.0.0.1:9090

# Override default audit log path (~/.agentcontrol/audit.jsonl)
agentcontrol protect --log-path /var/log/agentcontrol/audit.jsonl
```

### Reverting to Original Configuration (FR-1.4)

The `agentcontrol unprotect` command restores all IDE configs from their Agent Control-created backups. Backup integrity is verified (JSON structure validation) before any reversion is performed — ensuring zero-loss rollback.

```bash
# macOS / Linux
agentcontrol unprotect

# Windows (PowerShell)
agentcontrol.exe unprotect

# Bypass backup integrity check (use only for recovery)
agentcontrol.exe unprotect --force
```

> [!IMPORTANT]
> `unprotect` will **refuse** to restore from a corrupt or empty backup by default. Use `--force` only if you are certain the backup corruption is acceptable and want to proceed with manual cleanup.

---

### Advanced Wrapping Commands

- **Auto-Detect & Wrap All:** `agentcontrol wrap --auto-detect`
- **Dry Run:** `agentcontrol wrap <target> --dry-run`
- **Scan Responses:** `agentcontrol wrap <target> --scan-responses`

### Continuous Auto-Wrapping (`agentcontrol watch`)

You can run the **Watch Daemon** to continuously monitor your IDE configuration directories. Whenever a new MCP server is added to your IDE, Agent Control will automatically detect and wrap it in real time:

* **Linux / macOS (Bash / Zsh):**
  ```bash
  agentcontrol watch
  ```

* **Windows (PowerShell / CMD):**
  ```powershell
  agentcontrol.exe watch
  ```

### Telemetry & Fleet Visibility (`agentcontrol status`)

Run the status command to view the existence and wrap status of all supported IDE configurations on your machine:

* **Linux / macOS (Bash / Zsh):**
  ```bash
  agentcontrol status
  ```

* **Windows (PowerShell / CMD):**
  ```powershell
  agentcontrol.exe status
  ```

When connected to an Agent Control Dashboard, this command also sends an **MCP Server Inventory Snapshot**, providing Administrators with centralized, per-client visibility into which MCP servers are being used across the fleet.

---

## Supported Targets

| Target IDE | Wrap Command | Unwrap Command |
|---|---|---|
| **Claude Desktop** | `agentcontrol wrap claude` | `agentcontrol unwrap claude` |
| **Cursor** | `agentcontrol wrap cursor` | `agentcontrol unwrap cursor` |
| **VS Code** | `agentcontrol wrap vscode` | `agentcontrol unwrap vscode` |
| **JetBrains** | `agentcontrol wrap jetbrains` | `agentcontrol unwrap jetbrains` |
| **Zed Editor** | `agentcontrol wrap zed` | `agentcontrol unwrap zed` |
| **Cline** | `agentcontrol wrap cline` | `agentcontrol unwrap cline` |
| **OpenCode** | `agentcontrol wrap opencode` | `agentcontrol unwrap opencode` |
| **Antigravity** | `agentcontrol wrap antigravity` | `agentcontrol unwrap antigravity` |
| **Codex** | `agentcontrol wrap codex` | `agentcontrol unwrap codex` |

> [!NOTE]
> `agentcontrol protect` wraps **all** supported targets in one pass. Individual `wrap <target>` commands remain available for granular control.

---

## Local Dashboard Features

After running `agentcontrol protect`, the Local Dashboard opens automatically at `http://127.0.0.1:8080`. Key features include:

| Feature | Description |
|---|---|
| **Security Posture Toggle** (FR-2.1) | Interactive SHADOW ↔ ENFORCE switch in the sidebar. Changes propagate instantly via real-time SSE. No restart needed. |
| **Live Spend Card** (FR-2.2) | Tracks estimated dollar cost of LLM token usage in real-time (`$0.000` base, accumulates per SSE event). |
| **Risks Blocked Counter** (FR-2.2) | Live count of tool calls that were denied (injections, sensitive path reads, policy violations). |
| **Mission Mode Banner** (FR-2.3) | Guided onboarding: asks you to test Agent Control by telling your AI to "read /etc/shadow", proving real-time blocking. |
| **🪄 Quick Policy Button** (FR-2.4) | Per-tool wand button in the Tool Inventory table; calls `POST /api/policy/quick-rule` to apply a standard security rule for that tool instantly. |

### REST & SSE API Endpoints (`/api/v1/`)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/status` | Gateway health, version, posture mode, and active policy name |
| `GET` | `/api/v1/telemetry/stream` | SSE stream of real-time tool call events |
| `POST` | `/api/v1/hitl/respond` | Submit HITL approval or denial (`{"request_id": "...", "decision": "approve" \| "deny"}`) |

> [!NOTE]
> Legacy endpoints `/gateway/status` and `/api/events/stream` are preserved as aliases for backwards compatibility.

---

## How it works

When you run `agentcontrol wrap <target>` (or `agentcontrol protect`), the CLI edits the application's native configuration files (e.g., `settings.json`, `config.yaml`, or extension preferences) to point outbound HTTP and MCP connections to your local Agent Control proxy. 

To restore your configuration to its original state, run `agentcontrol unwrap <target>` or `agentcontrol unprotect` to restore all targets at once.
