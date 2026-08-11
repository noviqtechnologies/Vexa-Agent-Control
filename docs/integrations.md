# IDE & Ecosystem Integrations

AgentWall provides seamless integrations with the most popular AI-powered IDEs and coding assistants. 

Instead of manually setting up environment variables, you can use the `agentwall wrap` command to automatically patch your local IDE configurations to route traffic through the AgentWall proxy.

---

## One-Command Protection (FR-1.3)

The `agentwall protect` command is the recommended way to secure your entire AI development environment in a single step. It automatically:

1. **Discovers** all supported IDEs and their MCP server configurations on your machine
2. **Creates timestamped backups** of every config before modifying it (atomic, zero-loss)
3. **Injects the AgentWall proxy** into each discovered IDE configuration
4. **Starts the local security gateway** on `http://127.0.0.1:8080`
5. **Opens the Local Dashboard** in your default browser for instant observability

```bash
# macOS / Linux
agentwall protect

# Windows (PowerShell)
agentwall.exe protect

# Preview changes without writing to disk (--dry-run)
agentwall protect --dry-run

# Start in Enforce mode (active blocking enabled immediately)
agentwall protect --enforce

# Use a custom listen address
agentwall protect --listen 127.0.0.1:9090
```

### Reverting to Original Configuration (FR-1.4)

The `agentwall unprotect` command restores all IDE configs from their AgentWall-created backups. Backup integrity is verified (JSON structure validation) before any reversion is performed — ensuring zero-loss rollback.

```bash
# macOS / Linux
agentwall unprotect

# Windows (PowerShell)
agentwall.exe unprotect

# Bypass backup integrity check (use only for recovery)
agentwall.exe unprotect --force
```

> [!IMPORTANT]
> `unprotect` will **refuse** to restore from a corrupt or empty backup by default. Use `--force` only if you are certain the backup corruption is acceptable and want to proceed with manual cleanup.

---

### Advanced Wrapping Commands

- **Auto-Detect & Wrap All:** `agentwall wrap --auto-detect`
- **Dry Run:** `agentwall wrap <target> --dry-run`
- **Scan Responses:** `agentwall wrap <target> --scan-responses`

### Continuous Auto-Wrapping (`agentwall watch`)

You can run the **Watch Daemon** to continuously monitor your IDE configuration directories. Whenever a new MCP server is added to your IDE, AgentWall will automatically detect and wrap it in real time:

* **Linux / macOS (Bash / Zsh):**
  ```bash
  agentwall watch
  ```

* **Windows (PowerShell / CMD):**
  ```powershell
  agentwall.exe watch
  ```

### Telemetry & Fleet Visibility (`agentwall status`)

Run the status command to view the existence and wrap status of all supported IDE configurations on your machine:

* **Linux / macOS (Bash / Zsh):**
  ```bash
  agentwall status
  ```

* **Windows (PowerShell / CMD):**
  ```powershell
  agentwall.exe status
  ```

When connected to an AgentWall Dashboard, this command also sends an **MCP Server Inventory Snapshot**, providing Administrators with centralized, per-client visibility into which MCP servers are being used across the fleet.

---

## Supported Targets

| Target IDE | Wrap Command | Unwrap Command |
|---|---|---|
| **Claude Desktop** | `agentwall wrap claude` | `agentwall unwrap claude` |
| **Cursor** | `agentwall wrap cursor` | `agentwall unwrap cursor` |
| **VS Code** | `agentwall wrap vscode` | `agentwall unwrap vscode` |
| **JetBrains** | `agentwall wrap jetbrains` | `agentwall unwrap jetbrains` |
| **Zed Editor** | `agentwall wrap zed` | `agentwall unwrap zed` |
| **Cline** | `agentwall wrap cline` | `agentwall unwrap cline` |
| **OpenCode** | `agentwall wrap opencode` | `agentwall unwrap opencode` |
| **Antigravity** | `agentwall wrap antigravity` | `agentwall unwrap antigravity` |

> [!NOTE]
> `agentwall protect` wraps **all** supported targets in one pass. Individual `wrap <target>` commands remain available for granular control.

---

## Local Dashboard Features

After running `agentwall protect`, the Local Dashboard opens automatically at `http://127.0.0.1:8080`. Key features include:

| Feature | Description |
|---|---|
| **Security Posture Toggle** (FR-2.1) | Interactive SHADOW ↔ ENFORCE switch in the sidebar. Changes propagate instantly via real-time SSE. No restart needed. |
| **Live Spend Card** (FR-2.2) | Tracks estimated dollar cost of LLM token usage in real-time (`$0.000` base, accumulates per SSE event). |
| **Risks Blocked Counter** (FR-2.2) | Live count of tool calls that were denied (injections, sensitive path reads, policy violations). |
| **Mission Mode Banner** (FR-2.3) | Guided onboarding: asks you to test AgentWall by telling your AI to "read /etc/shadow", proving real-time blocking. |
| **🪄 Quick Policy Button** (FR-2.4) | Per-tool wand button in the Tool Inventory table; calls `POST /api/policy/quick-rule` to apply a standard security rule for that tool instantly. |

---

## How it works

When you run `agentwall wrap <target>` (or `agentwall protect`), the CLI edits the application's native configuration files (e.g., `settings.json`, `config.yaml`, or extension preferences) to point outbound HTTP and MCP connections to your local AgentWall proxy. 

To restore your configuration to its original state, run `agentwall unwrap <target>` or `agentwall unprotect` to restore all targets at once.
