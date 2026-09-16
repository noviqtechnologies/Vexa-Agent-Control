# IDE & Ecosystem Integrations

Agent Control provides seamless integrations with the most popular AI-powered IDEs and coding assistants.

Use `agentcontrol connect <target>` to automatically patch your local IDE configurations to route traffic and MCP tool calls through the Agent Control proxy.

---

## One-Command Protection

The `agentcontrol connect` command is the recommended way to secure individual AI coding assistants. To protect all detected IDEs in a single step:

```bash
# Start the local security gateway first:
agentcontrol start

# Connect individual targets:
agentcontrol connect claude
agentcontrol connect cursor
agentcontrol connect antigravity
agentcontrol connect codex
```

> [!NOTE]
> `agentcontrol connect` automatically:
> 1. **Discovers** the target IDE's MCP server configuration on your machine
> 2. **Creates timestamped backups** of every config before modifying it (atomic, zero-loss)
> 3. **Injects the Agent Control stdio-proxy** into each discovered IDE configuration
> 4. **Writes an ownership manifest** to `~/.agentcontrol/manifests/<target>.manifest.json`
> 5. **Sends a synthetic 1-token loopback probe** to assert routing

---

### Reverting to Original Configuration

The `agentcontrol disconnect <target>` command restores the IDE config from its ownership manifest. Backup integrity is verified before any reversion — ensuring zero-loss rollback.

```bash
# Disconnect specific targets:
agentcontrol disconnect claude
agentcontrol disconnect cursor
agentcontrol disconnect antigravity
agentcontrol disconnect codex

# Disconnect all managed targets at once:
agentcontrol disconnect --all

# Bypass backup integrity check (use only for recovery):
agentcontrol disconnect --force
```

> [!IMPORTANT]
> `disconnect` will **refuse** to restore from a corrupt or empty manifest by default. Use `--force` only if you are certain and want to proceed with manual cleanup.

---

### Advanced Connection Commands

- **Dry Run:** `agentcontrol connect <target> --dry-run`
- **Scan Responses:** `agentcontrol connect <target> --scan-responses`
- **Block on Secrets:** `agentcontrol connect <target> --block-on-secrets`

### Continuous Auto-Wrapping (`agentcontrol watch`)

You can run the **Watch Daemon** to continuously monitor your IDE configuration directories. Whenever a new MCP server is added to your IDE, Agent Control will automatically detect and wrap it in real time:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentcontrol watch
  ```

* **Windows (PowerShell / CMD):**
  ```powershell
  agentcontrol.exe watch
  ```

### Telemetry & Fleet Visibility (`agentcontrol status`)

Run the status command to view the existence and connection status of all supported IDE configurations on your machine:

* **macOS / Linux (Bash / Zsh):**
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

| Target IDE | Connect Command | Disconnect Command | Status |
|---|---|---|---|
| **Claude Desktop** | `agentcontrol connect claude` | `agentcontrol disconnect claude` | ✅ Verified |
| **Cursor** | `agentcontrol connect cursor` | `agentcontrol disconnect cursor` | ✅ Verified |
| **Antigravity IDE** | `agentcontrol connect antigravity` | `agentcontrol disconnect antigravity` | ✅ Verified |
| **Codex CLI** | `agentcontrol connect codex` | `agentcontrol disconnect codex` | ✅ Verified |
| **VS Code** | `agentcontrol connect vscode` | `agentcontrol disconnect vscode` | 🧪 Experimental |
| **JetBrains** | `agentcontrol connect jetbrains` | `agentcontrol disconnect jetbrains` | 🧪 Experimental |
| **Zed Editor** | `agentcontrol connect zed` | `agentcontrol disconnect zed` | 🧪 Experimental |
| **Cline** | `agentcontrol connect cline` | `agentcontrol disconnect cline` | 🧪 Experimental |
| **OpenCode** | `agentcontrol connect opencode` | `agentcontrol disconnect opencode` | 🧪 Experimental |

> [!NOTE]
> Legacy aliases `agentcontrol wrap <target>` and `agentcontrol unwrap <target>` remain functional but `connect` / `disconnect` are the preferred canonical commands.

---

## Local Dashboard Features

After running `agentcontrol start`, the Local Developer Dashboard is available at `http://127.0.0.1:18080`. Key features include:

| Feature | Description |
|---|---|
| **Security Posture Toggle** | Interactive SHADOW ↔ ENFORCE switch in the sidebar. Changes propagate instantly via real-time SSE. No restart needed. |
| **Live Spend Card** | Tracks estimated dollar cost of LLM token usage in real-time (`$0.000` base, accumulates per SSE event). |
| **Risks Blocked Counter** | Live count of tool calls that were denied (injections, sensitive path reads, policy violations). |
| **Mission Mode Banner** | Guided onboarding: ask your AI to "read /etc/shadow" to see real-time blocking in action. |
| **Quick Policy Button** | Per-tool wand button in the Tool Inventory table; applies a standard security rule for that tool instantly. |

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

When you run `agentcontrol connect <target>`, the CLI edits the application's native configuration files (e.g., `mcp.json`, `mcp_config.json`, `config.toml`) to wrap MCP server commands with `agentcontrol stdio-proxy --` and point LLM egress to `http://127.0.0.1:18080/v1`.

To restore your configuration to its original state, run `agentcontrol disconnect <target>` or `agentcontrol disconnect --all` to restore all targets at once.
