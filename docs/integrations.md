# IDE & Ecosystem Integrations

AgentWall provides seamless integrations with the most popular AI-powered IDEs and coding assistants. 

Instead of manually setting up environment variables, you can use the `agentwall wrap` command to automatically patch your local IDE configurations to route traffic through the AgentWall proxy.

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

## How it works

When you run `agentwall wrap <target>`, the CLI edits the application's native configuration files (e.g., `settings.json`, `config.yaml`, or extension preferences) to point outbound HTTP and MCP connections to your local AgentWall proxy. 

To restore your configuration to its original state, run `agentwall unwrap <target>`.
