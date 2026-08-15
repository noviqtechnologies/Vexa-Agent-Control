## Prerequisites & Installation

Before getting started, ensure you have **Claude Desktop** (or Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity IDE, Codex) installed, along with the `agentcontrol` binary on your system:

### Installing Vexa Agent Control

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  # Install latest release (mandatory SHA-256 verified, strict error handling)
  curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/install/install.sh | bash

  agentcontrol --version
  ```
* **Windows (PowerShell):**
  ```powershell
  # Install latest release (mandatory SHA-256 verified, auto-adds to PATH)
  irm https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/install/install.ps1 | iex

  agentcontrol.exe --version
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/install/install.ps1 -o install.ps1 && powershell -ExecutionPolicy Bypass -File install.ps1
  agentcontrol.exe --version
  ```

> [!NOTE]
> **`install/install.sh`** and **`install/install.ps1`** are the Standalone Developer installers. They auto-fetch the **latest release** from GitHub by default (override with `-v <tag>` / `-Version <tag>`), enforce a **mandatory SHA-256 checksum** (halt on mismatch or missing `checksums.txt`), and place `agentcontrol` and legacy alias `agentwall` + `quickstart_agent.py` into `~/.local/bin` (Linux/macOS) or `%USERPROFILE%\.local\bin` (Windows). The Windows script automatically adds the directory to your user `PATH`.

> [!NOTE]
> **Prerequisites for `quickstart_agent.py`**: Running the demonstration test script requires **Python 3.8+** installed on your system.

> [!TIP]
> **Enterprise Team enrollment?** Use the separate `team_otet.sh` / `team_otet.ps1` scripts instead. See the [Team Control Hub Guide](team_hub_guide.md).

---

## Step 1: Secure Your IDE & Start Gateway

Run `agentcontrol protect` to automatically discover and wrap your installed AI IDEs (Cursor, Claude Desktop, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity, Codex), auto-generate a baseline `agent-control-policy.yaml` if missing, start the local gateway proxy (writing logs to `~/.agent-control/audit.jsonl`), and open the embedded dashboard in your default browser:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentcontrol protect
  ```
* **Windows (PowerShell):**
  ```powershell
  agentcontrol.exe protect
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  agentcontrol.exe protect
  ```

*Vexa Agent Control is now running, listening on `http://127.0.0.1:8080`, and has opened the embedded local dashboard in your browser.*

> [!NOTE]
> **One-Command Protection (`agentcontrol protect`):** Running `agentcontrol protect` handles discovery, baseline policy generation, atomic config wrapping, and local console launch in a single step. The legacy `agentwall` alias is also supported.

---

## Step 2: Connect Claude Desktop to Agent Control

Open a **new, separate terminal window** and run the integration command:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentcontrol wrap claude
  agentcontrol status
  ```
* **Windows (PowerShell):**
  ```powershell
  agentcontrol.exe wrap claude
  agentcontrol.exe status
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  agentwall.exe wrap claude
  agentwall.exe status
  ```
*(This command updates Claude Desktop's configuration file so its MCP tool traffic routes through the proxy. Running `agentwall status` verifies the wrapping status).*

> [!TIP]
> **New one-command option:** Instead of wrapping individual IDEs, you can use `agentwall protect` to auto-discover and wrap all supported IDEs simultaneously, start the gateway, and open the dashboard in one step:
> ```bash
> agentwall protect          # macOS / Linux
> agentwall.exe protect      # Windows
> agentwall protect --dry-run  # Preview all changes without writing
> ```
> To undo everything at once: `agentwall unprotect`

---

## Step 3: Run a Real-World Scenario

1. Ensure standard filesystem / command MCP server tools are connected to Claude Desktop (or use standard file / search tools enabled in your IDE / agent).
2. Open **Claude Desktop** on your computer.
3. Ask Claude to perform a tool call. For example, type:
   > *"Can you list the files in my current workspace folder?"* or *"Can you inspect the files in my directory?"*

*Alternatively, run the instant test demonstration script to populate all telemetry without configuring an IDE (requires **Python 3.8+**):*

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  python3 ~/.local/bin/quickstart_agent.py
  ```
* **Windows (PowerShell):**
  ```powershell
  python "$env:USERPROFILE\.local\bin\quickstart_agent.py"
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  python "%USERPROFILE%\.local\bin\quickstart_agent.py"
  ```
*(This sends simulated AI tool calls through `http://127.0.0.1:8080` to populate the dashboard immediately if you see "No tool calls recorded yet").*

Claude / your agent will call its configured MCP tools. Meanwhile, in your first terminal window and at `http://127.0.0.1:8080`, you will see AgentWall logging these actions in real time!

---

## Understanding the Local Observability Dashboard

When opening `http://127.0.0.1:8080`, AgentWall provides an intuitive dashboard for monitoring agent activities—designed for non-security users to easily understand:

| Panel | Purpose & Description (Plain English) |
| :--- | :--- |
| **01. Tool Inventory** | Overview of all AI tools/APIs your agent has called, tracking total calls, last execution time, and safety risk tiers. Each tool has a 🪄 **Quick Policy** button to apply a standard security rule instantly. |
| **02. Session Timeline** | Real-time live log of every single request, command, and tool call executed by your AI agent in chronological order. |
| **03. Parameter Explorer** | Select any observed tool to inspect the exact input arguments, text strings, commands, or file paths passed by your agent, including inferred data types and detected data patterns. |
| **04. Risk Flags** | Automatically flags high-risk tool operations (such as system file edits or command executions) requiring oversight. |
| **05. Data Loss Prevention (DLP)** | Scans outgoing tool payloads to prevent accidental leakage of sensitive credentials, API keys, passwords, and personal information (PII). |
| **06. Injection & Poisoning** | Detects prompt injection attempts and external data poisoning—where untrusted text tries to hijack agent instructions. |
| **07. Semantic Scanner** | Uses behavioral analysis to flag unusual or out-of-context tool requests that differ from normal agent interaction patterns. |
| **08. Generate Policy** | Automatically generates a baseline security policy (`agentwall-policy.yaml`) based on real observed agent traffic. |
| **09. ADR Benchmark** | Standardized benchmark testing your agent's defense readiness against 303 security test cases across 17 attack categories. |

**Dashboard highlights:**
- **Security Posture Toggle** — Use the SHADOW ↔ ENFORCE switch in the sidebar to enable active blocking without restarting the proxy.
- **Live Spend** — Tracks estimated LLM token cost in real-time (`$0.000` initially, accumulates as tool calls flow through).
- **Risks Blocked** — Live counter of denied tool calls (injections, sensitive path reads, policy violations).
- **Mission Mode Banner** — Guided test: ask your AI to read `/etc/shadow` to prove real-time detection and blocking.

---

## Step 4: Generate a Security Policy

Now that AgentWall has seen what tools Claude needs to use, we can generate a security policy (a firewall rule) that *only* allows those specific actions and blocks everything else.

> 💡 **No More Blank YAML — Policy Marketplace**: Want to apply a pre-configured security posture instantly without generating or editing YAML? Open **Policy Marketplace** (`/policy/marketplace`) in the Control Hub to choose one-click templates like **Safe Cursor**, **Production Data Egress**, or **HIPAA Compliance**.

In your second terminal window, run:

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  agentwall generate-policy --decay-window 30
  ```
* **Windows (PowerShell):**
  ```powershell
  agentwall.exe generate-policy --decay-window 30
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  agentwall.exe generate-policy --decay-window 30
  ```

This creates an `agentwall-policy.yaml` file in your current folder. If you open this file, you will see something like this:

```yaml
# Auto-generated by AgentWall from 2 observed tool calls
version: "2"
default_action: deny

self_healing:
  enabled: true
  decay_window: 30d
  auto_suggest: true
  suggest_threshold: 0.9
  approval_required: true

tools:
  - name: exec_shell
    action: allow
    # risk_tier: TIER_1  confidence: low (1 observations)
    parameters:
      - name: command
        type: string
        required: true
        max_length: 128
        # AgentWall observed Claude ran "whoami" and automatically allowed it
        pattern: "^whoami$"

  - name: read_file
    action: allow
    # risk_tier: TIER_2  confidence: low (1 observations)
    parameters:
      - name: path
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
```

---

## Step 5: Enforce Policies & Observe DLP Shield

`agentwall protect` runs in **Active Enforcement Mode** by default. All incoming tool calls and outgoing responses are checked against your `agentwall-policy.yaml` rules, instant secret DLP patterns, and dangerous path traversal checks.

### Test the Firewall

Ask Claude / your agent to perform an unapproved action, such as accessing a restricted directory or sensitive file:
> *"Can you read the file `/etc/shadow`?"* or *"Can you inspect `~/.ssh/id_rsa`?"*

*(Alternatively, send a test HTTP request to verify policy enforcement directly):*

* **macOS / Linux (Bash / Zsh):**
  ```bash
  curl -X POST http://127.0.0.1:8080/mcp -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}},"id":1}'
  ```

* **Windows (PowerShell):**
  ```powershell
  Invoke-RestMethod -Uri "http://127.0.0.1:8080/mcp" -Method Post -ContentType "application/json" -Body '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/shadow"}},"id":1}'
  ```

* **Windows (Command Prompt - CMD):**
  ```cmd
  curl.exe -X POST http://127.0.0.1:8080/mcp -H "Content-Type: application/json" -d "{\"jsonrpc\":\"2.0\",\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/etc/shadow\"}},\"id\":1}"
  ```

AgentWall will immediately intercept and **block** the tool request (`403 Forbidden` / default-deny policy rule match), preventing the agent call from executing. You have successfully secured your AI Agent!

---

## Observation-Only Mode (`agentwall protect --shadow`)

If you want to observe agent tool traffic without active blocking (for policy learning or risk auditing), pass the `--shadow` flag:

```bash
agentwall protect --shadow          # macOS / Linux
agentwall.exe protect --shadow      # Windows
```

> [!NOTE]
> `agentwall dev` is deprecated in favor of `agentwall protect` and `agentwall protect --shadow`.

---

## Step 6: Clean Up (Optional)

If you ever want to remove AgentWall from Claude Desktop and return to normal, simply run:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  # Remove from a single IDE:
  agentwall unwrap claude

  # Or restore ALL IDEs at once (if you used 'agentwall protect'):
  agentwall unprotect
  ```
* **Windows (PowerShell / CMD):**
  ```powershell
  agentwall.exe unwrap claude
  # Or:
  agentwall.exe unprotect
  ```

> [!NOTE]
> `agentwall unprotect` verifies backup integrity before restoring each config. Use `--force` to skip verification if you need emergency recovery.
