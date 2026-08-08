## Prerequisites & Installation

Before getting started, ensure you have **Claude Desktop** (or Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity IDE) installed, along with the `agentwall` binary on your system:

### Installing AgentWall

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  curl -fsSL https://vexasec.io/install.sh | bash
  agentwall --version
  ```
* **Windows (PowerShell):**
  ```powershell
  irm https://vexasec.io/install.ps1 | iex
  agentwall.exe --version
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  curl.exe -fsSL https://vexasec.io/install.ps1 -o install.ps1 && powershell -ExecutionPolicy Bypass -File install.ps1
  agentwall.exe --version
  ```

*(The installer places the `agentwall` binary and the `quickstart_agent.py` test script into `~/.local/bin` / `%USERPROFILE%\.local\bin`).*

> [!NOTE]
> **Prerequisites for `quickstart_agent.py`**: Running the demonstration test script requires **Python 3.8+** installed on your system.

---

## Step 1: Start the AgentWall Proxy

First, start AgentWall in **developer mode** (shadow proxy). In this mode, AgentWall watches the traffic between Claude Desktop and your computer without blocking calls yet:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentwall dev
  ```
* **Windows (PowerShell):**
  ```powershell
  agentwall.exe dev
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  agentwall.exe dev
  ```

*AgentWall is now running and listening on `http://127.0.0.1:8080` (and opens the embedded browser dashboard at `http://127.0.0.1:8080`).*

---

## Step 2: Connect Claude Desktop to AgentWall

Open a **new, separate terminal window** and run the integration command:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentwall wrap claude
  agentwall status
  ```
* **Windows (PowerShell):**
  ```powershell
  agentwall.exe wrap claude
  agentwall.exe status
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  agentwall.exe wrap claude
  agentwall.exe status
  ```
*(This command updates Claude Desktop's configuration file so its MCP tool traffic routes through the proxy. Running `agentwall status` verifies the wrapping status).*

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
| **01. Tool Inventory** | Overview of all AI tools/APIs your agent has called, tracking total calls, last execution time, and safety risk tiers. |
| **02. Session Timeline** | Real-time live log of every single request, command, and tool call executed by your AI agent in chronological order. |
| **03. Parameter Explorer** | Select any observed tool to inspect the exact input arguments, text strings, commands, or file paths passed by your agent, including inferred data types and detected data patterns. |
| **04. Risk Flags** | Automatically flags high-risk tool operations (such as system file edits or command executions) requiring oversight. |
| **05. Data Loss Prevention (DLP)** | Scans outgoing tool payloads to prevent accidental leakage of sensitive credentials, API keys, passwords, and personal information (PII). |
| **06. Injection & Poisoning** | Detects prompt injection attempts and external data poisoning—where untrusted text tries to hijack agent instructions. |
| **07. Semantic Scanner** | Uses behavioral analysis to flag unusual or out-of-context tool requests that differ from normal agent interaction patterns. |
| **08. Generate Policy** | Automatically generates a baseline security policy (`agentwall-policy.yaml`) based on real observed agent traffic. |
| **09. ADR Benchmark** | Standardized benchmark testing your agent's defense readiness against 303 security test cases across 17 attack categories. |

---

## Step 4: Generate a Security Policy

Now that AgentWall has seen what tools Claude needs to use, we can generate a security policy (a firewall rule) that *only* allows those specific actions and blocks everything else.

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

## Step 5: Enforce the Policy

Right now, you are running `agentwall dev` (observation mode). Let's switch to **enforcement mode** to actually block bad behavior.

1. Go to your first terminal (where `agentwall dev` is running) and press `Ctrl + C` to stop it.
2. Start the gateway in enforcement mode using the policy we just generated:

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  agentwall start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
  ```
* **Windows (PowerShell):**
  ```powershell
  agentwall.exe start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  agentwall.exe start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
  ```

### Test the Firewall

Ask Claude / your agent to perform an unapproved action, such as accessing a restricted directory or unlisted path:
> *"Can you read the file `/etc/shadow`?"* or *"Can you inspect `../sensitive.key`?"*

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

## Step 6: Clean Up (Optional)

If you ever want to remove AgentWall from Claude Desktop and return to normal, simply run:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentwall unwrap claude
  ```
* **Windows (PowerShell / CMD):**
  ```powershell
  agentwall.exe unwrap claude
  ```

