## Prerequisites & Installation

Before getting started, ensure you have **Claude Desktop** (or Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity IDE, Codex) installed, along with the `agentcontrol` binary on your system:

### Installing Vexa Agent Control

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  # Install latest release (mandatory SHA-256 verified, strict error handling)
  curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash

  agentcontrol --version
  ```
* **Windows (PowerShell):**
  ```powershell
  # Install latest release (mandatory SHA-256 verified, auto-adds to PATH)
  irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex

  agentcontrol.exe --version
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 -o install.ps1 && powershell -ExecutionPolicy Bypass -File install.ps1
  agentcontrol.exe --version
  ```

> [!NOTE]
> **`install/install.sh`** (Linux/macOS/WSL) and **`install/install.ps1`** (Windows) are the Standalone Developer installers. They resolve the **latest release** from GitHub via a resilient 3-tier fallback chain (GitHub API &rarr; HTTP Redirect Scraping &rarr; Stable Pinned Release), verify **SHA-256 integrity**, and install `agentcontrol` to `~/.local/bin` / `%USERPROFILE%\.local\bin`. The Windows script automatically adds the install directory to your user `PATH`.

> [!NOTE]
> **Prerequisites for `quickstart_agent.py`**: Running the demonstration test script requires **Python 3.8+** installed on your system. All fixture-generated telemetry is explicitly badged `[SIMULATED]` in the local dashboard.

> [!TIP]
> **Enterprise Team enrollment?** Use the separate `team_otet.sh` / `team_otet.ps1` scripts instead. See the [Team Control Hub Guide](team_hub_guide.md).

---

## Step 1: Secure Your IDE & Start Gateway

Run `agentcontrol protect` to automatically discover and wrap your installed AI IDEs (Cursor, Claude Desktop, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity, Codex), auto-generate a baseline `agentcontrol-policy.yaml` if missing, start the local gateway proxy (writing logs to `~/.agentcontrol/audit.jsonl` and database to `~/.agentcontrol/events.db`), and open the embedded dashboard in your default browser:

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
> **One-Command Protection (`agentcontrol protect`):** Running `agentcontrol protect` handles discovery, baseline policy generation, atomic config wrapping, and local console launch in a single step.

---

## Step 2: Instant Security Verification Smoke Test (60-Second Proof)

In a **separate terminal window**, run the live 3-point security verification probe to confirm gateway health, DLP redaction, and prompt injection defenses in milliseconds:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentcontrol verify
  ```
* **Windows (PowerShell):**
  ```powershell
  agentcontrol.exe verify
  ```

**Sample Output:**
```text
  ✔ [1/3] 1. Safe Tool Call (read_file)          ➔ ALLOWED & RECORDED (3ms)
  ✔ [2/3] 2. DLP Secret Leak (AWS Key & SSN)     ➔ BLOCKED (DLP-01) (2ms)
  ✔ [3/3] 3. Prompt Injection (System Override)  ➔ BLOCKED (INJ-04) (2ms)
────────────────────────────────────────────────────────────────────────
  ✨ All 3 Security Assertions Verified in 12ms!
```

---

## Step 3: Connect Claude Desktop or Custom Agents

To check IDE wrap status or manually wrap individual IDEs:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  agentcontrol status
  agentcontrol wrap claude
  ```
* **Windows (PowerShell):**
  ```powershell
  agentcontrol.exe status
  agentcontrol.exe wrap claude
  ```

*(Running `agentcontrol status` verifies that your IDE configs are actively protected).*

> [!TIP]
> **Custom Agents / CLI Tools:** If you build custom Python or Node.js agents, route their HTTP/MCP traffic to the gateway with:
> ```bash
> export AGENTCONTROL_PROXY_URL=http://127.0.0.1:8080
> export HTTP_PROXY=http://127.0.0.1:8080
> ```

---

## Step 4: Run a Real-World Scenario or Demonstration

1. Ensure standard filesystem / command MCP server tools are connected to Claude Desktop (or use standard file / search tools enabled in your IDE / agent).
2. Open **Claude Desktop** or your IDE and ask your agent:
   > *"Can you list the files in my current workspace folder?"*

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

---

## Understanding the Local Developer Dashboard

When opening `http://127.0.0.1:8080`, Agent Control presents a modern, 4-destination interface designed around trust coherence and rapid triage:

| Destination | Purpose & Key Features |
| :--- | :--- |
| **01. Overview** | Immediate answers to: *Is the gateway working? What happened? Do I need to act?* Displays protection status, real-time decision counters, recent real-time decisions, and a single contextual next action. |
| **02. Activity Stream** | Chronological record of all tool invocations with toggleable **Timeline Stream** and **Tool Summary** views, plus an expandable diagnostic Event Drawer with full JSON-RPC inspectability. |
| **03. Detections & DLP** | Consolidated security findings across Data Loss Prevention (DLP), Prompt Injections, High-Risk Flags, and Behavioral Anomalies with exact policy rule justifications and safely masked secret previews. |
| **04. Policy & Gateway** | View and hot-reload active `agentcontrol-policy.yaml` rules, review candidate suggestions, monitor IDE discovery and config wrap status, and inspect gateway listener health. |

**Persistent Header & Safety Guardrails:**
- **Gateway Health Badge** — Real-time state (`Healthy`, `Degraded`, `Disconnected`) linking directly to diagnostic details.
- **Posture Selector** — Switch between **Shadow** (observation only) and **Enforce** (active blocking) with a confirmation modal safeguard.
- **Universal Payload Redaction** — All AWS access keys, Bearer tokens, DB credentials, and SSNs are masked before rendering on any dashboard surface.
- **Explicit Telemetry Badging** — Synthetic and test records are visibly badged `[SIMULATED]` to prevent confusion with real agent traffic.
- **✨ Live Policy Synthesizer** — An on-demand side drawer that auto-generates least-privilege YAML rules on explicit user click.

---

## Step 4: Generate a Security Policy

Now that Agent Control has seen what tools Claude needs to use, we can generate a security policy (a firewall rule) that *only* allows those specific actions and blocks everything else.

> 💡 **No More Blank YAML — Policy Marketplace**: Want to apply a pre-configured security posture instantly without generating or editing YAML? Open **Policy Marketplace** (`/policy/marketplace`) in the Control Hub to choose one-click templates like **Safe Cursor**, **Production Data Egress**, or **HIPAA Compliance**.

In your second terminal window, run:

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  agentcontrol generate-policy --decay-window 30
  ```
* **Windows (PowerShell):**
  ```powershell
  agentcontrol.exe generate-policy --decay-window 30
  ```
* **Windows (Command Prompt - CMD):**
  ```cmd
  agentcontrol.exe generate-policy --decay-window 30
  ```

This creates an `agentcontrol-policy.yaml` file in your current folder. If you open this file, you will see something like this:

```yaml
# Auto-generated by Agent Control from 2 observed tool calls
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
        # Agent Control observed Claude ran "whoami" and automatically allowed it
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

`agentcontrol protect` runs in **Active Enforcement Mode** by default. All incoming tool calls and outgoing responses are checked against your `agentcontrol-policy.yaml` rules, instant secret DLP patterns, and dangerous path traversal checks.

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

Agent Control will immediately intercept and **block** the tool request (`403 Forbidden` / default-deny policy rule match), preventing the agent call from executing. You have successfully secured your AI Agent!

---

## Observation-Only Mode (`agentcontrol protect --shadow`)

If you want to observe agent tool traffic without active blocking (for policy learning or risk auditing), pass the `--shadow` flag:

```bash
agentcontrol protect --shadow          # macOS / Linux
agentcontrol.exe protect --shadow      # Windows
```

> [!NOTE]
> `agentcontrol dev` is deprecated in favor of `agentcontrol protect` and `agentcontrol protect --shadow`.

---

## Step 6: Clean Up (Optional)

If you ever want to remove Agent Control from Claude Desktop and return to normal, simply run:

* **macOS / Linux (Bash / Zsh):**
  ```bash
  # Remove from a single IDE:
  agentcontrol unwrap claude

  # Or restore ALL IDEs at once (if you used 'agentcontrol protect'):
  agentcontrol unprotect
  ```
* **Windows (PowerShell / CMD):**
  ```powershell
  agentcontrol.exe unwrap claude
  # Or:
  agentcontrol.exe unprotect
  ```

> [!NOTE]
> `agentcontrol unprotect` verifies backup integrity before restoring each config. Use `--force` to skip verification if you need emergency recovery.
