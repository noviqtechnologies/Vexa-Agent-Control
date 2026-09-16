# 10-Minute Developer Quickstart

This tutorial takes you from a clean machine to a fully protected local workstation sentry with connected AI coding assistants, real-time developer dashboard visibility, and a proven non-destructive reversal path. **Zero Docker, zero external databases, and zero Control Hub required.**

---

## The 6-Step Interaction Contract

Every step in this guide defines: **Goal**, **Run**, **Expected Result**, **If it fails**, **What changes**, and **Undo**.

---

### Step 0: Platform Preflight

- **Goal:** Verify architecture compatibility and ensure port `18080` is free.
- **Run:**
  - *macOS / Linux / WSL:*
    ```bash
    uname -m && netstat -an | grep 18080 || echo "Port 18080 is available"
    ```
  - *Windows (PowerShell):*
    ```powershell
    $env:PROCESSOR_ARCHITECTURE; Get-NetTCPConnection -LocalPort 18080 -ErrorAction SilentlyContinue
    ```
- **Expected Result:** Architecture is `x86_64` or `aarch64` (or `AMD64` on Windows). Port 18080 is not in use.
- **If it fails:** If port 18080 is taken, the daemon automatically binds to an available fallback port in range `18080..=18090` and writes the active port to `~/.agentcontrol/daemon.port`.
- **What changes:** None (read-only inspection).
- **Undo:** Not applicable.

---

### Step 1: Install `agentcontrol` Binary

- **Goal:** Download and install the standalone release binary to `~/.local/bin` (or `%USERPROFILE%\.local\bin` on Windows).
- **Run:**
  - *macOS / Linux / WSL (Bash / Zsh):*
    ```bash
    curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
    export PATH="$HOME/.local/bin:$PATH"
    agentcontrol --version
    ```
  - *Windows (PowerShell):*
    ```powershell
    irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex
    agentcontrol.exe --version
    ```
  - *Windows (Command Prompt - CMD):*
    ```cmd
    curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 -o "%TEMP%\install.ps1" && powershell.exe -ExecutionPolicy Bypass -File "%TEMP%\install.ps1" && del "%TEMP%\install.ps1"
    set PATH=%USERPROFILE%\.local\bin;%PATH%
    agentcontrol.exe --version
    ```
- **Expected Result:** Prints `agentcontrol 1.0.85` (or current release).
- **If it fails:** Verify internet access to `raw.githubusercontent.com`. Refer to [Platform Installation Guides](install/).
- **What changes:** Binary placed in `~/.local/bin/agentcontrol` (or `%USERPROFILE%\.local\bin\agentcontrol.exe`).
- **Undo:** Delete the binary file or run the uninstaller script.

---

### Step 2: Start Local Gateway Daemon (`agentcontrol start`)

- **Goal:** Start the local security gateway and proxy daemon on `127.0.0.1:18080`.
- **Run:**
  ```bash
  agentcontrol start
  ```
  *(To register as a persistent per-user service across reboots, run `agentcontrol service install`).*
- **Expected Result:**
  - Gateway starts listening on `127.0.0.1:18080`.
  - Local high-entropy token generated in `~/.agentcontrol/local.token` (`vx-local-...`).
  - Embedded SQLite audit store initialized at `~/.agentcontrol/events.db` (WAL mode).
  - Embedded Local Developer Dashboard available at `http://127.0.0.1:18080`.
- **If it fails:** Ensure port 18080 is free or check fallback port in `~/.agentcontrol/daemon.port`.
- **What changes:** Local token and SQLite audit database initialized; gateway process active.
- **Undo:** Stop the daemon (`Ctrl+C` or `agentcontrol service uninstall`).

---

### Step 3: Connect Your AI Coding Assistants (`agentcontrol connect <target>`)

- **Goal:** Configure target assistants to route completions and MCP tools through Agent Control with baseline backups and ownership manifests.
- **Run:**
  In a new terminal window:
  ```bash
  # For Claude Desktop:
  agentcontrol connect claude

  # For Cursor:
  agentcontrol connect cursor

  # For Antigravity IDE:
  agentcontrol connect antigravity

  # For OpenAI Codex CLI:
  agentcontrol connect codex
  ```
- **Expected Result:**
  - Pristine baseline backup created: `<config>.baseline.bak`.
  - Ownership manifest created: `~/.agentcontrol/manifests/<target>.manifest.json`.
  - Injected loopback routing (`127.0.0.1:18080`) using local token or child MCP `agentcontrol stdio-proxy` wrapper.
  - Synthetic 1-token loopback probe verifies communication.
- **If it fails:** Check if assistant is installed or pinned version matches supported range (`agentcontrol doctor`).
- **What changes:** Target config updated; ownership manifest recorded.
- **Undo:** Run `agentcontrol disconnect <target>` (see Step 6).

---

### Step 4: Experience Live Protection in the Local Developer Dashboard (`http://127.0.0.1:18080`)

- **Goal:** Experience real-time governance, parameter DLP, and token telemetry in the embedded Local Developer Dashboard as tools execute.
- **Run:**
  1. Open the Local Developer Dashboard in your browser: `http://127.0.0.1:18080`.
  2. Ask your connected coding assistant (e.g., Codex or Claude Desktop) to perform a coding task or run a tool call.
  3. Watch real-time SSE telemetry in the **Activity Stream**, inspect blocked prompt injections or redacted secrets in **Detections & DLP**, and check **Token Economics & Cache**.
  4. Inspect active status and freshness tiers from your terminal:
     ```bash
     agentcontrol status
     ```
- **Expected Result:**
  ```text
  Target: claude          [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
  Target: cursor          [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
  Target: antigravity     [CONFIGURED, PROBE_VERIFIED]                   (🟢 ACTIVE_FRESH)
  Target: codex           [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
  ```
- **What changes:** Telemetry streamed live to dashboard and persisted in `~/.agentcontrol/events.db`.
- **Undo:** Not applicable.

---

### Step 5: Run Diagnostic Health Suite (`agentcontrol doctor`)

- **Goal:** Verify complete workstation health, background daemon, target configurations, and local security invariants.
- **Run:**
  ```bash
  agentcontrol doctor
  ```
- **Expected Result:**
  ```text
  ✔ Binary Integrity:          Pass (v1.0.85)
  ✔ Local Token Health:        Pass (~/.agentcontrol/local.token, 0600)
  ✔ Daemon Reachability:       Pass (127.0.0.1:18080 responsive)
  ✔ Local Database Health:     Pass (~/.agentcontrol/events.db, WAL active)
  ✔ Target Configuration:      Pass (claude: verified, cursor: verified, codex: verified)
  ✔ Security Hygiene:          Pass (Zero plaintext keys detected in env)

  Overall Health: HEALTHY (Exit Code 0)
  ```
- **If it fails:** Review diagnostic output for actionable error codes and run `agentcontrol repair`.
- **What changes:** None (read-only diagnostic inspection).
- **Undo:** Not applicable.

---

### Step 6: Non-Destructive Disconnect & Revert Anytime (`agentcontrol disconnect <target>`)

- **Goal:** Safely restore target configurations from ownership manifests without erasing custom user settings.
- **Run:**
  ```bash
  # Restore specific assistant configuration:
  agentcontrol disconnect claude
  agentcontrol disconnect cursor
  agentcontrol disconnect antigravity
  agentcontrol disconnect codex

  # Diagnose and repair configuration drift without losing settings:
  agentcontrol repair
  ```
- **Expected Result:**
  ```text
  [✓] Successfully disconnected codex. Restored original configuration from manifest.
  ```
- **What changes:** Injected Agent Control keys are reverted to previous values (or deleted if previously absent), while user-added keys remain untouched.
- **Undo:** Reconnect at any time with `agentcontrol connect <target>`.

---

## Next Steps

- [User Guide](user_guide.md) — Master operational manual for developer workstations and enterprise fleets.
- [Workstation Guide](guides/workstation.md) — 4-stage lifecycle: Observe (Shadow Mode) → Validate → Enforce → Restore.
- [Custom Agent HTTP Guide](guides/custom-agent-http.md) — Route LangChain, LlamaIndex, or CrewAI agents.
- [Troubleshooting & Doctor Guide](guides/troubleshooting_doctor.md) — Deep dive into diagnostic exit codes and recovery workflows.
