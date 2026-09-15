# 10-Minute Developer Quickstart

This tutorial takes you from a clean machine to an authenticated workstation sentry with one connected AI coding assistant, live diagnostic health verification, and a proven non-destructive reversal path.

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

- **Goal:** Download and install the standalone release binary to `~/.local/bin` (or `%USERPROFILE%\.local\bin`).
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
- **Expected Result:** Prints `agentcontrol 1.0.82` (or current release).
- **If it fails:** Verify internet access to `raw.githubusercontent.com`. Refer to [Platform Installation Guides](install/).
- **What changes:** Binary placed in `~/.local/bin/agentcontrol` (or `%USERPROFILE%\.local\bin\agentcontrol.exe`).
- **Undo:** Delete the binary file or run the uninstaller script.

---

### Step 2: Authenticate via Browser PKCE OAuth

- **Goal:** Enroll workstation, generate local Ed25519 keypair, and start per-user background agent.
- **Run:**
  ```bash
  agentcontrol login
  ```
  *(On headless Linux servers or CI without a browser, run: `agentcontrol login --no-browser`)*
- **Expected Result:**
  - Browser opens to the secure OAuth login page.
  - Sentry authenticates and stores private key in your OS Keyring (DPAPI / Keychain / `0600` token file).
  - Background daemon starts on `127.0.0.1:18080`.
- **If it fails:** Check network connectivity to `app.vexasec.io`.
- **What changes:** Device credentials stored in secure store; background daemon registered for autostart on login.
- **Undo:** Run `agentcontrol logout`.

---

### Step 3: Connect Your AI Coding Assistant

- **Goal:** Atomically configure target assistant to route completions and MCP tools through Agent Control with baseline backup and ownership manifest.
- **Run:**
  - *For OpenAI Codex CLI:*
    ```bash
    agentcontrol connect codex
    ```
  - *For Claude Desktop:*
    ```bash
    agentcontrol connect claude
    ```
  - *For VS Code Continue Extension:*
    ```bash
    agentcontrol connect vscode-continue --mode cloud-direct
    ```
- **Expected Result:**
  - Pristine baseline backup created: `<config>.baseline.bak`.
  - Ownership manifest created: `~/.agentcontrol/manifests/<target>.manifest.json`.
  - Injected loopback routing (`127.0.0.1:18080`) or MCP `agentcontrol stdio-proxy` child wrapper.
  - Synthetic 1-token loopback probe verifies communication.
- **If it fails:** Check if assistant is installed or pinned version matches supported range (`agentcontrol doctor`).
- **What changes:** Target config updated; ownership manifest recorded.
- **Undo:** Run `agentcontrol disconnect <target>` (see Step 6).

---

### Step 4: Run Diagnostic Health Suite

- **Goal:** Verify complete workstation health, background daemon, target configurations, and security invariants.
- **Run:**
  ```bash
  agentcontrol doctor
  agentcontrol status
  ```
- **Expected Result:**
  ```text
  [PASS] Binary integrity & architecture verified
  [PASS] Authentication state: ENROLLED (OS_KEYRING)
  [PASS] Background daemon: RUNNING (127.0.0.1:18080, PID 14208)
  [PASS] Gateway latency: 24ms RTT (gateway.vexa.ai)
  [PASS] Target governance: codex CONFIGURED, PROBE_VERIFIED
  [PASS] Security invariants: No Root CA detected; No plaintext keys
  ```
- **If it fails:** Review diagnostic output for actionable error codes (`AUTH_REQUIRED`, `PORT_UNAVAILABLE`, etc.) and run `agentcontrol repair`.
- **What changes:** None (diagnostic inspection).
- **Undo:** Not applicable.

---

### Step 5: Test with Real AI Completions & MCP Tools

- **Goal:** Confirm real tool calls and completions flow through Vexa with parameter DLP and FinOps governance.
- **Run:**
  1. Restart your AI client (e.g., Codex or Claude Desktop) so it reloads its configuration.
  2. Ask your assistant to perform a task or run a tool call.
  3. Inspect active status and freshness tiers:
     ```bash
     agentcontrol status
     ```
- **Expected Result:** Target shows `TRAFFIC_VERIFIED` with freshness tier `ACTIVE_FRESH`.
- **What changes:** Real tool and LLM telemetry logged to `~/.agentcontrol/audit.jsonl`.
- **Undo:** Not applicable.

---

### Step 6: Non-Destructive Disconnect & Revert Anytime

- **Goal:** Safely restore target configurations from ownership manifests without erasing custom user settings.
- **Run:**
  ```bash
  # Restore specific assistant configuration:
  agentcontrol disconnect codex
  agentcontrol disconnect claude

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
- [Docker Deployment Guide](guides/docker-deployment.md) — Deploy standalone gateway or full stack via Docker / Docker Compose.
- [Custom Agent HTTP Guide](guides/custom-agent-http.md) — Route LangChain, LlamaIndex, or CrewAI agents.
- [Troubleshooting & Doctor Guide](guides/troubleshooting_doctor.md) — Deep dive into diagnostic exit codes and recovery workflows.
