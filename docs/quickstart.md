# 10-Minute Developer Quickstart

This tutorial takes you from a clean machine to a running local gateway with one protected integration, live enforcement verification, and a proven rollback path.

---

## The 7-Step Interaction Contract

Every step in this guide defines: **Goal**, **Run**, **Expected Result**, **If it fails**, **What changes**, and **Undo**.

---

### Step 0: Platform Preflight

- **Goal:** Verify architecture compatibility and ensure port `8080` is free.
- **Run:**
  - *macOS / Linux / WSL:*
    ```bash
    uname -m && netstat -an | grep 8080 || echo "Port 8080 is available"
    ```
  - *Windows (PowerShell):*
    ```powershell
    $env:PROCESSOR_ARCHITECTURE; Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
    ```
- **Expected Result:** Architecture is `x86_64` or `aarch64` (or `AMD64` on Windows). Port 8080 is not in use.
- **If it fails:** If port 8080 is taken, select another port in Step 3 using `--listen 127.0.0.1:9090`.
- **What changes:** None (read-only inspection).
- **Undo:** Not applicable.

---

### Step 1: Install `agentcontrol` Binary

- **Goal:** Download and install the standalone release binary to `~/.local/bin`.
- **Run:**
  - *macOS / Linux / WSL:*
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
- **Expected Result:** Prints `agentcontrol 1.0.69`.
- **If it fails:** Verify internet access to `raw.githubusercontent.com`. Refer to [Platform Installation Guides](install/).
- **What changes:** Binary placed in `~/.local/bin/agentcontrol` (or `%USERPROFILE%\.local\bin\agentcontrol.exe`).
- **Undo:** Delete the binary file or run the uninstaller script.

---

### Step 2: Safe Discovery (Dry-Run)

- **Goal:** Identify which AI clients exist on your machine without modifying any configurations.
- **Run:**
  ```bash
  agentcontrol status
  agentcontrol protect --dry-run
  ```
- **Expected Result:** Prints an IDE config table showing existence and verification levels:
  - `Claude Desktop` [verified]
  - `Cursor` [verified]
  - `Codex` [verified]
  - `Antigravity` [verified]
  - `VS Code`, `JetBrains`, `Zed`, `Cline`, `OpenCode` [unverified]
- **If it fails:** Check if your client configuration is stored in a non-standard location. See [Integrations Matrix](integrations/README.md).
- **What changes:** None (dry-run mode).
- **Undo:** Not applicable.

---

### Step 3: Wrap Configuration & Launch Gateway

- **Goal:** Atomically wrap discovered configurations and launch the local security proxy.
- **Run:**
  - *For observation/audit-only mode (recommended for evaluation):*
    ```bash
    agentcontrol protect --shadow
    ```
  - *For active blocking mode (DLP & injection prevention):*
    ```bash
    agentcontrol protect
    ```
- **Expected Result:**
  - Terminal prints discovered and wrapped MCP targets.
  - A timestamped backup is saved next to each modified config.
  - Local gateway starts listening on `http://127.0.0.1:8080`.
  - Local dashboard automatically opens in your browser.
- **If it fails:** If a port collision occurs, specify `--listen 127.0.0.1:9090`.
- **What changes:**
  - Client config files modified to route stdio tool calls through `agentcontrol stdio-proxy`.
  - Backups created: `<config_file>.bak.<timestamp>`.
  - Baseline policy created: `./agentcontrol-policy.yaml`.
  - Event logs written: `~/.agentcontrol/audit.jsonl`.
- **Undo:** Run `agentcontrol unprotect` (see Step 6).

---

### Step 4: Verify Live Enforcement

- **Goal:** Prove the gateway is actively evaluating and blocking threats using a 3-point smoke test.
- **Run (in a second terminal):**
  ```bash
  agentcontrol verify
  ```
- **Expected Result:**
  ```text
  ✔ [1/3] Safe Tool Execution (read_file)      ➔ ALLOWED
  ✔ [2/3] DLP Exfiltration Guard (AWS Key)     ➔ BLOCKED [DLP-01-HIGH-ENTROPY]
  ✔ [3/3] Prompt Injection (System Override)  ➔ BLOCKED [INJ-04-OVERRIDE]
  ```
- **If it fails:** Ensure the `agentcontrol protect` process is running in your primary terminal.
- **What changes:** 3 probe events logged in `~/.agentcontrol/audit.jsonl`.
- **Undo:** None needed.

---

### Step 5: Test with Your Real AI Client

- **Goal:** Confirm your AI agent tool calls flow through Vexa.
- **Run:**
  1. Restart your AI client (e.g., Claude Desktop or Cursor) so it loads the updated configuration.
  2. Ask your AI client to execute any tool call (e.g., "List files in workspace").
  3. Open the Local Dashboard at `http://127.0.0.1:8080` or view logs:
     ```bash
     tail -f ~/.agentcontrol/audit.jsonl
     ```
- **Expected Result:** The event appears in the Local Dashboard marked with a live timestamp and verdict `ALLOW`.
- **What changes:** Real tool call events appended to audit log.
- **Undo:** Not applicable.

---

### Step 6: Roll Back & Restore Original State

- **Goal:** Safely restore all client configurations from backups and verify clean removal.
- **Run:**
  ```bash
  # Restore all wrapped configurations:
  agentcontrol unprotect

  # Verify all configurations are back to original state:
  agentcontrol status
  ```
- **Expected Result:**
  ```text
  ✔ Claude Desktop: Restored config from .../claude_desktop_config.json.bak.xxx
  ✔ Restored: 1, No Backups Needed: 8, Errors: 0
  ```
- **What changes:** Client config files are replaced with the pre-Vexa backup copies.
- **Undo:** You can re-run `agentcontrol protect` at any time.

---

## Next Steps

- [Workstation Guide](guides/workstation.md) — Learn how to generate custom policies with `agentcontrol generate-policy`.
- [Custom Agent HTTP Guide](guides/custom-agent-http.md) — Route LangChain, LlamaIndex, or CrewAI agents.
- [Small Team Hub Guide](guides/small-team-hub.md) — Share security policies across your team.
