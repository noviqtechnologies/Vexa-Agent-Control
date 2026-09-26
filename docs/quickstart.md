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
- **Expected Result:** Prints `agentcontrol 1.0.90` (or current release).
- **If it fails:** Verify internet access to `raw.githubusercontent.com`. Refer to [Platform Installation Guides](install/).
- **What changes:** Binary placed in `~/.local/bin/agentcontrol` (or `%USERPROFILE%\.local\bin\agentcontrol.exe`).
- **Undo:** Delete the binary file or run the uninstaller script.

---

### Alternative: Zero-Touch Team Onboarding (SSO + Central Provider Key Custody)

If your company runs a **Vexa Team Hub**, you do not need individual provider keys or local policy files:

```bash
# 1. Authenticate with your corporate Google Workspace or Microsoft Entra ID
agentcontrol login --hub https://hub.yourcompany.com

# 2. Connect your AI coding assistant with zero secrets on disk
agentcontrol connect cursor
agentcontrol connect claude-code
```

- **How it works:**
  1. Opens your default browser for Google Workspace or Entra ID single sign-on.
  2. Ephemeral loopback callback safely persists sender-constrained session credentials into your OS Credential Store (Windows Credential Manager, macOS Keychain, Linux Secret Service).
  3. IDE configurations are pointed to `http://127.0.0.1:18080` with **zero provider secrets** on your local drive.
  4. Requests are authoritatively attributed to your corporate email and team budget at the Hub, while company upstream master keys stay safely in the server KMS vault.

---

### Step 2: Protect Your Workstation in 1 Command (`agentcontrol protect`)

- **Goal:** Automatically discover all installed AI assistants, verify listener responsiveness, and safely wrap configurations with atomic transaction rollback.
- **Run:**
  ```bash
  agentcontrol protect
  ```
  *(To start only the background security proxy without modifying IDE client files, run `agentcontrol start`.)*
- **Expected Result:**
  - Pre-flight check verifies listener port `18080`.
  - Staged atomic transaction journal created at `~/.agentcontrol/protect_journal.json`.
  - Discovers installed assistants: **Cursor**, **Claude Desktop**, **Claude Code**, **OpenAI Codex**, and **Google Antigravity**.
  - All target files safely updated; ownership manifests written to `~/.agentcontrol/manifests/<target>.manifest.json`.
  - Embedded Local Developer Dashboard available at `http://127.0.0.1:18080`.
- **What changes:** Target config files updated; ownership manifests and SQLite/audit storage initialized.
- **Undo:** Run `agentcontrol unprotect` (see Step 6).

---

### Step 3: Verified Client Routing & Enforcement Boundaries

- **Goal:** Understand exact routing paths and enforcement boundaries per assistant:
  - **Cursor IDE:** All LLM completion and MCP tool traffic routed through `127.0.0.1:18080` via `http.proxy`.
  - **Claude Code CLI:** Environment variable `ANTHROPIC_BASE_URL` routes all commands through the proxy.
  - **Google Antigravity IDE:** Intercepted via `mcp_config.json` (`proxy_url`).
  - **Claude Desktop:** MCP tools intercepted via child process `agentcontrol stdio-proxy`. Model completions connect directly to Anthropic cloud (*Tool Boundary Only*).
  - **OpenAI Codex CLI:** Shell wrapper script (`codex-intercept.sh`) intercepts Codex invocations.
- **Enforcement Boundary Guarantee:** Agent Control enforces controls strictly at the configured client and proxy layers. It does **not** capture raw OS network sockets or unmanaged terminal processes.
- **Selective Management:** Connect or disconnect assistants individually:
  ```bash
  agentcontrol connect cursor
  agentcontrol disconnect claude
  ```

---

### Step 4: Experience Live Protection in the Local Developer Dashboard (`http://127.0.0.1:18080`)

- **Goal:** Experience real-time governance, parameter DLP, and token telemetry in the embedded Local Developer Dashboard as tools execute.
- **Run:**
  1. Open the Local Developer Dashboard in your browser: `http://127.0.0.1:18080`.
  2. Ask your connected assistant (e.g. Cursor or Claude Desktop) to perform a coding task or tool call.
  3. Watch real-time SSE telemetry in the **Activity Stream**, inspect blocked prompt injections or redacted secrets in **Detections & DLP**, and check **Token Economics & Cache**.
  4. Inspect active status and freshness tiers from your terminal:
     ```bash
     agentcontrol status
     ```
     ```text
     Target: cursor          [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
     Target: claude          [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
     Target: codex           [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
     ```
- **What changes:** Telemetry streamed live to dashboard and persisted locally in `~/.agentcontrol/events.db`.
- **Undo:** Not applicable.

---

### Step 5: Dual-Store Maintenance & Diagnostics (`backup`, `verify-db`, `doctor`)

- **Goal:** Manage local SQLite database and cryptographic HMAC audit logs safely.
- **Run:**
  ```bash
  # 1. Consistent live backup (SQLite WAL VACUUM INTO + HMAC audit log):
  agentcontrol backup

  # 2. Cryptographic and database verification:
  agentcontrol verify-db

  # 3. Overall health diagnostics:
  agentcontrol doctor
  ```
- **Expected Result:**
  - `backup`: Produces an atomic snapshot in `~/.agentcontrol/backups/backup_<timestamp>` with restricted permissions (`0700`/`0600`).
  - `verify-db`: Validates SQLite `PRAGMA integrity_check;` on `events.db` and verifies the full HMAC-SHA256 hash chain of `audit.jsonl` from line 0 to EOF.
  - `doctor`: Reports 7-point health check passing with Exit Code 0.
- **What changes:** Backup snapshot written if requested.
- **Undo:** Delete backup folder when no longer needed.

---

### Step 6: 1-Command Clean Reversal Anytime (`agentcontrol unprotect`)

- **Goal:** Safely restore all target assistant configurations without losing user customizations.
- **Run:**
  ```bash
  # Revert all assistants at once:
  agentcontrol unprotect

  # Or revert a specific assistant:
  agentcontrol disconnect cursor
  ```
- **Expected Result:**
  ```text
  [✓] Successfully unprotected all assistants. Original configurations restored from manifests.
  ```
- **What changes:** Injected Agent Control keys are reverted to previous values, preserving custom themes, fonts, keybindings, and extensions.

---

### Step 7: Seamless In-Place Upgrade to Team Hub

- **Goal:** Transition from standalone developer mode to centralized Team governance without disrupting connected IDEs.
- **Run:**
  ```bash
  # Browser PKCE OAuth authentication:
  agentcontrol login

  # Or headless device enrollment:
  agentcontrol enroll --token <OTET> --hub https://console.vexasec.io
  ```
- **Expected Result:**
  - Profile state transitions from `local-gateway` to `team-gateway` in `~/.agentcontrol/profile.json`.
  - Existing wrapped IDE configurations remain completely intact.
  - Offline resilience: If Control Hub disconnects, Agent Control enforces the verified cached policy (`~/.agentcontrol/cached_policy.yaml`) and never fails open.
  - Return to standalone mode anytime via `agentcontrol logout`.

---

## Next Steps

- [User Guide](user_guide.md) — Master operational manual for developer workstations and enterprise fleets.
- [Workstation Guide](workstation_guide.md) — Deep dive into ownership manifests, port verification, and transaction journals.
- [Docker Deployment](guides/docker-deployment.md) — Standalone non-root compose (`docker-compose.standalone.yml`) and full-stack deployment.
- [CLI Reference](reference/cli.md) — Complete CLI command and flag specifications.
