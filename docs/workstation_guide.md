# Workstation Sidecar — User Guide

> **Target Audience:** Individual developers securing AI agent tool calls on a local workstation.
> No Docker, no database, no external servers required.

---

## What This Profile Provides

The **Workstation Sidecar** profile installs a single statically-linked binary that acts as a local security gateway and shadow proxy. Everything runs on your machine in seconds.

| Capability | What You Get |
|---|---|
| **Default-Deny Policy Engine** | 15 out-of-the-box safe-mode rules block dangerous tool calls even before you write a single policy line |
| **Prompt Injection Protection** | 9 active scanners intercept jailbreaks, instruction overrides, memory poisoning, and tool-response poisoning |
| **Dual-Pass DLP Scanning** | 21 built-in regex detectors redact or block AWS keys, SSH keys, PII, and API tokens in real time |
| **Passive Shadow AI Discovery** | Observe traffic risk-free and auto-generate a **Risk Delta Report** before enabling blocking mode |
| **MCP Security Scoring Engine** | Audit and score local MCP server definitions (0–100 Vexa Security Score) |
| **Local Developer Web Console** | Embedded real-time dashboard at `http://127.0.0.1:8080` |
| **IDE Auto-Wrapping Engine** | One-command patching of Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity IDE |
| **ADR Security Benchmark** | Run 303 attack-detection tasks across 17 categories to score your security posture |

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Step-by-Step: Getting Started](#3-step-by-step-getting-started)
   - [Step 1 — Protect & Launch (Recommended)](#step-1--protect--launch-recommended) | [Manual: `agentcontrol dev`](#step-1b--manual-launch-agentcontrol-dev)
   - [Step 2 — Route Agent HTTP Traffic Through Proxy](#step-2--route-agent-http-traffic-through-proxy)
   - [Step 3 — Wrap Stdio Tools & Desktop IDEs](#step-3--wrap-stdio-tools--desktop-ides)
   - [Step 4 — Auto-Generate Security Policy](#step-4--auto-generate-security-policy)
   - [Step 5 — Run ADR Security Benchmark](#step-5--run-adr-security-benchmark)
   - [Step 6 — Run MCP Security Scan](#step-6--run-mcp-security-scan)
4. [Safe Mode & Default-Deny Guardrails](#4-safe-mode--default-deny-guardrails)
5. [Prompt Injection Protection](#5-prompt-injection-protection)
6. [Shadow AI Discovery & Risk Delta Reports](#6-shadow-ai-discovery--risk-delta-reports)
7. [Shared Reference Sections](#7-shared-reference-sections)
8. [Upgrading to Team Control Hub](#8-upgrading-to-team-control-hub)

---

## 1. Prerequisites

| Requirement | Details |
|---|---|
| **Operating System** | Linux, macOS, or Windows (PowerShell / WSL / Git Bash) |
| **Network Utilities** | `curl` and `sh` for binary download (Linux/macOS/WSL) |
| **Python (Optional)** | Python 3.8+ — required only for executing the quickstart telemetry generator script (`quickstart_agent.py`) |
| **Node.js (Optional)** | `node` and `npx` v18+ — required only when wrapping stdio MCP servers (e.g., `@modelcontextprotocol/server-filesystem`) |
| **Write Permissions** | Ability to write to `~/.local/bin` (Linux/macOS) or `%USERPROFILE%\.local\bin` (Windows) |

> [!NOTE]
> On Windows, `curl` and `sh` are **not** required. The installer runs natively via PowerShell (`irm ... | iex`). Git Bash / WSL are optional alternatives, not prerequisites.

---

## 2. Installation

### macOS / Linux / WSL

```bash
# Install latest release (mandatory SHA-256 verified, strict error handling)
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash

agentcontrol --version
```

> [!TIP]
> **Enterprise / Team enrollment?** Use the separate `team_otet.sh` script which handles OTET token enrollment and Sentry daemon installation. See the [Team Control Hub Guide](team_hub_guide.md).

### Persistent OS Sentry Daemon & File Locking

Instead of manually running `agentcontrol start` in terminal, install Agent Control as an always-on background OS daemon with read-only file locks:

```bash
# Install persistent systemd (Linux) or launchd (macOS) service
# All three flags are required — they must match your Control Plane API configuration.
agentcontrol service install \
  --hub-url       "https://hub.corp.com" \
  --gateway-secret    "<GATEWAY_SECRET>" \
  --policy-read-secret "<POLICY_READ_SECRET>" \
  --agent-id      "dev-$(hostname)"   # optional: sets a friendly name in the dashboard

# Check daemon status
agentcontrol service status
```

> [!IMPORTANT]
> The `--gateway-secret` and `--policy-read-secret` values **must exactly match** the `GATEWAY_SECRET` and `POLICY_READ_SECRET` environment variables configured on your Control Plane API. Mismatched secrets cause HTTP 401 errors on every policy fetch. There are no safe defaults — you must supply real values.

**How Sentry Protection Works:**
- **Immutable File Locking:** Applies read-only attributes (`chmod 0444`, BSD `chflags uchg`, Windows ACL Write Deny) to `mcp.json` configs.
- **Continuous Watcher:** File changes trigger <300ms auto-rewrapping and instant (<100ms) `TAMPER_DETECTED` alert dispatch.
- **Windows Session 0 Scanning:** Automatically enumerates developer profile hives in `C:\Users\*` when running under `SYSTEM`.

**Permanent PATH configuration (run once — survives terminal restarts):**

- **Bash (Linux/WSL):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
  ```
- **Zsh (macOS):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
  ```
- **Fish:**
  ```fish
  fish_add_path ~/.local/bin
  ```

### Windows (PowerShell)

```powershell
# Install latest release (mandatory SHA-256 verified, auto-adds to user PATH)
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex

agentcontrol.exe --version
```

> [!NOTE]
> **`install/install.sh`** and **`install/install.ps1`** are the Standalone Developer installers. They auto-fetch the **latest release** from GitHub by default (override with `-v <tag>` / `-Version <tag>`), enforce a **mandatory SHA-256 checksum** (halt on mismatch or missing `checksums.txt`), and place the binary + `quickstart_agent.py` into `~/.local/bin` / `%USERPROFILE%\.local\bin`. The Windows script automatically adds the install dir to your user `PATH`.

> [!TIP]
> **Enterprise / Team enrollment?** Use the separate `team_otet.ps1` script instead. See the [Team Control Hub Guide](team_hub_guide.md).

> **Important — Installer Elevation & Administrator Permissions:**
> - **Enterprise Automated Deployments (Intune / SCCM / GPO / MSI):** Installer packages and GPO scripts execute under **`NT AUTHORITY\SYSTEM`** with full administrative rights. **`agentcontrol service install` runs automatically and sets all secrets at System scope.**
> - **Manual Script Execution (`install.ps1`):** Running `install.ps1` in an elevated Administrator session installs the binary and configures the `Agent ControlSentry` SCM Service. Run `agentcontrol service install` afterwards with your real secrets:
>   ```powershell
>   # Run in an elevated (Administrator) PowerShell session:
>   agentcontrol.exe service install `
>     --hub-url            "http://localhost:8400" `
>     --gateway-secret     "<GATEWAY_SECRET>" `
>     --policy-read-secret "<POLICY_READ_SECRET>" `
>     --agent-id           "dev-workstation-01"   # optional
>   ```
>   This writes `DASHBOARD_API_URL`, `GATEWAY_SECRET`, `POLICY_READ_SECRET` (and optionally `AGENT_ID`) to the HKLM system-scope registry **before** starting the service, so Sentry reads the correct secrets on first boot.
> - **Non-Admin Interactive Watcher:** Users without administrator access can run **`agentcontrol watch --all`** in a standard user terminal.


**Permanent PATH configuration (run once — survives terminal restarts):**

- **PowerShell (User Path):**
  ```powershell
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.local\bin", "User")
  ```
  *(Restart open PowerShell windows for the change to take effect.)*

- **Command Prompt (CMD):**
  ```cmd
  setx PATH "%PATH%;%USERPROFILE%\.local\bin"
  ```
  *(Re-open Command Prompt for the change to take effect.)*

- **Git Bash / MSYS2:**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile && source ~/.bash_profile
  ```

---

## 3. Step-by-Step: Getting Started

### Step 1 — Protect & Launch (Recommended)

The fastest path from zero to full protection. Run **one command** and Agent Control handles everything:
1. Auto-generates a baseline `agentcontrol-policy.yaml` with DLP secret rules if no policy exists
2. Discovers all installed AI IDEs (Cursor, Claude Desktop, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity, Codex) and atomically wraps their MCP configs
3. Starts the local gateway proxy listening on `127.0.0.1:8080` (audit log → `~/.agentcontrol/audit.jsonl`)
4. Opens the local developer dashboard in your default browser

```bash
agentcontrol protect                # macOS / Linux
agentcontrol protect --enforce      # Start immediately in active-blocking mode
agentcontrol protect --dry-run      # Preview all changes without writing to disk
```

**Windows (PowerShell):**
```powershell
agentcontrol.exe protect
```

**What You Will See:**
A terminal summary listing every IDE discovered, configs patched, and the baseline policy generated. Your default browser opens automatically at `http://127.0.0.1:8080`.

**What You Achieve:**
Full IDE protection + real-time agent event monitoring with zero manual configuration. Reverse everything cleanly with `agentcontrol unprotect`.

> [!NOTE]
> **`agentcontrol init` is deprecated.** All zero-config setup is now handled by `agentcontrol protect` in a single step.

---

### Step 1b — Observation-Only Mode (`agentcontrol protect --shadow`)

If you want to observe agent traffic *without* active policy enforcement (for risk auditing or policy learning), pass the `--shadow` flag:

```bash
agentcontrol protect --shadow          # macOS / Linux
agentcontrol.exe protect --shadow      # Windows
```

> [!NOTE]
> `agentcontrol dev` is deprecated in favor of `agentcontrol protect` and `agentcontrol protect --shadow`.

**What You Achieve:**
Real-time agent event monitoring is active. All traffic passing through the proxy appears instantly in the dashboard without active blocking, allowing you to assess agent behavior before enforcing policy rules.

> [!TIP]
> **Populating Test Telemetry:** `quickstart_agent.py` is automatically installed alongside the `agentcontrol` binary into your PATH. If your browser dashboard shows *"No tool calls recorded yet"*, run the test script in a separate terminal to populate all dashboard panels:
> ```bash
> python quickstart_agent.py
> ```

---

### Step 2 — Route Agent HTTP Traffic Through Proxy

Redirect HTTP/HTTPS requests from your AI agents or SDKs through Agent Control by setting standard proxy environment variables:

**Linux / macOS (Bash / Zsh):**
```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export AGENTWALL_PROXY_URL=http://127.0.0.1:8080
```

**Windows (PowerShell):**
```powershell
$env:HTTP_PROXY="http://127.0.0.1:8080"
$env:HTTPS_PROXY="http://127.0.0.1:8080"
$env:AGENTWALL_PROXY_URL="http://127.0.0.1:8080"
```

**Windows (Command Prompt / CMD):**
```cmd
set HTTP_PROXY=http://127.0.0.1:8080
set HTTPS_PROXY=http://127.0.0.1:8080
set AGENTWALL_PROXY_URL=http://127.0.0.1:8080
```

**What You Will See:**
Live HTTP requests from Python/Node AI scripts immediately appear in the browser dashboard.

**What You Achieve:**
All outgoing agent HTTP API calls (e.g., to OpenAI or Anthropic) are intercepted and recorded in `~/.agentcontrol/events.db`.

---

### Step 3 — Wrap Stdio Tools & Desktop IDEs

Secure Model Context Protocol (MCP) tool calls and desktop AI applications by wrapping their configuration.

#### Wrap a Stdio MCP Server

> **Prerequisites:** Node.js (`npx` v18+) installed and target directory created.

**Linux / macOS (Bash / Zsh):**
```bash
mkdir -p ~/workspace
agentcontrol dev --stdio -- npx -y @modelcontextprotocol/server-filesystem ~/workspace
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Path "$HOME\workspace" -Force
agentcontrol.exe dev --stdio -- npx -y @modelcontextprotocol/server-filesystem "$HOME\workspace"
```

**Windows (Command Prompt - CMD):**
```cmd
if not exist "%USERPROFILE%\workspace" mkdir "%USERPROFILE%\workspace"
agentcontrol.exe dev --stdio -- npx -y @modelcontextprotocol/server-filesystem "%USERPROFILE%\workspace"
```

> [!TIP]
> If `npx` is not found automatically (common with nvm/brew/fnm on macOS), pass the full path:
> ```bash
> agentcontrol dev --stdio -- $(which npx) -y @modelcontextprotocol/server-filesystem ~/workspace
> ```

**What You Will See:**
`Agent Control MCP Security Proxy` initialization header in your terminal.

#### Wrap a Desktop IDE

Agent Control automatically patches the MCP configuration file of the target IDE — no manual JSON editing required. Supported targets:

> [!TIP]
> **One-command protection:** Instead of wrapping IDEs one by one, use `agentcontrol protect` to discover and wrap **all** supported IDEs simultaneously, start the gateway, and open the dashboard:
> ```bash
> agentcontrol protect             # macOS / Linux — wraps all IDEs in one pass
> agentcontrol.exe protect         # Windows
> agentcontrol protect --dry-run   # Preview changes without writing to disk
> agentcontrol protect --enforce   # Start immediately in active-blocking mode
> ```
> To restore every IDE to its original config: `agentcontrol unprotect` (verifies backup integrity before restoring).

| IDE / Client | Wrap Command | Unprotect |
|---|---|---|
| Claude Desktop | `agentcontrol wrap claude` | `agentcontrol unwrap claude` |
| Cursor | `agentcontrol wrap cursor` | `agentcontrol unwrap cursor` |
| VS Code | `agentcontrol wrap vscode` | `agentcontrol unwrap vscode` |
| JetBrains IDEs | `agentcontrol wrap jetbrains` | `agentcontrol unwrap jetbrains` |
| Zed | `agentcontrol wrap zed` | `agentcontrol unwrap zed` |
| Cline | `agentcontrol wrap cline` | `agentcontrol unwrap cline` |
| OpenCode | `agentcontrol wrap opencode` | `agentcontrol unwrap opencode` |
| Antigravity IDE | `agentcontrol wrap antigravity` | `agentcontrol unwrap antigravity` |

**Linux / macOS (Bash / Zsh):**
```bash
agentcontrol wrap claude      # or cursor, vscode, jetbrains, zed, cline, opencode, antigravity
agentcontrol status           # inspect active wrappers and proxy health
```

**Windows (PowerShell / CMD):**
```powershell
agentcontrol.exe wrap claude  # or cursor, vscode, jetbrains, zed, cline, opencode, antigravity
agentcontrol.exe status       # inspect active wrappers and proxy health
```

> [!IMPORTANT]
> **Restart your IDE** after running `agentcontrol wrap <target>`. IDE processes read MCP configuration strictly at application startup.

**What You Achieve:**
MCP tool calls (file manipulation, shell execution, etc.) are proxied and governed by Agent Control. The IDE itself requires no plugin installation.

---

### Step 4 — Auto-Generate Security Policy

> [!TIP]
> **Using `agentcontrol protect`?** A baseline `agentcontrol-policy.yaml` is automatically created for you with P0 DLP secret rules when no policy file exists. You can skip this step and refine the generated policy manually.

After running your agents or IDE tools, generate a YAML security policy derived from the observed traffic. This is a **one-time learning step** — run it after observation, not during.

**Linux / macOS (Bash / Zsh):**
```bash
agentcontrol generate-policy --decay-window 30
```

**Windows (PowerShell / CMD):**
```powershell
agentcontrol.exe generate-policy --decay-window 30
```

**What You Will See:**
Terminal output displaying a newly generated `policy.yaml` rule set based on recorded events in `~/.agentcontrol/events.db` (or `%USERPROFILE%\.agentcontrol\events.db`).

**What You Achieve:**
A tailored, baseline security policy automatically crafted for your specific agent tools — without manual YAML writing.

> [!TIP]
> Run `agentcontrol generate-policy --decay-window 7` to weight recent traffic more heavily (7-day window). Use `--decay-window 30` for a broader 30-day baseline.

For complete YAML policy authoring and the v2 schema reference, see → [Common Reference Guide — YAML Policies](common_guide.md#writing-yaml-policies-v2-schema).

---

### Step 5 — Run ADR Security Benchmark

Evaluate how well your policy configuration detects and blocks 303 real-world AI attack tasks across 17 categories:

**Linux / macOS (Bash / Zsh):**
```bash
agentcontrol bench --full
```

**Windows (PowerShell / CMD):**
```powershell
agentcontrol.exe bench --full
```

*(When building from source: `cargo run -- bench --full`)*

The benchmark completes in under 60 seconds and writes a report to `target/benchmark-report.html`:

```bash
open target/benchmark-report.html            # macOS
xdg-open target/benchmark-report.html       # Linux
Start-Process target/benchmark-report.html  # Windows PowerShell
start target\benchmark-report.html          # Windows Command Prompt (CMD)
```

The **ADR Benchmark tab** in the local dashboard (`http://127.0.0.1:8080`) also renders the latest report interactively.

For the full benchmark reference (all 17 attack categories and scoring methodology), see → [Common Reference Guide — ADR Security Benchmark](common_guide.md#adr-security-benchmark).

---

### Step 6 — Run MCP Security Scan

Audit your local MCP server definitions and receive a Vexa Security Score (0–100) before deploying to production:

```bash
agentcontrol scan --path agentcontrol-policy.yaml
```

**What You Will See:**
A scored security report flagging risky tool definitions, missing parameter constraints, and unsafe path validators.

**What You Achieve:**
A Vexa Security Score you can use as a CI/CD quality gate to prevent insecure MCP server configurations from reaching production.

---

## 4. Safe Mode & Default-Deny Guardrails

Agent Control ships with **15 out-of-the-box safe-mode rules** that are active by default — no policy file required. These rules automatically block the most common dangerous AI agent behaviors:

| Rule Category | Example Detections |
|---|---|
| **Sensitive Path Access** | Blocks reads/writes to `.ssh/`, `.env`, `.aws/credentials`, `/etc/shadow`, `C:\Windows\System32` |
| **Credential File Exfiltration** | Blocks access to SSH private keys, API token files, and certificate stores |
| **Destructive Commands** | Blocks `rm -rf`, `DROP TABLE`, `format c:`, and irreversible file operations |
| **Persistence Mechanism Attempts** | Blocks modifications to startup scripts, cron jobs, and registry run keys |
| **Network Exfiltration Patterns** | Blocks sequential file-read → HTTP-POST patterns indicative of data exfiltration |

To view wrapper status and gateway health:
```bash
agentcontrol status
```

To enable **enforcing (blocking) mode** after observation:
```bash
agentcontrol start --policy agentcontrol-policy.yaml --listen 127.0.0.1:8080
```

For full policy authoring, see → [Common Reference Guide — YAML Policies](common_guide.md#writing-yaml-policies-v2-schema).

---

## 5. Prompt Injection Protection

Agent Control includes **9 active prompt injection scanners** that inspect both inbound tool call parameters and outbound tool response payloads:

| Scanner | What It Detects |
|---|---|
| **Direct Jailbreak Detection** | Instructions embedded in tool calls attempting to override system prompts |
| **Indirect Injection via Responses** | Malicious instructions hidden inside file contents, web page results, or API responses returned to the agent |
| **Instruction Override Patterns** | Phrases like "ignore previous instructions", "disregard your rules", "new system prompt" |
| **Memory Poisoning** | Attempts to corrupt the agent's conversation history or inject false memories |
| **Tool Call Poisoning** | Malformed tool definitions designed to trigger unauthorized executions |
| **Role-Play Escalation** | Social engineering prompts asking the agent to "act as" an unrestricted model |
| **Context Window Flooding** | Massive payloads intended to push safety instructions out of the context window |
| **Unicode & Encoding Exploits** | Zero-width characters, RTL overrides, and homoglyph substitutions masking injections |
| **Multi-Turn Manipulation** | Patterns that span multiple conversation turns to gradually bypass safety rules |

Injection detections appear in real time in the local dashboard under the **Threat Events** tab.

---

## 6. Shadow AI Discovery & Risk Delta Reports

**Shadow mode** lets you observe agent behavior for a period without blocking any calls, then generate a **Risk Delta Report** summarizing what would have been blocked had enforcement been active.

### Run Shadow Mode

```bash
agentcontrol start --shadow-mode --log-path audit.log
```

Or use `agentcontrol dev` (shadow mode is the default for the `dev` subcommand).

### Generate a Risk Delta Report

After agents have run and traffic has been logged:
```bash
agentcontrol report audit.log --risk
```

The report summarizes:
- **Tool calls that would have been denied** by policy
- **DLP matches** (credentials, PII) that would have been blocked or redacted
- **Prompt injection attempts** detected in observed traffic
- **Sequence-rule violations** (multi-step attack chains)
- **Recommended policy rules** to add based on observed behavior

---

## 7. Shared Reference Sections

The following technical reference sections apply across all deployment profiles and are maintained in the shared [Common Reference Guide](common_guide.md):

| Reference Topic | Link |
|---|---|
| Writing YAML Policies (v2.2 Schema) | [common_guide.md → YAML Policies](common_guide.md#writing-yaml-policies-v2-schema) |
| MCP Schema-Drift Detection (FR-601) | [user_guide.md → Schema Drift](user_guide.md#12-mcp-schema-drift-detection--client-sdks-v22) |
<!-- | Python SDK (`agentcontrol`) & TypeScript SDK (`@vexa/agentcontrol`) | [user_guide.md → Client SDKs](user_guide.md#python-client-sdk-agentcontrol) | -->
| OWASP Agentic Top 10 (ASI 2026) Architecture | [owasp_agentic_top10.md](owasp_agentic_top10.md) |
| Configuring Data Loss Prevention (DLP) | [common_guide.md → DLP](common_guide.md#configuring-data-loss-prevention-dlp) |
| Setting Up OIDC Identity Binding | [common_guide.md → OIDC](common_guide.md#setting-up-oidc-identity-binding) |
| Verifying Audit Logs | [common_guide.md → Audit Logs](common_guide.md#verifying-audit-logs) |
| Stateful Sequence Rules (ADR Framework) | [common_guide.md → Sequence Rules](common_guide.md#stateful-sequence-rules-adr-framework) |
| ADR Security Benchmark Reference | [common_guide.md → ADR Benchmark](common_guide.md#adr-security-benchmark) |
| Troubleshooting Common Issues | [common_guide.md → Troubleshooting](common_guide.md#troubleshooting-common-issues) |

---

## 8. Upgrading to Team Control Hub

When you are ready to extend governance across your engineering team — with centralized policy push, OIDC identity binding, shared API key custody, and a team web console — upgrade to the Team Control Hub profile:

→ **[Team Control Hub User Guide](team_hub_guide.md)**
