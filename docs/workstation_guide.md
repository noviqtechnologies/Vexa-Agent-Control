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
| **Local Developer Web Console** | Embedded real-time dashboard at `http://127.0.0.1:18080` |
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
   - [Step 7 — Run Verification Probe & Assert Effective Routing](#step-7--run-verification-probe--assert-effective-routing)
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

> [!TIP]
> **Prefer Running with Docker?**
> If you prefer not to install binaries on your host machine, you can run the standalone gateway via `docker compose -f docker-compose.standalone.yml up -d` or `docker run`:
> ```bash
> docker run -d --name agentcontrol -p 127.0.0.1:18080:18080 -v agentcontrol-data:/app/data -v agentcontrol-logs:/var/log/agentcontrol -e AGENTCONTROL_ADMIN_TOKEN="admin123456" ghcr.io/noviqtechnologies/agentcontrol:latest start --listen 0.0.0.0:18080 --container-bridge-mode
> ```
> See the full [Docker Deployment Guide](guides/docker-deployment.md).

### macOS / Linux / WSL (Native Binary)

```bash
# Install latest release (mandatory SHA-256 verified, strict error handling)
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash

agentcontrol --version
```

> [!TIP]
> **Enterprise / Team enrollment?** Use the separate `team_otet.sh` script which handles OTET token enrollment and Sentry daemon installation. See the [Team Control Hub Guide](team_hub_guide.md).

### Persistent OS Sentry Daemon & Always-On Governance

The simplest way to register Agent Control as an always-on background daemon is through the **zero-touch login flow**, which handles authentication, device enrollment, and service registration in a single step:

```bash
# Zero-touch: authenticate, enroll, and register background daemon in one command
agentcontrol login --hub "https://app.vexasec.io"
```

This opens your browser for PKCE SSO, generates a local Ed25519 device key, and automatically registers the background OS service — no separate `service install` step required.

For advanced or scripted scenarios where you need direct service control after authentication:

```bash
# Check daemon health (works after login or service install)
agentcontrol service status
```

Example Output:
```text
● Vexa Agent Control Daemon Health Inspection
  OS Platform:        windows (x86_64)
  Supervisor Type:    Windows User Startup (HKCU\Run) (ACTIVE / SUPERVISED)
  Daemon Process:     PID 25936 (v1.0.89) | Up 23s
  Listener Binding:   127.0.0.1:18080 (20 ms RTT)
  Hub Connection:     ENROLLED (http://127.0.0.1:8081) | Policy: ACTIVE (local-safe-mode)
```

```bash
# System-level enterprise install (requires Administrator / root; no prior enrollment needed)
agentcontrol service install --enterprise --hub-url "https://app.vexasec.io"

# Completely uninstall background daemon
agentcontrol service uninstall
```

> [!NOTE]
> `agentcontrol service install` (without `--enterprise`) requires prior authentication via `agentcontrol login`. The `login` command already calls `service install` internally after successful PKCE authentication, so you only need `service install` directly if re-registering after an OS-level supervisor failure.

**Architecture & Security Contract:**
- **One Platform → One Authoritative Supervisor:**
  - **Linux:** Standard user uses `systemd --user` with linger verification; enterprise mode uses `/etc/systemd/system/`.
  - **macOS:** Standard user uses domain-scoped `LaunchAgent` (`gui/<uid>/io.vexasec.agentcontrol`); enterprise mode uses `/Library/LaunchDaemons/`.
  - **Windows:** Standard user uses zero-admin Windows User Startup (`HKCU\Run`) or Task Scheduler; enterprise mode uses Windows SCM Service (`AgentControlSentry`).
- **Self-Contained Configuration (`daemon.json`):** Configuration and secrets are stored in `~/.agentcontrol/daemon.json` (`0600` permissions on Unix) or `%PROGRAMDATA%\VexaAgentControl\daemon.json`, avoiding process table leaks and supervisor environment variable incompatibilities.
- **Truthful Status Inspection:** `agentcontrol service status` conducts an authentic HTTP handshake against `/api/v1/health`, measuring latency, process PID, policy safe mode status, and Hub authentication. If the process is running manually without a registered OS service, it explicitly reports `DEGRADED (Unmanaged)`.
- **Zero-Trust Identity Separation:** Device keys verify hardware identity (`DeviceVerified`), while human developer identities are attested via OIDC / Hub tokens (`HumanIdentityVerified`). External user spoofing headers (`X-AgentControl-User-Id`) are strictly rejected.

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

> [!NOTE]
> **Installer Elevation & Administrator Permissions:**
> - **Standard User Mode (Default):** `agentcontrol login` handles authentication and service registration with zero administrative permissions. It registers Windows User Logon Startup (`HKCU\Run`) or Task Scheduler without UAC prompts.
> - **Enterprise / System Mode:** Run in an elevated Administrator session with `agentcontrol service install --enterprise` to configure the system-wide SCM service `AgentControlSentry`. Enterprise mode does not require prior user-space enrollment.


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

### Step 1 — Protect Workstation in 1 Command (`agentcontrol protect`)

The recommended standalone developer flow automatically discovers all installed assistants, verifies listener responsiveness, and applies atomic, journaled configuration updates:

```bash
# 1-command protection with transaction journal safety:
agentcontrol protect

# Check verified ports, status, and health:
agentcontrol status
agentcontrol doctor

# Cleanly unprotect all assistants anytime:
agentcontrol unprotect
```

#### Individual Assistant Connection (Alternative)
You can also connect or disconnect assistants selectively:
```bash
agentcontrol connect cursor
agentcontrol connect claude
agentcontrol connect codex
agentcontrol disconnect cursor
```

**What You Achieve:**
- **Transaction Safety:** Mutations are journaled in `~/.agentcontrol/protect_journal.json`. If an error occurs, Agent Control rolls back immediately with zero corrupted configuration files.
- **Port Verification:** The gateway binds and tests the listener before any file writes, ensuring client configs point to the actual active port.
- **Zero-Elevation Governance:** Pristine baseline backups (`.baseline.bak`) and ownership manifests (`~/.agentcontrol/manifests/<target>.manifest.json`). Cleanly revert all changes with `agentcontrol unprotect`.

---

### Step 2 — Route Agent HTTP Traffic Through Proxy

Redirect HTTP/HTTPS requests from custom AI scripts or SDKs through Agent Control by setting standard proxy environment variables:

**Linux / macOS (Bash / Zsh):**
```bash
export HTTP_PROXY=http://127.0.0.1:18080
export HTTPS_PROXY=http://127.0.0.1:18080
export AGENTCONTROL_PROXY_URL=http://127.0.0.1:18080
```

**Windows (PowerShell):**
```powershell
$env:HTTP_PROXY="http://127.0.0.1:18080"
$env:HTTPS_PROXY="http://127.0.0.1:18080"
$env:AGENTCONTROL_PROXY_URL="http://127.0.0.1:18080"
```

**Windows (Command Prompt / CMD):**
```cmd
set HTTP_PROXY=http://127.0.0.1:18080
set HTTPS_PROXY=http://127.0.0.1:18080
set AGENTCONTROL_PROXY_URL=http://127.0.0.1:18080
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
> **One-command protection for all IDEs:** Use `agentcontrol connect --all` to discover and connect **all** detected supported IDEs simultaneously:
> ```bash
> agentcontrol connect --all             # macOS / Linux — connects all detected IDEs in one pass
> agentcontrol.exe connect --all         # Windows
> agentcontrol connect --all --dry-run   # Preview changes without writing to disk
> ```
> To restore every IDE to its original config: `agentcontrol disconnect --all`.

| IDE / Client | Connect Command | LLM Routing & Budgets | MCP Tool Interception | Key Custody / Injection | Disconnect |
|---|---|:---:|:---:|:---:|---|
| **Claude Desktop** *(Verified)* | `agentcontrol connect claude` | ℹ️ *Direct Cloud* | ✅ Full | 🔒 Preserved | `agentcontrol disconnect claude` |
| **Cursor** *(Verified)* | `agentcontrol connect cursor` | ✅ Full | ✅ Full | ✅ Injected (`settings.json`) | `agentcontrol disconnect cursor` |
| **Google Antigravity** *(Verified)* | `agentcontrol connect antigravity` | ✅ Full | ✅ Full | ✅ Injected (`mcp_config.json`) | `agentcontrol disconnect antigravity` |
| **Codex CLI** *(Verified)* | `agentcontrol connect codex` | ✅ Full | ✅ Full | ✅ Injected (`auth.json`) | `agentcontrol disconnect codex` |
| **Claude Code (CLI)** *(Verified)* | `agentcontrol connect claude-code` | ✅ Full | ✅ Full | ✅ Injected (`settings.json`) | `agentcontrol disconnect claude-code` |
| **VS Code (Continue)** *(Verified)* | `agentcontrol connect vscode-continue` | ✅ Full | ✅ Full | ✅ Injected (`config.json`) | `agentcontrol disconnect vscode-continue` |
| **JetBrains IDEs** *(Experimental)* | `agentcontrol connect jetbrains` | ✅ Full | ✅ Full | ✅ Config | `agentcontrol disconnect jetbrains` |
| **Zed** *(Experimental)* | `agentcontrol connect zed` | ✅ Full | ✅ Full | ✅ Config | `agentcontrol disconnect zed` |
| **Cline** *(Experimental)* | `agentcontrol connect cline` | ✅ Full | ✅ Full | ✅ Config | `agentcontrol disconnect cline` |
| **OpenCode** *(Experimental)* | `agentcontrol connect opencode` | ✅ Full | ✅ Full | ✅ Config | `agentcontrol disconnect opencode` |

**macOS / Linux (Bash / Zsh):**
```bash
agentcontrol connect claude       # or claude-code, cursor, antigravity, codex, vscode-continue
agentcontrol status               # inspect active connections and proxy health
```

**Windows (PowerShell / CMD):**
```powershell
agentcontrol.exe connect claude   # or claude-code, cursor, antigravity, codex, vscode-continue
agentcontrol.exe status           # inspect active connections and proxy health
```

> [!IMPORTANT]
> **Restart your IDE** after running `agentcontrol connect <target>`. IDE processes read MCP configuration strictly at application startup.

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

The **ADR Benchmark tab** in the local dashboard (`http://127.0.0.1:18080`) also renders the latest report interactively.

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

### Step 7 — Run Verification Probe & Assert Effective Routing

Execute the automated verification smoke test against your running gateway to verify that proxy interception, DLP redaction, injection defenses, and Control Hub identity correlation are active:

**Linux / macOS (Bash / Zsh):**
```bash
# Basic gateway smoke test
agentcontrol verify --gateway http://127.0.0.1:18080

# With Control Hub identity correlation and desired-state assertion (REQ-VER-004)
agentcontrol verify \
  --gateway http://127.0.0.1:18080 \
  --hub https://console.vexasec.io \
  --user-id $(whoami) \
  --json
```

**Windows (PowerShell):**
```powershell
agentcontrol.exe verify --gateway http://127.0.0.1:18080 --hub https://console.vexasec.io --user-id $env:USERNAME
```

**What You Will See:**
A 5-point verification report confirming:
1. `[PASS]` Gateway Health Pre-flight (`/healthz`)
2. `[PASS]` Safe Tool Execution (`echo` pass-through)
3. `[PASS]` DLP Secret Leakage Redaction (AWS Key simulation redacted)
4. `[PASS]` Prompt Injection Defense (Delimiter extraction blocked)
5. `[PASS]` Control Hub Identity Correlation (Device ID & user verified in Control Hub)

**What You Achieve:**
Proof of compliance that your local workstation is securely wrapped, intercepting traffic, and correlated with your authenticated identity.

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
agentcontrol start --policy agentcontrol-policy.yaml --listen 127.0.0.1:18080
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
