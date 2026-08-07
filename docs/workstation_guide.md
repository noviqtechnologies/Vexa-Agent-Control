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
   - [Step 1 — Launch Observation Proxy & Dashboard](#step-1--launch-observation-proxy--dashboard)
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
curl -fsSL https://vexasec.io/install.sh | bash
agentwall --version
```

### Persistent OS Sentry Daemon & File Locking

Instead of manually running `agentwall start` in terminal, install AgentWall as an always-on background OS daemon with read-only file locks:

```bash
# Install persistent systemd (Linux) or launchd (macOS) service
agentwall service install --hub-url "https://hub.corp.com"

# Check daemon status
agentwall service status
```

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
irm https://vexasec.io/install.ps1 | iex
agentwall.exe --version
```

> **Important — Installer Elevation & Administrator Permissions:**
> - **Enterprise Automated Deployments (Intune / SCCM / GPO / MSI):** Installer packages and GPO scripts execute under **`NT AUTHORITY\SYSTEM`** with full administrative rights. **`agentwall service install` runs automatically without user interaction.**
> - **Manual Script Execution (`install.ps1`):** Running `install.ps1` in a standard PowerShell session installs the binary to `%USERPROFILE%\.local\bin`. **To install the persistent SCM Service (`agentwall service install`), PowerShell must be opened with "Run as Administrator".**
> - **Windows Task Scheduler Background Daemon (Recommended Alternative):** To run the background gateway service & heartbeat loop on system startup without SCM control function errors:
>   ```cmd
>   setx /M DASHBOARD_API_URL "http://localhost:8080"
>   SchTasks /Create /TN "AgentWallSentry" /TR "C:\AgentWall\agentwall\target\debug\agentwall.exe start --listen 127.0.0.1:8080" /SC ONSTART /RU SYSTEM /F
>   SchTasks /Run /TN "AgentWallSentry"
>   ```
> - **Non-Admin Interactive Watcher:** Users without administrator access can run **`agentwall watch --all`** in a standard user terminal.


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

### Step 1 — Launch Observation Proxy & Dashboard

Start the observation-mode shadow proxy listening on `127.0.0.1:8080`. AgentWall runs a **single process** that serves both the proxy (intercepting agent traffic on port `8080`) and the web dashboard UI (accessible in your browser at `http://127.0.0.1:8080`).

```bash
agentwall dev
```

*(Windows PowerShell: `.\agentwall.exe dev`)*

**What You Will See:**
A terminal banner confirming proxy launch. Your default browser opens automatically at `http://127.0.0.1:8080` showing the live traffic dashboard.

**What You Achieve:**
Real-time agent event monitoring is active. All traffic passing through the proxy appears instantly in the dashboard — no configuration needed.

> [!NOTE]
> **Shadow / Observation Mode:** In this mode, AgentWall **observes and logs** all traffic but does **not block** any tool calls. This lets you assess your agents' behavior before enabling enforcement.

> [!TIP]
> **Populating Test Telemetry:** `quickstart_agent.py` is automatically installed alongside the `agentwall` binary into your PATH. If your browser dashboard shows *"No tool calls recorded yet"*, run the test script in a separate terminal to populate all dashboard panels:
> ```bash
> python quickstart_agent.py
> ```

---

### Step 2 — Route Agent HTTP Traffic Through Proxy

Redirect HTTP/HTTPS requests from your AI agents or SDKs through AgentWall by setting standard proxy environment variables:

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
All outgoing agent HTTP API calls (e.g., to OpenAI or Anthropic) are intercepted and recorded in `~/.agentwall/events.db`.

---

### Step 3 — Wrap Stdio Tools & Desktop IDEs

Secure Model Context Protocol (MCP) tool calls and desktop AI applications by wrapping their configuration.

#### Wrap a Stdio MCP Server

> **Prerequisites:** Node.js (`npx` v18+) installed and target directory created.

**Linux / macOS:**
```bash
mkdir -p ~/workspace
agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem ~/workspace
```

**Windows (PowerShell):**
```powershell
New-Item -ItemType Directory -Path "$HOME\workspace" -Force
agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem "$HOME\workspace"
```

> [!TIP]
> If `npx` is not found automatically (common with nvm/brew/fnm on macOS), pass the full path:
> ```bash
> agentwall dev --stdio -- $(which npx) -y @modelcontextprotocol/server-filesystem ~/workspace
> ```

**What You Will See:**
`AgentWall MCP Security Proxy` initialization header in your terminal.

#### Wrap a Desktop IDE

AgentWall automatically patches the MCP configuration file of the target IDE — no manual JSON editing required. Supported targets:

| IDE / Client | Wrap Command |
|---|---|
| Claude Desktop | `agentwall wrap claude` |
| Cursor | `agentwall wrap cursor` |
| VS Code | `agentwall wrap vscode` |
| JetBrains IDEs | `agentwall wrap jetbrains` |
| Zed | `agentwall wrap zed` |
| Cline | `agentwall wrap cline` |
| OpenCode | `agentwall wrap opencode` |
| Antigravity IDE | `agentwall wrap antigravity` |

```bash
agentwall wrap claude      # or cursor, vscode, jetbrains, zed, cline, opencode, antigravity
agentwall status           # inspect active wrappers and proxy health
```

> [!IMPORTANT]
> **Restart your IDE** after running `agentwall wrap <target>`. IDE processes read MCP configuration strictly at application startup.

**What You Achieve:**
MCP tool calls (file manipulation, shell execution, etc.) are proxied and governed by AgentWall. The IDE itself requires no plugin installation.

---

### Step 4 — Auto-Generate Security Policy

After running your agents or IDE tools, generate a YAML security policy derived from the observed traffic. This is a **one-time learning step** — run it after observation, not during.

```bash
agentwall generate-policy --decay-window 30
```

**What You Will See:**
Terminal output displaying a newly generated `policy.yaml` rule set based on recorded events in `~/.agentwall/events.db`.

**What You Achieve:**
A tailored, baseline security policy automatically crafted for your specific agent tools — without manual YAML writing.

> [!TIP]
> Run `agentwall generate-policy --decay-window 7` to weight recent traffic more heavily (7-day window). Use `--decay-window 30` for a broader 30-day baseline.

For complete YAML policy authoring and the v2 schema reference, see → [Common Reference Guide — YAML Policies](common_guide.md#writing-yaml-policies-v2-schema).

---

### Step 5 — Run ADR Security Benchmark

Evaluate how well your policy configuration detects and blocks 303 real-world AI attack tasks across 17 categories:

```bash
agentwall bench --full
```

*(When building from source: `cargo run -- bench --full`)*

The benchmark completes in under 60 seconds and writes a report to `target/benchmark-report.html`:

```bash
open target/benchmark-report.html            # macOS
xdg-open target/benchmark-report.html       # Linux
Start-Process target/benchmark-report.html  # Windows PowerShell
```

The **ADR Benchmark tab** in the local dashboard (`http://127.0.0.1:8080`) also renders the latest report interactively.

For the full benchmark reference (all 17 attack categories and scoring methodology), see → [Common Reference Guide — ADR Security Benchmark](common_guide.md#adr-security-benchmark).

---

### Step 6 — Run MCP Security Scan

Audit your local MCP server definitions and receive a Vexa Security Score (0–100) before deploying to production:

```bash
agentwall scan --path agentwall-policy.yaml
```

**What You Will See:**
A scored security report flagging risky tool definitions, missing parameter constraints, and unsafe path validators.

**What You Achieve:**
A Vexa Security Score you can use as a CI/CD quality gate to prevent insecure MCP server configurations from reaching production.

---

## 4. Safe Mode & Default-Deny Guardrails

AgentWall ships with **15 out-of-the-box safe-mode rules** that are active by default — no policy file required. These rules automatically block the most common dangerous AI agent behaviors:

| Rule Category | Example Detections |
|---|---|
| **Sensitive Path Access** | Blocks reads/writes to `.ssh/`, `.env`, `.aws/credentials`, `/etc/shadow`, `C:\Windows\System32` |
| **Credential File Exfiltration** | Blocks access to SSH private keys, API token files, and certificate stores |
| **Destructive Commands** | Blocks `rm -rf`, `DROP TABLE`, `format c:`, and irreversible file operations |
| **Persistence Mechanism Attempts** | Blocks modifications to startup scripts, cron jobs, and registry run keys |
| **Network Exfiltration Patterns** | Blocks sequential file-read → HTTP-POST patterns indicative of data exfiltration |

To view wrapper status and gateway health:
```bash
agentwall status
```

To enable **enforcing (blocking) mode** after observation:
```bash
agentwall start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
```

For full policy authoring, see → [Common Reference Guide — YAML Policies](common_guide.md#writing-yaml-policies-v2-schema).

---

## 5. Prompt Injection Protection

AgentWall includes **9 active prompt injection scanners** that inspect both inbound tool call parameters and outbound tool response payloads:

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
agentwall start --shadow-mode --log-path audit.log
```

Or use `agentwall dev` (shadow mode is the default for the `dev` subcommand).

### Generate a Risk Delta Report

After agents have run and traffic has been logged:
```bash
agentwall report audit.log --risk
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
| Writing YAML Policies (v2 Schema) | [common_guide.md → YAML Policies](common_guide.md#writing-yaml-policies-v2-schema) |
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
