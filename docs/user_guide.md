# Vexa AgentWall — User Guide

Welcome to the Vexa AgentWall documentation hub. AgentWall is an enterprise-grade, default-deny AI security gateway and firewall for MCP, HTTP, HTTPS, and WebSocket agent traffic.

This page is the top-level navigation hub. Select the guide that matches your deployment profile to get started.

---

## Choose Your Deployment Profile

AgentWall supports three graduated deployment profiles. Pick the one that matches your environment:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                  DEPLOYMENT PROFILES                                    │
├──────────────────────────┬──────────────────────────────┬───────────────────────────────┤
│ Workstation Sidecar      │ Team Control Hub              │ Enterprise Fleet              │
│ Single Binary & Sidecar  │ Docker Compose Stack         │ Kubernetes + Helm Fleet       │
│ Shadow Gateway + Local UI│ Go API + React UI + Postgres │ TLS rustls + SIEM + OIDC SSO  │
└──────────────────────────┴──────────────────────────────┴───────────────────────────────┘
```

---

### 🖥️ [Workstation Sidecar Guide](workstation_guide.md)

> **Best for:** Individual developers securing AI agent tool calls on a local workstation.
> No Docker, no database, no external servers required.

**What you get:**
- Default-deny policy engine with 15 out-of-the-box safe-mode rules
- 9 active prompt injection scanners
- 21 built-in DLP detectors (AWS keys, SSH keys, PII, API tokens)
- Passive shadow AI discovery & Risk Delta Reports
- MCP Security Scoring Engine (`agentwall scan`)
- Local developer web console at `http://127.0.0.1:8080`
- One-command IDE wrapping for Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity IDE
- ADR Security Benchmark (303 tasks across 17 attack categories)

**Quick start:**
```bash
# macOS / Linux / WSL
curl -fsSL https://vexasec.io/install.sh | bash && agentwall dev

# Windows (PowerShell)
irm https://vexasec.io/install.ps1 | iex; .\agentwall.exe dev

# Populate test traffic (if seeing "No tool calls recorded yet")
python quickstart_agent.py
```

→ **[Open Workstation Sidecar Guide](workstation_guide.md)** | **[Open Quickstart Guide](quickstart.md)**

---

### 🏢 [Team Control Hub Guide](team_hub_guide.md)

> **Best for:** DevOps engineers and Engineering leads extending governance across an entire engineering team or staging environment.
> Requires Docker Compose (or Go + Node.js bare-metal).

**What you get (in addition to all Workstation capabilities):**
- Centralized policy push via SSE — hot-swap policies across all gateways without restarts
- OIDC identity binding (Okta, Keycloak, Entra ID, Auth0, Ping)
- Multi-tenant policy sharding (`agent_project_id`, `agent_task_id`)
- Vault & LLM provider API key custody — agents never hold raw keys
- Async HITL approval queue (Slack, Teams, Webhooks)
- Spend caps, token budgets & concurrency limits
- Loop detection & PivotError countermeasures
- Multi-backend SIEM export (Splunk, Datadog, OpenSearch)
- Team management console at `http://localhost:8081`

**Quick start:**
```bash
cd control-plane && docker compose up -d --build
export DASHBOARD_API_URL="http://localhost:8400"
export GATEWAY_SECRET="your-gateway-secret"
agentwall start --listen 127.0.0.1:8080 --centralized --log-path ./team-audit.log
```

→ **[Open Team Control Hub Guide](team_hub_guide.md)**

---

### ☁️ [Enterprise Fleet Guide](enterprise_guide.md)

> **Best for:** Platform engineers and Security architects deploying high-availability, cloud-native gateway fleets on Kubernetes.
> Requires Kubernetes v1.26+, Helm v3+, and a domain TLS certificate.

**What you get (in addition to all Team Hub capabilities):**
- Hardened Agent Container Runtime (HAR) — <100 MB Distroless/Alpine OCI sidecar
- Hardened WebSocket egress tunneling (<5ms latency)
- Real-time threat intelligence feed (live Vexa AI Malware signatures via SSE)
- Zero-knowledge Customer-Managed Key (CMK) AES-256-GCM SIEM encryption
- Pure-Rust TLS termination powered by `rustls`
- Fleet-wide telemetry & Kubernetes monitoring

**Quick start:**
```bash
kubectl create namespace agentwall-system
kubectl create secret tls agentwall-tls --cert=tls.crt --key=tls.key -n agentwall-system
helm install agentwall ./chart --namespace agentwall-system \
  --set gateway.tls.enabled=true \
  --set gateway.oidcIssuer="https://auth.corp.com/oauth2/default"
```

→ **[Open Enterprise Fleet Guide](enterprise_guide.md)**

---

## Capabilities by Deployment Profile

| Capability | Workstation Sidecar | Team Control Hub | Enterprise Fleet |
|---|:---:|:---:|:---:|
| Default-Deny Policy Engine | ✓ | ✓ | ✓ |
| 15 Out-of-the-Box Safe Rules | ✓ | ✓ | ✓ |
| 9 Prompt Injection Scanners | ✓ | ✓ | ✓ |
| 21-Pattern Dual-Pass DLP | ✓ | ✓ | ✓ |
| Passive Shadow AI Discovery | ✓ | ✓ | ✓ |
| MCP Security Scoring Engine | ✓ | ✓ | ✓ |
| IDE Auto-Wrapping Engine | ✓ | ✓ | ✓ |
| Hardware PKI Device Enrollment | ✓ | ✓ | ✓ |
| Persistent OS Sentry Daemon | ✓ | ✓ | ✓ |
| ADR Security Benchmark | ✓ | ✓ | ✓ |
| Tamper-Evident HMAC Logging | ✓ | ✓ | ✓ |
| Centralized Policy Push (SSE) | — | ✓ | ✓ |
| [Central Device Governance](team_hub_guide.md#6-central-device-governance--fleet-health) | — | ✓ | ✓ |
| OIDC Identity Binding | — | ✓ | ✓ |
| Project & Task Policy Sharding | — | ✓ | ✓ |
| Vault & API Key Custody | — | ✓ | ✓ |
| Async HITL Webhook Queue | — | ✓ | ✓ |
| Spend Caps & Token Ledger | — | ✓ | ✓ |
| Loop Detection & PivotError | — | ✓ | ✓ |
| Hardened Container Runtime (HAR) | — | — | ✓ |
| WebSocket Egress Tunneling | — | — | ✓ |
| Real-Time Threat Intel Feed | — | — | ✓ |
| Zero-Knowledge CMK Encryption | — | — | ✓ |
| Pure-Rust TLS Termination | — | — | ✓ |

---

## Shared Reference Sections

These technical reference topics apply across all deployment profiles and are maintained in the [Common Reference Guide](common_guide.md):

| Reference Topic | Description |
|---|---|
| [YAML Policy v2 Schema](common_guide.md#1-writing-yaml-policies-v2-schema) | Complete v2 schema reference with annotated example policy |
| [DLP Configuration](common_guide.md#2-configuring-data-loss-prevention-dlp) | All 21 built-in detectors, custom patterns, entropy scanning |
| [OIDC Identity Binding](common_guide.md#3-setting-up-oidc-identity-binding) | IdP setup, JWT validation, short-lived credential CLI |
| [Control Hub Connectivity](common_guide.md#4-connecting-to-the-control-hub) | SSE event stream, API key custody, telemetry uploads |
| [Audit Log Verification](common_guide.md#5-verifying-audit-logs) | HMAC chain verification, session reports, SIEM export |
| [Sequence Rules (ADR)](common_guide.md#6-stateful-sequence-rules-adr-framework) | Multi-step attack detection engine and rule authoring |
| [ADR Benchmark](common_guide.md#7-adr-security-benchmark) | 303-task benchmark suite, scoring, dashboard integration |
| [Environment Variables](common_guide.md#8-environment-variables) | Complete environment variable reference |
| [Troubleshooting](common_guide.md#10-troubleshooting-common-issues) | PATH errors, YAML validation, OIDC failures, IDE wrap issues |

---

## Additional Documentation

| Document | Description |
|---|---|
| [quickstart.md](quickstart.md) | Step-by-step quickstart for local MCP servers, Claude Desktop, and Cursor |
| [oidc_identity_binding.md](oidc_identity_binding.md) | Provider-specific OIDC setup (Okta, Keycloak, Entra ID, Auth0, Cognito, Ping) |
| [adr_benchmark.md](adr_benchmark.md) | Full ADR benchmark reference (all 17 attack categories and scoring methodology) |
| [agentwall_architecture.md](agentwall_architecture.md) | Detailed system architecture, 6-pass pipeline, and component interaction flows |
| [configuration.md](configuration.md) | Deep-dive policy schema, DLP regex, spend caps, and environment variables |
| [deployment.md](deployment.md) | Platform-specific installation reference (macOS, Linux, Windows, Docker, K8s, HAR) |
| [integrations.md](integrations.md) | IDE wrappers, stdio proxies, Vault adapters, and SIEM exporters |
| [comprehensive_guide.md](comprehensive_guide.md) | Command-line walkthroughs and scenario tutorials |

---

## Table of Contents

1. [Getting Started for Each Deployment Profile](#1-getting-started-for-each-deployment-profile)
   - [Workstation Sidecar](#workstation-sidecar)
   - [Team Control Hub](#team-control-hub)
   - [Enterprise Fleet](#enterprise-fleet)
2. [Writing YAML Policies (v2 Schema)](#2-writing-yaml-policies-v2-schema)
   - [v2 Policy Architecture](#v2-policy-architecture)
   - [Complete v2 Schema Reference & Example](#complete-v2-schema-reference--example)
   - [Policy Rules & Parameter Validation](#policy-rules--parameter-validation)
3. [Configuring Data Loss Prevention (DLP)](#3-configuring-data-loss-prevention-dlp)
   - [Built-In Regex Detectors](#built-in-regex-detectors)
   - [Custom Pattern Definitions](#custom-pattern-definitions)
   - [Deep Scanning & Entropy Analysis](#deep-scanning--entropy-analysis)
   - [Tool Response Secret Scanning](#tool-response-secret-scanning)
4. [Setting Up OIDC Identity Binding](#4-setting-up-oidc-identity-binding)
   - [IdP Configuration](#idp-configuration)
   - [JWT Validation & Scope Matching](#jwt-validation--scope-matching)
   - [Agent Short-Lived Credential CLI](#agent-short-lived-credential-cli)
5. [Connecting to the Control Hub](#5-connecting-to-the-control-hub)
   - [Hub Architecture & API Specifications](#hub-architecture--api-specifications)
   - [Real-Time SSE Event Stream](#real-time-sse-event-stream)
   - [Provider API Key Custody & Injection](#provider-api-key-custody--injection)
   - [Telemetry Batch Uploads](#telemetry-batch-uploads)
6. [Verifying Audit Logs](#6-verifying-audit-logs)
   - [HMAC Cryptographic Hash Chaining](#hmac-cryptographic-hash-chaining)
   - [Log Integrity Verification](#log-integrity-verification)
   - [Session Reports & SIEM Export](#session-reports--siem-export)
7. [Troubleshooting Common Issues](#7-troubleshooting-common-issues)
   - [Gateway Startup & YAML Validation Errors](#gateway-startup--yaml-validation-errors)
   - [Tool Call Denials & Safe Mode Interceptions](#tool-call-denials--safe-mode-interceptions)
   - [OIDC & JWT Authorization Failures](#oidc--jwt-authorization-failures)
   - [Control Hub Synchronization Issues](#control-hub-synchronization-issues)
   - [IDE Wrapping & Watch Daemon Diagnostics](#ide-wrapping--watch-daemon-diagnostics)
   - [Spend Limit & Loop Detection Triggers](#spend-limit--loop-detection-triggers)
8. [Stateful Sequence Rules (ADR Framework)](#8-stateful-sequence-rules-adr-framework)
   - [How the Sequence Engine Works](#how-the-sequence-engine-works)
   - [Writing Sequence Rules](#writing-sequence-rules)
   - [Sequence Rule Violations in Audit Logs](#sequence-rule-violations-in-audit-logs)
9. [ADR Security Benchmark](#9-adr-security-benchmark)
   - [Running the Benchmark](#running-the-benchmark)
   - [Reading the Report](#reading-the-report)
   - [Dashboard Integration](#dashboard-integration)
10. [War Plan Strategic Features (v2.0)](#10-war-plan-strategic-features-v20)
    - [Passive Shadow AI Risk Delta Reports](#passive-shadow-ai-risk-delta-reports)
    - [Vexa Security Scanning (vexa-scan)](#vexa-security-scanning-vexa-scan)
    - [WebSocket Egress Tunneling](#websocket-egress-tunneling)
    - [Human-in-the-Loop (HITL) Webhooks](#human-in-the-loop-hitl-webhooks)
    - [Hardened Agent Containers (HAR)](#hardened-agent-containers-har)

---

## 1. Getting Started for Each Deployment Profile

AgentWall supports three graduated deployment profiles designed to fit seamlessly into any stage of development and enterprise rollout.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                  DEPLOYMENT PROFILES                                    │
├──────────────────────────┬──────────────────────────────┬───────────────────────────────┤
│ Workstation Sidecar      │ Team Control Hub              │ Enterprise Fleet              │
│ Single Binary & Sidecar  │ Docker Compose Stack         │ Kubernetes + Helm Fleet       │
│ Shadow Gateway + Local UI│ Go API + React UI + Postgres │ TLS rustls + SIEM + OIDC SSO  │
└──────────────────────────┴──────────────────────────────┴───────────────────────────────┘
```

### Workstation Sidecar

The Workstation Sidecar profile provides local observation, automatic policy generation, and Safe Mode protection without requiring external servers, Docker, or database setups.

#### Prerequisites
- **Operating System:** Linux, macOS, or Windows (WSL / PowerShell).
- **Network / Utilities:** `curl` and `sh` installed for binary download.
- **Node.js Environment (Optional):** Node.js (`node` & `npx` v18+) required if proxying stdio MCP servers like `@modelcontextprotocol/server-filesystem`.
- **Permissions:** Execution permission to write to `/usr/local/bin` (or user `$PATH`).

#### Step-by-Step Installation
* **macOS / Linux / WSL:**
  ```bash
  curl -fsSL https://vexasec.io/install.sh | bash
  agentwall --version
  ```
  > **Permanent PATH Configuration (Set Once Across Terminals):**
  > - **Bash (Linux/WSL):** `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`
  > - **Zsh (macOS):** `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc`
  > - **Fish:** `fish_add_path ~/.local/bin`

* **Windows (PowerShell / CMD / Git Bash):**
  ```powershell
  irm https://vexasec.io/install.ps1 | iex
  agentwall.exe --version
  ```
  > **Important — Installer Elevation & Administrator Permissions:**
  > - **Enterprise Automated Deployments (Intune / SCCM / GPO / MSI):** Installer packages execute under **`NT AUTHORITY\SYSTEM`** with administrative rights, allowing **`agentwall service install` to complete automatically.**
  > - **Manual PowerShell Execution:** Running `install.ps1` in a standard session installs the binary. **Installing the SCM Service (`agentwall service install`) requires launching PowerShell with "Run as Administrator".**
  > - **Windows Task Scheduler Background Daemon:** To run the background gateway and heartbeat daemon automatically on boot:
  >   `SchTasks /Create /TN "AgentWallSentry" /TR "C:\AgentWall\agentwall\target\debug\agentwall.exe start --listen 127.0.0.1:8080" /SC ONSTART /RU SYSTEM /F`
  > - **Non-Admin Execution:** Without administrative privileges, run **`agentwall watch --all`** in a standard user terminal to run the Sentry watcher daemon interactively.

  > **Permanent PATH Configuration (Set Once Across Terminals):**
  > - **PowerShell (User Path):**
  >   `[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.local\bin", "User")`
  > - **Command Prompt (CMD):**
  >   `setx PATH "%PATH%;%USERPROFILE%\.local\bin"`
  > - **Git Bash / MSYS2:**
  >   `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile && source ~/.bash_profile`

#### Post-Installation Activities & Verification

Follow these simplified steps to activate observation mode, wrap agent traffic, and auto-generate governance policies:

##### Step 1: Launch Observation Proxy & Dashboard
Launch `agentwall dev` to start an observation-mode shadow proxy listening on `127.0.0.1:8080`:
```bash
agentwall dev
```
* **Prerequisites:** `agentwall` installed and added to PATH (or run as `.\agentwall.exe dev` in PowerShell).
* **What You Will See:** A terminal banner confirming proxy launch, and your default web browser automatically opens `http://127.0.0.1:8080`.
* **What You Achieve:** Live proxy monitoring is active, displaying real-time agent events on your local dashboard.

---

##### Step 2: Route Agent HTTP Traffic Through Proxy
Redirect HTTP/HTTPS requests from your AI agents or SDKs through AgentWall:

* **Linux / macOS (Bash / Zsh):**
  ```bash
  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080
  export AGENTWALL_PROXY_URL=http://127.0.0.1:8080
  ```
* **Windows (PowerShell):**
  ```powershell
  $env:HTTP_PROXY="http://127.0.0.1:8080"
  $env:HTTPS_PROXY="http://127.0.0.1:8080"
  $env:AGENTWALL_PROXY_URL="http://127.0.0.1:8080"
  ```
* **Windows (Command Prompt / CMD):**
  ```cmd
  set HTTP_PROXY=http://127.0.0.1:8080
  set HTTPS_PROXY=http://127.0.0.1:8080
  set AGENTWALL_PROXY_URL=http://127.0.0.1:8080
  ```
* **What You Will See:** Silent confirmation in the terminal; live HTTP requests from Python/Node AI scripts immediately appear in the browser dashboard (`http://127.0.0.1:8080`).
* **What You Achieve:** All outgoing agent HTTP API calls (e.g., to OpenAI or Anthropic) are intercepted and recorded in `~/.agentwall/events.db`.

---

##### Step 3: Wrap Stdio Tools & Desktop IDEs
Secure Model Context Protocol (MCP) tool calls and desktop AI applications (e.g., Claude Desktop, Cursor):

* **Wrap Stdio MCP Server:**
  > **Prerequisites:** Node.js (`npx` v18+) installed and target directory created.
  * **Linux / macOS:**
    ```bash
    mkdir -p ~/workspace
    agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem ~/workspace
    ```
  * **Windows (PowerShell):**
    ```powershell
    New-Item -ItemType Directory -Path "$HOME\workspace" -Force
    agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem "$HOME\workspace"
    ```
* **Wrap Desktop IDE & Check Health:**
  ```bash
  agentwall wrap claude
  agentwall status
  ```
* **What You Will See:**
  * For stdio wrapping: `AgentWall MCP Security Proxy` initialization header in your terminal.
  * For `agentwall wrap claude`: Terminal confirmation that client configuration files (e.g., `claude_desktop_config.json`) were updated.
  * For `agentwall status`: Diagnostic table listing active wrappers and proxy health.
* **What You Achieve:** MCP tool calls (like file manipulation or shell execution) are proxied and governed by AgentWall.

---

##### Step 4: Auto-Generate Security Policy
After running your agents or IDE tools, generate a YAML security policy derived from observed traffic:
```bash
agentwall generate-policy --decay-window 30
```
* **What You Will See:** Terminal output displaying a newly generated `policy.yaml` rule set based on recorded events in `~/.agentwall/events.db`.
* **What You Achieve:** A tailored, baseline security policy automatically crafted for your specific agent tools without manual YAML writing.

---

### Team Control Hub

The Team Control Hub profile introduces the self-hosted **Control Hub** (React Web Dashboard + Go REST API + PostgreSQL Database) running alongside local or shared gateway instances.

#### Prerequisites

##### Option A: Standard Control Hub Deployment (Docker Compose — Recommended)
1. **Control Hub Server Host:**
   - **Docker Engine / Docker Desktop (v24.0+):** Must be installed and **actively running** (daemon active).
   - **Docker Compose (v2.20+):** Required to orchestrate PostgreSQL, API, and UI containers.
   - **Available Network Ports:** `8081` (Control Hub UI), `8400` (Control Hub API), `5433` (PostgreSQL DB).
2. **Gateway Host(s) / Developer Workstations:**
   - Installed `agentwall` binary (`curl -fsSL https://vexasec.io/install.sh | bash` on Linux/macOS or `irm https://vexasec.io/install.ps1 | iex` on Windows).
   - Direct network connectivity to the Control Hub server on port `8400`.

##### Option B: Native / Non-Docker Local Deployment (Bare-Metal Binaries)
If Docker is not running or available on your local environment:
1. **PostgreSQL Server (v16+):** Running locally (e.g., port `5433` or `5432`) with database `agentwall` created and schema migrations executed from `control-plane/db/migrations/`.
2. **Control Hub API Binary (`dashboard-api`):** Compiled or run via Go 1.21+ (`go run ./cmd/server`) with `DATABASE_URL` pointing to PostgreSQL.
3. **Control Hub UI (`frontend`):** Built or served via Node.js (v18+) development server (`npm run dev` in `control-plane/ui`).


#### Step-by-Step Installation
1. **Deploy the Control Hub Stack via Docker Compose:**
   Navigate to the `control-plane` directory and build the services:
   ```bash
   cd control-plane
   docker compose up -d --build
   ```
   This provisions:
   - **Control Hub UI:** `http://localhost:8081`
   - **Control Hub API:** `http://localhost:8400` (REST API at `/api/v1`)

2. **Start Gateway Instances Connected to the Control Hub:**
   Configure shared bearer secrets and start gateway instances in centralized mode:

   > [!IMPORTANT]
   > **Long-Running Foreground Process:** `agentwall start` runs in the foreground. Keep this terminal window open while the gateway is active. Do not run `curl` or `verify-log` commands in this same window.
   >
   > **Proxy Environment Warning:** When running `docker compose up -d` for Step 1, ensure `HTTP_PROXY` and `HTTPS_PROXY` are **not** set in that terminal session, as Docker requires direct internet access to download base images.

   * **Linux / macOS (Bash / Zsh):**
     ```bash
     export DASHBOARD_API_URL="http://localhost:8400"
     export POLICY_READ_SECRET="local-dev-policy-read-secret"
     export GATEWAY_SECRET="local-dev-shared-secret-change-me"

     agentwall start \
       --listen 127.0.0.1:8080 \
       --centralized \
       --log-path ./team-audit.log
     ```
   * **Windows (PowerShell):**
     ```powershell
     $env:DASHBOARD_API_URL="http://localhost:8400"
     $env:POLICY_READ_SECRET="local-dev-policy-read-secret"
     $env:GATEWAY_SECRET="local-dev-shared-secret-change-me"

     .\agentwall.exe start `
       --listen 127.0.0.1:8080 `
       --centralized `
       --log-path .\team-audit.log
     ```
   The gateway will bootstrap its policy state directly from PostgreSQL via the Control Hub API and maintain a live SSE connection (`GET /api/v1/policy/subscribe`) for zero-downtime policy hot-reloading.

#### Post-Installation Activities & Verification

Follow these steps to verify your Control Hub deployment and centralized team gateway:

##### Step 1: Verify Control Hub API Backend Health
Check that the Control Hub API service is running and accessible:
```bash
curl -i http://localhost:8400/healthz
```
* **Prerequisites:** Control Hub stack launched via Docker Compose (`docker compose up -d`).
* **What You Will See:** HTTP `200 OK` response with JSON payload `{"status":"ok"}`.
* **What You Achieve:** Confirms the centralized REST API and PostgreSQL database backend are operational.

---

##### Step 2: Access & Inspect Team Dashboard
Open `http://localhost:8081` in your web browser.

* **Prerequisites:** Control Hub UI service running on port `8081`.
* **Default Dashboard Credentials:**
  - **Local Docker Compose (DEV_MODE):** Email/Username: `admin` | Password: `admin` (or any string).
  - **Production Mode:** Email/Username: `admin` | Password: `<Bootstrap Token>` (found via `docker compose logs dashboard-api | grep "Bootstrap Token"`).
* **How to Populate Live Dashboard Data:**
  - Connect your centralized gateway (`DASHBOARD_API_URL="http://localhost:8400"` and `GATEWAY_SECRET="local-dev-shared-secret-change-me"`).
  - Wrap stdio MCP tools (`agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem "$HOME"`).
  - Or route agent HTTP traffic through `127.0.0.1:8080` (`export HTTP_PROXY=http://127.0.0.1:8080`).
* **What You Will See:** The web dashboard displaying active gateways, real-time event telemetry stream, threat heatmaps, and active policy rules.
* **What You Achieve:** Provides complete visual monitoring and team policy administration.

---

##### Step 3: Verify Gateway Policy Bootstrap & Hot-Reloading
Inspect stdout logs from your running `agentwall start --centralized` gateway instance in **Terminal 1**.
* **What You Will See:** Gateway output log lines:
  ```text
  [INFO] Policy loaded successfully from Control Hub
  [INFO] SSE event subscription connected to http://localhost:8400/api/v1/policy/subscribe
  ```
* **What You Achieve:** Confirms the gateway is connected to the Control Hub and will receive instant zero-downtime policy hot-reloads when team policies change.

---

##### Step 4: Generate MCP Traffic & Cryptographically Verify Audit Log Integrity
Validate the tamper-evident cryptographic hash chain of the team audit log:

> [!NOTE]
> **Multi-Terminal Workflow:**
> 1. **Terminal 1:** Keep the `agentwall start` gateway server running.
> 2. **Terminal 2 (New Window):** Send MCP tool call traffic through the proxy to populate the audit log.
>
>    > **What Generates Audit Log Entries?** The audit log exclusively records **MCP `tools/call` JSON-RPC decisions** (allow, deny, rate-limit). Plain HTTP proxy requests (e.g. `curl --proxy`) establish a session and are tracked, but do **not** create audit log entries on their own. Route traffic from an actual AI agent or SDK (e.g. Python OpenAI SDK, Node.js Anthropic SDK) through the proxy to generate audit events.
>    >
>    > **Centralized Mode Auth Requirement:** All proxy requests require an `Authorization` header to identify the agent session. Any non-empty value is accepted as a session key when OIDC is not configured.
>
>    **Quick Connectivity Test (verifies session start, not audit):**
>    - **Linux/macOS:**
>      ```bash
>      curl --proxy http://127.0.0.1:8080 \
>           -H "Authorization: Bearer test-agent-session-1" \
>           http://localhost:8400/healthz
>      ```
>    - **Windows (PowerShell):**
>      ```powershell
>      curl.exe --proxy http://127.0.0.1:8080 `
>               -H "Authorization: Bearer test-agent-session-1" `
>               http://localhost:8400/healthz
>      ```
>
>    **Send an MCP Tool Call Directly to the Gateway (generates audit entries):**
>    Post a JSON-RPC `tools/call` request **directly to the gateway** on port `8080`. The gateway evaluates the policy and writes an audit entry before forwarding upstream.
>    - **Linux/macOS:**
>      ```bash
>      curl -X POST http://127.0.0.1:8080 \
>           -H "Authorization: Bearer test-agent-session-1" \
>           -H "Content-Type: application/json" \
>           -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}'
>      ```
>    - **Windows (PowerShell):**
>      ```powershell
>      curl.exe -X POST http://127.0.0.1:8080 `
>               -H "Authorization: Bearer test-agent-session-1" `
>               -H "Content-Type: application/json" `
>               -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/test.txt\"}}}'
>      ```
>    > The gateway will evaluate the policy, write a cryptographic audit entry, then attempt to forward to the upstream MCP server. An upstream connection error is expected if no MCP server is running — the audit log entry is still written.
>
> 3. **Terminal 2:** After agent traffic has flowed through the proxy, run the log verification command:
>    - **Linux/macOS:** `agentwall verify-log ./team-audit.log`
>    - **Windows:** `.\agentwall.exe verify-log .\team-audit.log`
>
> *(Note: Running `verify-log` on an empty log file before any MCP tool call traffic has passed through the gateway will report `log file contains no audit entries`).*

```bash
agentwall verify-log team-audit.log
```
* **Prerequisites:** Audit log file (`team-audit.log`) generated by active gateway sessions.
* **What You Will See:** Terminal verification report: `Audit log verification complete: Hash chain intact. 0 tampered entries.`
* **What You Achieve:** Guarantees cryptographic audit log compliance and tamper evidence.

---

### Enterprise Fleet

The Enterprise Fleet profile deploys AgentWall as a high-availability, cloud-native gateway fleet on Kubernetes, featuring memory-safe TLS (`rustls`), enterprise OIDC SSO, direct SIEM audit streaming, and zero-downtime policy distribution.

#### Production Prerequisites

1. **Target Kubernetes Cluster (Target Infrastructure):**
   - Kubernetes cluster v1.26+ (AWS EKS, GCP GKE, Azure AKS, or On-Premise K8s).
   - Ingress controller / Load Balancer configured for external TLS traffic.
   - StorageClass available for persistent database storage (if deploying embedded PostgreSQL).

2. **Admin Workstation / CI/CD Deployment Host:**
   - `helm` CLI v3+ installed.
   - `kubectl` CLI installed and configured with `cluster-admin` context permissions for the target cluster.

3. **Security & Cryptography Assets:**
   - Domain TLS Certificate (`tls.crt`) and matching private key (`tls.key`) in PEM format.

4. **Enterprise Identity & Audit Services (External Integrations):**
   - **OIDC Provider:** Keycloak, Okta, Microsoft Entra ID (Azure AD), Auth0, or PingIdentity configured with an OIDC Discovery URL (`.well-known/openid-configuration`).
   - **SIEM Collector (Optional):** Splunk HEC, Datadog HTTP Intake, or OpenSearch endpoint and authentication token.

#### Step-by-Step Installation

1. **Create K8s Namespace & Secrets for TLS:**
   Create a Kubernetes secret containing your TLS certificate and key in the target namespace:
   ```bash
   kubectl create namespace agentwall-system
   kubectl create secret tls agentwall-tls \
     --cert=/etc/certs/tls.crt \
     --key=/etc/certs/tls.key \
     -n agentwall-system
   ```

2. **Deploy AgentWall Stack via Helm:**
   Deploy the AgentWall stack using the official Helm chart:
   ```bash
   helm install agentwall ./chart \
     --namespace agentwall-system \
     --set gateway.tls.enabled=true \
     --set gateway.tls.secretName="agentwall-tls" \
     --set gateway.oidcIssuer="https://auth.corp.com/oauth2/default" \
     --set gateway.siem.backend="splunk" \
     --set gateway.siem.endpoint="https://splunk.corp.com:8088/services/collector/event" \
     --set gateway.siem.token="${SPLUNK_HEC_TOKEN}" \
     --set dashboardApi.enabled=true \
     --set dashboardDb.enabled=true \
     --set dashboardFrontend.enabled=true
   ```

#### Post-Installation Activities & Verification

Follow these steps to verify your enterprise production deployment:

##### Step 1: Verify Kubernetes Workload Health
Confirm all gateway pods, control plane API, database, and frontend deployments are running:
```bash
kubectl get pods -n agentwall-system -o wide
```
* **Prerequisites:** Helm deployment completed in the `agentwall-system` namespace.
* **What You Will See:** Pod status table listing all deployments as `Running` and `1/1 Ready`.
* **What You Achieve:** Confirms high-availability gateway pods and infrastructure services are healthy.

---

##### Step 2: Inspect Gateway Container Logs
Inspect gateway logs for clean startup and enterprise service connections:
```bash
kubectl logs -n agentwall-system -l app.kubernetes.io/component=gateway --tail=100
```
* **What You Will See:** Clean startup log stream showing successful TLS certificate binding, OIDC provider discovery, and SIEM HTTP intake connection.
* **What You Achieve:** Validates cryptographic identity integration, secure TLS listener setup, and SIEM telemetry streaming.

---

##### Step 3: Execute Automated Policy Smoke Test
Run the CLI policy test suite against the live cluster ingress endpoint:
```bash
agentwall test --policy agentwall-policy.yaml --gateway https://agentwall.corp.com
```
* **Prerequisites:** `agentwall` CLI installed and cluster ingress reachable at `https://agentwall.corp.com`.
* **What You Will See:** Terminal test report summarizing passed assertions and policy enforcement checks.
* **What You Achieve:** End-to-end empirical verification of governance policy enforcement across the active cloud gateway fleet.

---

##### Step 4: Verify Enterprise SIEM & OIDC Audit Telemetry
Check your enterprise SIEM dashboard (e.g., Splunk, Datadog) and OIDC Provider audit logs.
* **What You Will See:** Real-time audit events indexed in your SIEM portal (e.g. index `security_events`) with valid OIDC subject claim bindings.
* **What You Achieve:** Guarantees enterprise compliance reporting, automated SIEM alert triggers, and identity-bound audit trails.

---

## 2. Writing YAML Policies (v2 Schema)

AgentWall policies use strict, explicit YAML configuration files conforming to the **v2 schema**. AgentWall operates on a **default-deny** model: any tool call, parameter value, or LLM prompt not explicitly allowed is blocked.

### v2 Policy Architecture

The v2 policy schema organizes security controls into distinct sections:
- `identity_binding`: IdP discovery and claim mappings
- `policy_bindings`: Role/group mapping to policy rulesets
- `tools`: Tool call allowlists, parameter constraints, structural validators, and JSON schemas
- `dlp`: Scannable tool definitions and DLP regex patterns
- `spend`: Session token budgets and concurrency limits
- `loop_detection`: Thresholds and actions for agent loop containment
- `audit`: Local file output and SIEM export endpoints

---

### Complete v2 Schema Reference & Example

Below is a complete reference policy (`agentwall-policy.yaml`) demonstrating all v2 schema options:

```yaml
version: 2
default_action: deny

# 1. Identity & OIDC Binding
identity_binding:
  oidc_discovery_url: "https://auth.corp.com/.well-known/openid-configuration"
  allowed_audiences: ["agentwall-gateway-prod"]
  group_claim: "groups"

# 2. Policy Bindings (Group & Subject Mappings)
policy_bindings:
  - group: "secops-team"
    policy: "admin-unrestricted"
  - group: "dev-team"
    policy: "developer-standard"
  - sub: "ci-agent@corp.com"
    policy: "ci-restricted"

# 3. Tool Rules & Parameter Validation
tools:
  - name: "read_file"
    action: allow
    credential_scope: ["file:read"]
    parameters:
      - name: "path"
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - no_sensitive_paths
        regex: "^/home/[a-z]+/projects/.*"
        deny_patterns: ["\\.ssh", "\\.env", "\\.aws", "id_rsa"]

  - name: "write_file"
    action: allow
    credential_scope: ["file:write"]
    parameters:
      - name: "path"
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - no_sensitive_paths
      - name: "content"
        type: string
        required: true
        max_length: 1048576

  - name: "configure_settings"
    action: allow
    credential_scope: ["settings:write"]
    parameters:
      - name: "options"
        type: object
        required: true
        schema:
          type: object
          properties:
            theme:
              type: string
              pattern: "^(dark|light)$"
            retries:
              type: integer
              minimum: 0
              maximum: 5
          required: ["theme"]

# 4. Data Loss Prevention (DLP)
dlp:
  scannable_tools: ["read_file", "write_file", "execute_command"]
  safe_tools: ["list_directory"]
  patterns:
    - name: "aws_access_key"
      regex: "AKIA[0-9A-Z]{16}"
      action: block
    - name: "credit_card"
      regex: "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
      action: redact
    - name: "email_address"
      regex: "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}"
      action: warn

# 5. Spend Limits & Circuit Breakers
spend:
  max_tokens_per_session: 100000
  max_concurrent_sessions: 10

# 6. Loop Detection & Cycle Prevention
loop_detection:
  threshold: 3
  action: PivotError

# 7. Audit & SIEM Export
audit:
  log_file: "/var/log/agentwall/audit.jsonl"
  siem_export:
    type: "splunk_hec"
    endpoint: "https://splunk.corp.com:8088/services/collector/event"
    token: "${SPLUNK_HEC_TOKEN}"
    index: "security_events"
```

---

### Policy Rules & Parameter Validation

#### Parameter Types
Parameters support `string`, `number`, `integer`, `boolean`, and `object`.

#### Structural Validators
AgentWall provides built-in structural validators:
- `path_traversal`: Detects and blocks directory traversal attempts (e.g. `../`, `..\\`, `%2e%2e/`).
- `no_sensitive_paths`: Blocks access to sensitive system paths (`/etc/shadow`, `C:\Windows\System32`, `.ssh`, `.env`, `.aws/credentials`).

#### JSON Schema Validation
For complex object parameters, supply standard JSON Schema contracts under the `schema:` property. The gateway enforces object properties, types, enums, min/max bounds, and required keys.

---

## 3. Configuring Data Loss Prevention (DLP)

AgentWall includes an inline DLP engine that scans MCP tool parameters, tool response payloads, and outbound LLM prompts for sensitive credentials, keys, and PII.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                DLP SCANNING PIPELINE                                    │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│ Payload ──► 3-Pass Base64 Decode ──► 21 Built-in Regexes ──► Entropy (>4.5) ──► Action  │
│                                                                                 (Block/ │
│                                                                                 Redact) │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

### Built-In Regex Detectors

AgentWall ships with **21 built-in regex detectors**:

| Pattern Name | Description | Default Action |
|---|---|---|
| `aws_access_key` | AWS Access Key ID (`AKIA...`) | Block |
| `aws_secret_key` | AWS Secret Access Key | Block |
| `github_pat` | GitHub Personal Access Token (`ghp_...`, `github_pat_...`) | Block |
| `openai_api_key` | OpenAI API Key (`sk-...`) | Block |
| `anthropic_api_key` | Anthropic API Key (`sk-ant-...`) | Block |
| `stripe_live_key` | Stripe Live Secret Key (`sk_live_...`) | Block |
| `ssh_private_key` | PEM / OpenSSH Private Key Block | Block |
| `azure_storage_key` | Azure Storage Account Key | Block |
| `gcp_api_key` | Google Cloud API Key (`AIza...`) | Block |
| `slack_bot_token` | Slack Bot Token (`xoxb-...`) | Block |
| `sendgrid_api_key` | SendGrid API Key (`SG....`) | Block |
| `database_uri` | Connection String (PostgreSQL, MongoDB, Redis) | Redact |
| `credit_card` | Luhn-validated Credit Card Numbers | Redact |
| `us_ssn` | US Social Security Number (`XXX-XX-XXXX`) | Redact |
| `uae_emirates_id` | UAE Emirates ID (`784-XXXX-XXXXXXX-X`) | Redact |
| `email_address` | Standard Email Address | Warn |

---

### Custom Pattern Definitions

Extend DLP capabilities by specifying custom patterns under the `dlp.patterns` block in your policy:

```yaml
dlp:
  scannable_tools: ["read_file", "write_file", "execute_command"]
  patterns:
    - name: "internal_employee_id"
      regex: "EMP-[0-9]{6}-[A-Z]{2}"
      action: block
    - name: "custom_bearer_token"
      regex: "Bearer eyJ[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+"
      action: redact
```

---

### Deep Scanning & Entropy Analysis

In addition to regex patterns, AgentWall performs deep heuristic inspection:
1. **Recursive Base64 Decoding:** Automatically decodes Base64 encoded payload segments up to 3 layers deep before applying DLP scanners.
2. **Shannon Entropy Analysis:** Flags high-entropy random strings (entropy > 4.5 bits/char on strings longer than 32 characters), identifying obfuscated secret keys.
3. **BIP-39 Mnemonic Validation:** Scans text payloads for 12/24-word cryptocurrency seed phrase combinations.

---

### Tool Response Secret Scanning

AgentWall can scan and redact secret leakage contained within incoming tool response payloads before returning them to the agent.

Enable response scanning via CLI flags when launching the gateway or wrapper:
```bash
agentwall start \
  --policy policy.yaml \
  --scan-responses \
  --block-on-secrets \
  --max-scan-bytes 1048576
```
- `--scan-responses`: Enables response body scanning.
- `--block-on-secrets`: Blocks the entire tool response with an error instead of inline redaction (`[REDACTED]`).
- `--max-scan-bytes`: Configures the maximum payload size to scan (default: 1MB).

---

## 4. Setting Up OIDC Identity Binding

AgentWall binds agent sessions and tool call execution to cryptographic OIDC identities, ensuring zero-trust attribution and access enforcement.

> [!NOTE]
> For complete step-by-step configuration guides, claims mappings, and policy examples for **Okta**, **Keycloak**, **Microsoft Entra ID**, **Auth0**, **AWS Cognito**, **Google Workspace**, and **PingIdentity**, see the dedicated [OIDC Identity Binding & Auth Provider Guide](oidc_identity_binding.md) ([oidc_identity_binding.md](file:///c:/AgentWall/agentwall/docs/oidc_identity_binding.md)).

### IdP Configuration

In your YAML policy, define the `identity` configuration (for instance, connecting **Keycloak** or another OIDC provider):

```yaml
identity:
  provider: "oidc"
  issuer: "https://keycloak.corp.internal/realms/production"
  audience: "agentwall-gateway"
  group_claim_key: "groups"    # IdP-specific claim key (e.g. "groups", "cognito:groups", "memberOf")
```

Or pass the discovery issuer via command line:
```bash
agentwall start --policy policy.yaml --oidc-issuer https://keycloak.corp.internal/realms/production
```

---

### JWT Validation & Scope Matching

1. **Bearer Token Extraction:** Agents pass their OIDC JWT Bearer token in the HTTP `Authorization: Bearer <jwt>` header.
2. **Signature & Claim Verification:** The gateway fetches the IdP's JWKS public keys and verifies the signature, expiration (`exp`), issuer (`iss`), and audience (`aud`).
3. **Scope Enforcement (`X-AgentWall-Credential-Scope`):** Each tool rule in the policy can mandate required credential scopes. The agent's token must match the required scope:
   ```yaml
   tools:
     - name: "delete_database"
       action: allow
       credential_scope: ["db:admin"]
   ```
4. **Strict Scope Mode:** By default, scope mismatches log a warning. Upgrade scope mismatches to hard `403 Forbidden` denials by enabling strict mode:
   ```bash
   export AGENTWALL_STRICT_CREDENTIAL_SCOPE=true
   agentwall start --policy policy.yaml
   ```

---

### Agent Short-Lived Credential CLI

Manage short-lived agent credentials directly via the `agentwall identity` subcommand suite:

#### 1. Provision Short-Lived Credential
```bash
agentwall identity create --agent financial-agent-01 --scope "file:read" --ttl 1h
```

#### 2. Rotate Agent Credentials
Force zero-downtime rotation with a 30-second old credential drain period:
```bash
agentwall identity rotate --agent financial-agent-01 --drain-secs 30
```

#### 3. Configure Per-Tool Scoping Rules
```bash
agentwall identity scope --agent financial-agent-01 --tool execute_shell --deny
```

#### 4. Audit Identity History
Display the HMAC-chained identity audit trail:
```bash
agentwall identity audit --agent financial-agent-01 --verify
```

---

## 5. Connecting to the Control Hub

The **Control Hub** acts as the central control plane for AgentWall fleets, providing real-time policy hot-reloading, secret custody, and centralized telemetry aggregation.

### Hub Architecture & API Specifications

- **Base URL:** `https://{hub-host}:8080/api/v1` (or `:8081` in local dev)
- **Protocol:** HTTP/2 over TLS with OIDC JWT Bearer Authentication

---

### Real-Time SSE Event Stream

Gateways maintain a persistent Server-Sent Events (SSE) connection to `GET /api/v1/events` (or `/api/v1/policy/subscribe`).

```
Gateway                                               Control Hub API
   │                                                         │
   │─── GET /api/v1/events (Accept: text/event-stream) ─────►│
   │◄── event: policy_update (id: policy-v42) ───────────────│ (Hot-swaps policy in RAM)
   │◄── event: credential_rotation (provider: openai) ───────│ (Refreshes cached API keys)
   │◄── : ping (every 15s) ──────────────────────────────────│ (Keepalive ping)
```

#### Event Handlers:
- `policy_update`: Triggers an atomic in-memory hot-swap (`ArcSwap`) of the gateway policy ruleset without dropping active agent TCP connections.
- `credential_rotation`: Signals that a provider API key has been rotated, causing the gateway to fetch updated ciphertext from `GET /api/v1/credentials/:provider`.
- `: ping`: Sent every 15 seconds. If no ping is received within 30 seconds, the gateway logs a warning and retries connection backoff.

#### Connecting Gateways in Centralized Mode:
```bash
export DASHBOARD_API_URL="https://hub.corp.com:8080"
export POLICY_READ_SECRET="your-policy-read-secret"
export GATEWAY_SECRET="your-gateway-secret"

agentwall start --listen 0.0.0.0:8080 --centralized
```

---

### Provider API Key Custody & Injection

AgentWall eliminates the need to store long-lived LLM provider API keys (OpenAI, Anthropic) on developer machines or agent containers:

1. **Central Custody:** API keys are encrypted with AES-256-GCM and stored centrally in the Hub database.
2. **Gateway Ingestion:** Authorized gateways fetch encrypted key blocks via `GET /api/v1/credentials/:provider` during bootstrap.
3. **Outbound Injection:** When an agent sends an LLM API request through the gateway, AgentWall verifies authorization, injects the real `Authorization: Bearer sk-...` key, and strips the agent's temporary credential before forwarding to OpenAI/Anthropic.

---

### Telemetry Batch Uploads

Gateways periodically flush audit logs to the Control Hub via `POST /api/v1/telemetry`.

```json
{
  "gateway_id": "gw-prod-us-east-1a",
  "events": [
    {
      "seq": 1042,
      "ts": "2026-07-31T12:34:56.789Z",
      "event": "policy.deny",
      "request_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "tool": "read_file",
      "action": "BLOCK",
      "hmac_chain_hash": "7c2e4b8a91c..."
    }
  ]
}
```

*Privacy Guarantee:* Raw parameter payloads and response content are hashed (SHA-256) or stripped before telemetry upload to guarantee zero payload leakage to the central dashboard.

---

## 6. Verifying Audit Logs

AgentWall records tamper-evident, cryptographically chained audit logs to ensure regulatory compliance and forensic accountability.

### HMAC Cryptographic Hash Chaining

Every audit event written to disk contains an HMAC hash calculated from its own payload combined with the HMAC hash of the preceding event:

$$\text{HMAC}_n = \text{HMAC-SHA256}(K, \text{Payload}_n \parallel \text{HMAC}_{n-1})$$

If an attacker attempts to modify, delete, or re-order any historical audit line, the hash chain breaks, causing verification tools to instantly detect the tamper point.

---

### Log Integrity Verification

To verify audit log integrity, run `agentwall verify-log`:

```bash
agentwall verify-log audit.log
```

With custom signing keys:
```bash
agentwall verify-log audit.log --key-file /etc/agentwall/audit.key
```

**Sample Output:**
```
[INFO] Verifying audit log: audit.log
[INFO] Records checked: 4,821
[SUCCESS] HMAC hash chain intact. Zero tampering detected.
```

---

### Session Reports & SIEM Export

#### Generating Session Reports
Generate structured JSON or text summaries from audit logs:
```bash
agentwall report audit.log --format json --output report.json
```

#### Direct SIEM Streaming
Stream audit events directly to SIEM platforms in real time:

**Splunk HEC:**
```bash
agentwall start \
  --policy policy.yaml \
  --siem-backend splunk \
  --siem-endpoint https://splunk.corp.com:8088/services/collector/event \
  --siem-token "${SPLUNK_HEC_TOKEN}"
```

**Datadog:**
```bash
agentwall start \
  --policy policy.yaml \
  --siem-backend datadog \
  --siem-endpoint https://http-intake.logs.datadoghq.com/api/v2/logs \
  --siem-token "${DATADOG_API_KEY}"
```

**OpenSearch:**
```bash
agentwall start \
  --policy policy.yaml \
  --siem-backend opensearch \
  --siem-endpoint https://opensearch.corp.com/agentwall-logs/_doc \
  --siem-token "user:password"
```

*Fail-Safe Redundancy:* If SIEM network requests time out (default: 2 seconds), the gateway automatically writes events to the local audit log (`audit.log`) to prevent data loss.

---

## 7. Troubleshooting Common Issues

### Gateway Startup & YAML Validation Errors

#### Error: `POLICY_INVALID` / Unknown Fields Rejection
```
[ERROR] Failed to load policy: unknown field `allowed_tools` at line 14 column 3
```
- **Cause:** Schema v2 enforces `#[serde(deny_unknown_fields)]`. Obsolete v1 policy fields are rejected.
- **Solution:** Run `agentwall lint agentwall-policy.yaml` to identify invalid syntax. Update tool definitions to conform to the v2 specification.

#### Error: Missing TLS Certificate Pair
```
[ERROR] Both --tls-cert and --tls-key must be specified together
```
- **Cause:** Only one TLS flag was provided.
- **Solution:** Supply both `--tls-cert` and `--tls-key` paths, or omit both for HTTP mode behind a reverse proxy.

---

### Tool Call Denials & Safe Mode Interceptions

#### Error 403 `POLICY_VIOLATION`
```json
{
  "error": {
    "code": "POLICY_VIOLATION",
    "message": "Tool 'exec_shell' is not in the allowlist for group 'dev-team'"
  }
}
```
- **Cause:** The requested tool is not explicitly listed in `tools:` with `action: allow`.
- **Solution:** Add the tool entry to `agentwall-policy.yaml` or use `agentwall identity scope --agent <name> --tool exec_shell --allow`.

#### Error 403 `DLP_BLOCKED`
```json
{
  "error": {
    "code": "DLP_BLOCKED",
    "message": "Content blocked by DLP pattern 'aws_access_key'"
  }
}
```
- **Cause:** A tool parameter or response contained a secret matching a DLP rule.
- **Solution:** Check the tool parameter inputs. Ensure secrets are referenced via secure environment variables or provider key custody rather than raw text.

---

### OIDC & JWT Authorization Failures

#### Error 401 `IDENTITY_REQUIRED` / `TOKEN_EXPIRED`
```json
{
  "error": {
    "code": "IDENTITY_REQUIRED",
    "message": "Missing or invalid OIDC JWT Bearer token"
  }
}
```
- **Cause:** The HTTP request lacked a valid `Authorization: Bearer <jwt>` header or the token expired.
- **Solution:** Refresh the agent's OIDC JWT from your identity provider and pass it in the request header.

---

### Control Hub Synchronization Issues

#### Error 503 `HUB_UNAVAILABLE`
```
[WARN] Control Hub unreachable at https://hub.corp.com:8080. Retrying SSE connection...
```
- **Cause:** Gateway cannot connect to the Control Hub SSE endpoint (`/api/v1/events`).
- **Solution:** Check network routing and verify `DASHBOARD_API_URL` and `POLICY_READ_SECRET`. The gateway automatically falls back to local policy disk files until connection is re-established.

---

### Executable & PATH Troubleshooting

#### Issue: `agentwall: command not found` or `agentwall --version` failing across terminal restarts

To ensure `agentwall` works globally across **all future terminal sessions** without re-running `export PATH` manually, persist the installation directory in your shell/OS environment configuration:

* **Linux / WSL (Bash):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
  source ~/.bashrc
  ```

* **macOS / Linux (Zsh):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc
  source ~/.zshrc
  ```

* **Fish Shell (Linux / macOS):**
  ```fish
  fish_add_path ~/.local/bin
  ```

* **Windows (PowerShell):**
  Persistently append `%USERPROFILE%\.local\bin` to the User `Path` environment variable:
  ```powershell
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.local\bin", "User")
  ```
  *(Note: Restart active PowerShell windows for the change to take effect).*

* **Windows (Command Prompt / CMD):**
  ```cmd
  setx PATH "%PATH%;%USERPROFILE%\.local\bin"
  ```
  *(Note: Re-open Command Prompt for the change to take effect).*

* **Windows (Git Bash / MSYS2):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile
  source ~/.bash_profile
  ```

#### Issue: `✖ Stdio proxy error: No such file or directory (os error 2)`

- **Cause 1 (`npx` not in PATH environment):** On macOS, Node/nvm/brew/fnm binaries like `npx` may reside in a non-standard binary directory (e.g. `~/.nvm/versions/node/v20.x/bin/npx` or `/opt/homebrew/bin/npx`) that `agentwall` cannot resolve automatically if executed in a restricted shell context.
  - **Solution:** Pass the full path using `$(which npx)`:
    ```bash
    agentwall dev --stdio -- $(which npx) -y @modelcontextprotocol/server-filesystem ~/workspace
    ```

- **Cause 2 (Target directory missing or invalid path):** The target directory (e.g., `~/workspace`) does not exist.
  - **Solution:** Ensure the path exists before running `agentwall dev --stdio`:
    ```bash
    mkdir -p ~/workspace
    agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem ~/workspace
    ```

---

### IDE Wrapping & Watch Daemon Diagnostics

#### Issue: IDE MCP tools not routing through AgentWall after `agentwall wrap`
- **Cause:** IDE processes (Claude Desktop, Cursor, VS Code) read `mcpServers` configuration strictly at application startup.
- **Solution:** Restart the IDE process completely after running `agentwall wrap <target>`.
- **Diagnostic Tool:** Run `agentwall status` to inspect path resolution, file existence, and wrap status across all IDE targets.

---

### Spend Limit & Loop Detection Triggers

#### Error 429 `SPEND_LIMIT_EXCEEDED`
```json
{
  "error": {
    "code": "SPEND_LIMIT_EXCEEDED",
    "message": "Token budget of 100,000 exceeded for current session"
  }
}
```
- **Cause:** The session token consumption exceeded `spend.max_tokens_per_session`.
- **Solution:** Reset session spend metrics or adjust spend limits in `agentwall-policy.yaml`.

#### Error 429 `LOOP_DETECTED`
```json
{
  "error": {
    "code": "LOOP_DETECTED",
    "message": "Agent loop detected: tool 'read_file' repeated 3 times with identical parameters"
  }
}
```
- **Cause:** The agent invoked the exact same tool call and parameters repeatedly, tripping cycle detection.
- **Solution:** AgentWall returned a `PivotError` instructing the agent to break out of its loop. Check agent prompt logic or adjust `loop_detection.threshold` in policy configuration.

---

## 8. Stateful Sequence Rules (ADR Framework)

> **ADR** stands for **AI Detection & Response** — a security framework that extends AgentWall with stateful multi-step attack detection, security benchmarking, and self-healing policy synthesis.

Standard tool allowlisting evaluates each tool call in isolation. However, many real-world attacks unfold across multiple steps — a legitimate-looking `read_file` followed by an `http_post` to an external endpoint is an exfiltration chain that neither call reveals alone. AgentWall's **ADR Sequence Engine** solves this by maintaining a per-session sliding-window call history and evaluating multi-step pattern rules against it.

### How the Sequence Engine Works

1. The **`SessionTracker`** maintains a ring buffer of recent tool calls per session, keyed by session ID.
2. On every incoming tool call, the **Sequence Engine** evaluates all configured `sequence_rules` against the trailing call window.
3. If a rule's pattern matches (in order, within the configured `window`), the engine immediately returns a **`deny`** response and logs the violation with the rule ID.
4. Violations appear as **Sequence Rule Violation Badges** in the local dashboard at `http://127.0.0.1:8080`.

### Writing Sequence Rules

Add a `sequence_rules` stanza to your `agentwall-policy.yaml`:

```yaml
sequence_rules:
  # Block the read_file → execute_command chain (common exfiltration pattern)
  - id: "no-read-then-exec"
    description: "Block shell execution that follows a file read"
    window: 5          # Look back over the last 5 tool calls in this session
    pattern:
      - tool: read_file
      - tool: execute_command
    action: deny
    message: "Exfiltration chain detected: read_file → execute_command"

  # Block repeated HTTP POSTs (data pump pattern)
  - id: "no-repeated-http-post"
    description: "Block more than 3 HTTP POSTs within a 10-call window"
    window: 10
    pattern:
      - tool: http_post
      - tool: http_post
      - tool: http_post
    action: deny
    message: "Repeated POST pattern blocked"

  # Detect credential file read followed by network call
  - id: "no-cred-read-then-network"
    description: "Block network calls after reading credential files"
    window: 3
    pattern:
      - tool: read_file
      - tool: http_post
    action: deny
    message: "Credential theft chain blocked: credential read → outbound network"
```

### Rule Fields Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | Yes | Unique identifier, referenced in audit logs and dashboard badges |
| `description` | string | No | Human-readable explanation of the attack pattern |
| `window` | integer | Yes | Number of recent tool calls to examine in the session history |
| `pattern` | list | Yes | Ordered list of `tool:` names forming the attack chain |
| `action` | enum | Yes | `deny` — block and log; `log` — observe only |
| `message` | string | No | Reason string returned to the agent and written to the audit log |

### Sequence Rule Violations in Audit Logs

When a sequence rule fires, the audit log entry includes:

```json
{
  "event_type": "sequence_rule_violation",
  "rule_id": "no-read-then-exec",
  "matched_pattern": ["read_file", "execute_command"],
  "session_id": "sess-abc123",
  "blocked_tool": "execute_command",
  "timestamp": "2026-08-04T09:00:00Z"
}
```

Use `agentwall verify-log audit.log` to confirm the chain of custody for any sequence violation.

---

## 9. ADR Security Benchmark

The `agentwall bench` command runs an offline **303-task benchmark suite** against a local AgentWall gateway instance. It measures how well your current policy configuration detects and blocks 17 categories of AI attack patterns.

### Running the Benchmark

```bash
# Run all 303 tasks across all 17 attack categories
agentwall bench --full

# Or when building from source
cargo run -- bench --full
```

The benchmark completes in under 60 seconds and writes an HTML report to `target/benchmark-report.html`.

```bash
# Open the report
open target/benchmark-report.html           # macOS
xdg-open target/benchmark-report.html      # Linux
Start-Process target/benchmark-report.html # Windows PowerShell
```

### Reading the Report

The report shows:

- **Overall security grade** (A ≥ 90%, B = 75–89%, C < 75%) with pass/fail counts
- **Per-category pass rates** with plain-English descriptions of what each category tests
- **Comparative baselines** against GuardAgent, LlamaFirewall, and ALRPHFS
- **Policy recommendations** to address failing categories

### Dashboard Integration

The **ADR Benchmark tab** in the local dashboard (`http://127.0.0.1:8080`) renders the latest benchmark report interactively. Launch the dashboard with:

```bash
agentwall dev
```

---

## 10. War Plan Strategic Features (v2.0)

### Passive Shadow AI Risk Delta Reports
Run AgentWall in non-blocking observation mode to audit agent traffic:
```bash
agentwall start --shadow-mode --log-path audit.log
# Generate Risk Delta report summarizing hypothetical blocks and PII exfiltrations
agentwall report audit.log --risk
```

### Vexa Security Scanning (vexa-scan)
Scan MCP server definitions and security policy schemas before deployment:
```bash
agentwall scan --path agentwall-policy.yaml
```

### WebSocket Egress Tunneling
Bridge cloud agents with local MCP tools over a secure Rust WebSocket tunnel with sub-5ms latency and inline DLP:
```bash
agentwall start --centralized --listen 0.0.0.0:8080
```

### Human-in-the-Loop (HITL) Webhooks
Intercept dangerous commands and require HMAC-signed approval via Slack, Teams, or the Control Hub UI:
```yaml
hitl_escalation:
  enabled: true
  secret_key: "env:AGENTWALL_HITL_SECRET"
  webhook_url: "https://hooks.slack.com/services/..."
```

### Hardened Agent Containers (HAR)
Deploy AgentWall as an entrypoint proxy inside OCI container environments (Obot, Kubernetes) using the lightweight image (<100MB):
```bash
docker build -f Dockerfile.har -t agentwall-har:v2.0 .
```

Then click **ADR Benchmark** in the sidebar to view your security score ring and per-category breakdown.

For the full benchmark reference including all 17 attack categories and scoring methodology, see the [ADR Security Benchmark Guide](adr_benchmark.md).

---

## 11. Air-Gapped Operations, Licensing & Compliance (v2.1)

### Offline Licensing & Key Generation
AgentWall provides offline Ed25519-signed licensing for Control Hub deployments without external phone-home telemetry:

```bash
# 1. Generate Ed25519 keypair for license signing
agentwall license keygen --output ./keys

# 2. Issue a signed JWT license for an organization
agentwall license generate \
  --org "acme-corp" \
  --tier "team" \
  --seats 25 \
  --days 365 \
  --signing-key ./keys/vexa_license.key
```

Configure `AGENTWALL_HUB_LICENSE_KEY` on the Control Hub API container to enable licensed features and enforce seat limits.

### Air-Gapped OIDC & JWKS Export
For isolated environments lacking outbound internet connectivity, export JWKS keys from your OIDC provider and load them directly from local disk:

```bash
# Export JWKS keys from an OIDC provider (run on connected host)
agentwall identity export-jwks --issuer "https://auth.corp.com" --output ./jwks.json
```

In your `agentwall-policy.yaml`:
```yaml
auth:
  provider: "okta"
  issuer: "https://auth.corp.com"
  audience: "agentwall-prod"
  jwks_file: "/etc/agentwall/jwks.json" # Bypasses HTTP discovery
```

### Provider API Key Encryption (AES-256-GCM)
Provider LLM API keys stored in the Control Hub PostgreSQL database are encrypted at rest using AES-256-GCM with random 12-byte nonces:

```bash
# Set 32-byte master encryption secret for Control Hub API
export PROVIDER_KEY_ENCRYPTION_SECRET="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
```

### Automated Compliance Evidence Reporting
Generate audit evidence reports mapped to SOC 2 Type II, ISO 27001, and NIST AI RMF 1.0:

```bash
# Print Markdown summary report to stdout
agentwall compliance report --log audit.log

# Export JSON evidence report for auditors
agentwall compliance report --log audit.log --format json --output soc2_evidence.json
```


