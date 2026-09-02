# Vexa Agent Control

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.70-green.svg?style=flat-square)](Cargo.toml)
[![Rust](https://img.shields.io/badge/Rust-1.80%2B-orange.svg?style=flat-square)](https://www.rust-lang.org/)
[![OWASP ASI 2026](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%20(ASI%202026)-success.svg?style=flat-square)](docs/owasp_agentic_top10.md)
[![Documentation Hub](https://img.shields.io/badge/Docs-Documentation%20Hub-1f6feb.svg?style=flat-square)](docs/README.md)

> **Protect local AI-agent tool calls with a small, inspectable gateway.**
>
> Vexa Agent Control routes supported MCP and HTTP traffic through local policy checks, records security decisions, and helps developers catch secrets, prompt-injection patterns, and risky tool behavior before they leave the workstation.
>
> Start in observation mode if you are evaluating the tool. Move to enforcement only after you have verified the integration that you use.

---

## Navigation

- [What Vexa Does Today](#what-vexa-does-today)
- [Who Should Use It](#who-should-use-it)
- [Supported Platforms](#supported-platforms)
- [Verified Integrations](#verified-integrations)
- [Docker Quickstart (2 Minutes)](#docker-quickstart-2-minutes)
- [10-Minute Workstation Quickstart](#10-minute-quickstart)
- [What Changes on Your Machine](#what-changes-on-your-machine)
- [Modes Explained](#modes-explained)
- [Small Team Path](#small-team-path)
- [Troubleshooting & Removal](#troubleshooting--removal)
- [Advanced & Enterprise](#advanced--enterprise)
- [Documentation Index](#documentation-index)

---

## What Vexa Does Today

Vexa Agent Control acts as a local security sidecar and transparent proxy for AI agent tool calls:

- **Phase-Oriented Request Pipeline:** Deterministic 9-stage execution lifecycle (Ingress, Identity Binding, Snapshot Acquisition, Security Inspection, Preflight Reservation, Route Planning, Upstream Execution, Stream Sanitization, Settlement & Outbox) with zero lock contention.
- **Universal Provider Transformation Engine:** Native bidirectional protocol normalization across OpenAI, Azure OpenAI Service, Groq, Anthropic Claude, Google Gemini, and AWS Bedrock.
- **Valkey-Powered Distributed State:** High-performance open-source Valkey (BSD) state layer for sub-millisecond virtual key caching, distributed rate limiting, and zero-lock atomic microcent spend reservations.
- **Safe Operation Replay Taxonomy:** Strict classification separating safe `ReadOnly` requests from side-effecting MCP tool calls to prevent duplicate mutations.
- **Decoupled Durable Outbox:** Local HMAC-SHA256 disk durability (`sync_all`) combined with non-blocking async SIEM / telemetry fan-out.
- **Run Explorer & Forensic Dossiers:** Traces every LLM request through identity, policy snapshots, spend authorization, and upstream dispatch with forensic drawers and cryptographic correlation.
- **Effective Policy Explorer:** Resolves deterministic multi-layer policy hierarchies (Organization, Group, Spend, Virtual-Key, Device) with point-in-time historical audit support.
- **Fail-Closed Spend Governance:** Enforces integer microcent preflight reservations and accurate SSE streaming token settlement.
- **Enrolled-Device Sentry & Attestation:** Provides continuous filesystem posture monitoring, auto-healing, and authentic Ed25519 cryptographic policy verification.
- **Identity Provider Integration (Local, Google, Azure Entra ID):** Authenticates operators via Local Admin or SSO, validates agent JWTs via dynamic JWKS discovery, and attributes spend and audit events to verified identities.
- **DLP & Secret Leak Prevention:** Detects AWS keys, OpenAI keys, SSH private keys, GitHub tokens, and high-entropy credentials before they leave your workstation.
- **Prompt Injection & Loop Guards:** Evaluates tool arguments against deterministic rules and structural recursion limits.
- **Tamper-Evident Audit Logging:** Emits durable, JSONL event records to `~/.agentcontrol/audit.jsonl` with HMAC signing.
- **Cost-Effective Multi-Cloud OpenTofu Deployments:** Production-ready OpenTofu blueprints for AWS (ECS Fargate Spot), Azure (Container Apps), and GCP (Cloud Run) with containerized Valkey sidecars.

> [!IMPORTANT]
> **Protection Boundary:** Vexa Agent Control inspects traffic routed through wrapped MCP configurations, explicit HTTP proxy environment variables (`AGENTCONTROL_PROXY_URL` / `HTTP_PROXY`), and strict mTLS brokered routes. In Team Enforce Mode, spend governance and broker eligibility fail closed.

---

## Who Should Use It

| Profile | Typical Use Case | Recommended Starting Point |
|---|---|---|
| **Local Dev & PoC (Docker)** | Instant local evaluation without installing toolchains; running standalone container or full stack. | [Docker Quickstart](#docker-quickstart-2-minutes) · [Docker Guide](docs/guides/docker-deployment.md) |
| **Individual Developer** | Evaluating MCP tools, inspecting tool traffic, blocking accidental secret leakage natively. | [10-Minute Quickstart](#10-minute-quickstart) |
| **Small AI Team / SMB** | Shared security policies across engineers, unified audit logging, spend caps. | [Small Team Hub Guide](docs/guides/small-team-hub.md) |
| **Platform & Enterprise** | Kubernetes Helm sidecars, OIDC identity binding, SIEM forwarding, zero-knowledge CMK. | [Enterprise Reference](docs/advanced/enterprise.md) |

---

## Supported Platforms

| Platform | Architecture | Status | Shell / Runtime Requirements | Notes |
|---|---|---|---|---|
| **Docker / Containers** | `x86_64` / `aarch64` | **Supported** | Docker Engine 24.0+ / Compose v2+ | Zero host setup; standalone or full stack |
| **macOS (Apple Silicon)** | `aarch64` (M1/M2/M3/M4) | **Supported** | Zsh / Bash | Mandatory SHA-256 verified |
| **macOS (Intel)** | `x86_64` | **Supported** | Zsh / Bash | Mandatory SHA-256 verified |
| **Linux** | `x86_64` / `aarch64` | **Supported** | Bash / Zsh (`curl`, `unzip`, `sha256sum`) | Ubuntu, Debian, Fedora, Arch, Alpine |
| **WSL2** | `x86_64` | **Supported** | Bash / Zsh inside WSL | Protects Linux-side tools and agents |
| **Windows 10/11** | `x86_64` (AMD64) | **Supported** | PowerShell 5.1+ / CMD | Auto-adds `%USERPROFILE%\.local\bin` to PATH |
| **Windows on ARM** | `aarch64` | *Experimental* | PowerShell | Requires specific ARM64 release asset |

---

## Verified Integrations

Trust has levels. Vexa classifies integrations based on end-to-end automated test validation:

| Level | Client / IDE | Configuration Path Checked | Automatic Wrap Support |
|---|---|---|---|
| **Verified** | **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` / `~/Library/Application Support/Claude/` | Tested & fully supported |
| **Verified** | **Cursor** | `~/.cursor/mcp.json` & `User/settings.json` | Tested & fully supported ([Cursor Guide](docs/guides/cursor_governance_guide.md)) |
| **Verified** | **Codex** | `~/.codex/config.toml` | Tested & fully supported |
| **Verified** | **Antigravity** | `~/.gemini/antigravity/mcp_config.json` | Tested & fully supported |
| **Experimental** | VS Code, JetBrains, Zed, Cline, OpenCode | User-managed / hypothetical path | Requires `agentcontrol status` & manual check |
| **Custom Agent** | LangChain, LlamaIndex, CrewAI, AutoGen, Raw HTTP | `AGENTCONTROL_PROXY_URL=http://127.0.0.1:8080` | Manual proxy routing |

---

## Docker Quickstart (2 Minutes)

Get up and running immediately with zero host toolchain installation:

### Option 1: Standalone Gateway Container (`docker run`)

#### Basic Deployment
```bash
docker run -d \
  --name agentcontrol \
  -p 8080:8080 \
  -v agentcontrol-data:/app/data \
  -v agentcontrol-logs:/var/log/agentcontrol \
  ghcr.io/noviqtechnologies/agentcontrol:latest \
  start --listen 0.0.0.0:8080
```

#### With Authentication (Recommended)
```bash
docker run -d \
  --name agentcontrol \
  -p 8080:8080 \
  -v agentcontrol-data:/app/data \
  -v agentcontrol-logs:/var/log/agentcontrol \
  -e AGENTCONTROL_ENABLE_AUTHENTICATION=true \
  -e AGENTCONTROL_BOOTSTRAP_TOKEN=your-bootstrap-token \
  -e AGENTCONTROL_ADMIN_TOKEN=your-bootstrap-token \
  ghcr.io/noviqtechnologies/agentcontrol:latest \
  start --listen 0.0.0.0:8080
```

#### Using a Custom Port (e.g. `-p 9999:8080`)
```bash
docker run -d \
  --name agentcontrol \
  -p 9999:8080 \
  -v agentcontrol-data:/app/data \
  -v agentcontrol-logs:/var/log/agentcontrol \
  -e AGENTCONTROL_SERVER_HOSTNAME=localhost:9999 \
  -e AGENTCONTROL_ENABLE_AUTHENTICATION=true \
  -e AGENTCONTROL_BOOTSTRAP_TOKEN=your-bootstrap-token \
  ghcr.io/noviqtechnologies/agentcontrol:latest \
  start --listen 0.0.0.0:8080
```

### Option 2: Full-Stack Control Hub (`docker compose`)
```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control

# Launch PostgreSQL 16 + Control Plane API + Web Console UI + Gateway
docker compose -f docker-compose.team.yml up -d
```
- **Web Console UI:** `http://localhost:3000` (Login: `admin@vexa.local` / `admin12345678`)
- **Gateway Endpoint:** `http://localhost:8080`
- Read the complete [Docker Deployment Guide](docs/guides/docker-deployment.md).

---

## 10-Minute Workstation Quickstart

Follow this step-by-step developer journey to install, safely discover, protect one client, verify enforcement, and roll back.

### Step 0: Preflight Check

Confirm your local architecture and ensure port `8080` is available:

```bash
# macOS / Linux / WSL
uname -m && netstat -an | grep 8080 || echo "Port 8080 is available"
```

```powershell
# Windows (PowerShell)
$env:PROCESSOR_ARCHITECTURE; Get-NetTCPConnection -LocalPort 8080 -ErrorAction SilentlyContinue
```

### Step 1: Install Vexa Agent Control

Download and install the statically-linked binary to `~/.local/bin`:

**macOS / Linux / WSL:**
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
export PATH="$HOME/.local/bin:$PATH"
agentcontrol --version
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex
agentcontrol.exe --version
```

- **Expected Result:** Prints `agentcontrol 1.0.70`.
- **If it fails:** Verify curl / PowerShell connectivity; check [Platform Install Guides](docs/install/).

### Step 2: Inspect Discovered Clients (Safe Dry-Run)

Inspect which IDE configurations exist on your machine without modifying any files:

```bash
agentcontrol status
agentcontrol protect --dry-run
```

- **Expected Result:** Prints the status table identifying **[verified]** vs **[unverified]** config files.

### Step 3: Protect and Launch Local Gateway

Run one-command protection to wrap discovered configs and launch the local security gateway:

```bash
# Start in observation (shadow) mode:
agentcontrol protect --shadow

# OR start in active enforcement mode (blocks secrets & prompt injections):
agentcontrol protect
```

- **Expected Result:** Discovered MCP configs are backed up and wrapped; local gateway starts on `http://127.0.0.1:8080` and opens the local dashboard.
- **What Changes:** Configs are updated; backups saved to `<config_path>.bak.<timestamp>`.

### Step 4: Verify Live Enforcement

In a separate terminal, execute the 3-point live verification probe:

```bash
agentcontrol verify
```

- **Expected Result:**
  ```text
  ✔ [1/3] Safe Tool Execution (read_file)      ➔ ALLOWED
  ✔ [2/3] DLP Exfiltration Guard (AWS Secret) ➔ BLOCKED [DLP-01-HIGH-ENTROPY]
  ✔ [3/3] Prompt Injection (System Override)  ➔ BLOCKED [INJ-04-OVERRIDE]
  ```

### Step 5: Clean Reversion & Unprotect

To restore all original IDE configurations from backups at any time:

```bash
agentcontrol unprotect
```

- **Expected Result:** Backups are restored; configurations return to their pre-Vexa state.

---

## What Changes on Your Machine

Before writing any configuration, here is the complete footprint of Vexa Agent Control:

| Component | Path (macOS / Linux) | Path (Windows) |
|---|---|---|
| **Binary Executable** | `~/.local/bin/agentcontrol` | `%USERPROFILE%\.local\bin\agentcontrol.exe` |
| **State & Audit Logs** | `~/.agentcontrol/audit.jsonl` | `%USERPROFILE%\.agentcontrol\audit.jsonl` |
| **Local Database** | `~/.agentcontrol/events.db` | `%USERPROFILE%\.agentcontrol\events.db` |
| **Local Policy** | `./agentcontrol-policy.yaml` | `.\agentcontrol-policy.yaml` |
| **Backups Created** | `<config_dir>/<file>.bak.<timestamp>` | `<config_dir>\<file>.bak.<timestamp>` |
| **Local TCP Port** | `127.0.0.1:8080` (customizable with `--listen`) | `127.0.0.1:8080` (customizable with `--listen`) |

---

## Modes Explained

### Security Enforcement Modes
- **Observation / Shadow Mode (`--shadow`):** Logs all tool calls and evaluated policy decisions without blocking any execution. Ideal for testing and policy baseline generation (`agentcontrol generate-policy`).
- **Enforcement Mode (`--enforce` / default in `protect`):** Actively denies tool executions that violate DLP, schema validation, or prompt injection rules.
- **Custom Agent Proxy Mode:** Routes custom Python/Node.js agents via HTTP proxy variables:
  ```bash
  export AGENTCONTROL_PROXY_URL=http://127.0.0.1:8080
  export HTTP_PROXY=http://127.0.0.1:8080
  ```

### LLM Key & Spend Governance Modes (`llm_mode`)
- **`local_compat` (Default):** Standalone local developer compatibility. Dispatches upstream LLM traffic directly using workstation environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GROQ_API_KEY`, `TOGETHER_API_KEY`, `MISTRAL_API_KEY`) or client request headers.
- **`central_shadow`:** Enterprise observation mode. Upstream requests are routed through the Control Plane with centralized key custody. Evaluates price books and logs would-deny events without blocking execution.
- **`central_enforce`:** Authoritative enterprise governance. Zero provider keys on workstations. Enforces preflight row-locked budget reservations, pinned active price books, and fail-closed budget caps before dispatch.

---

## Small Team Path

Deploy a production-ready shared Control Hub for small teams using Docker Compose:

```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control

# 1. Create your production environment file from the secure template
cp .env.team.example .env

# 2. Fill in random secrets and your domain (e.g., using: openssl rand -hex 32)
# 3. Start the secure Team Hub stack
docker compose -f docker-compose.team.secure.yml up -d
```

- **Features:** Centralized policy management (SSE sync), shared audit logs, spend caps, provider key custody, and OTET device onboarding.
- Read the full [Small Team Hub Guide](docs/guides/small-team-hub.md).

---

## Troubleshooting & Removal

### Top 3 First-Run Checks

1. **Port 8080 in use:** Launch on an alternative port:
   ```bash
   agentcontrol protect --listen 127.0.0.1:9090
   ```
2. **IDE tool calls not intercepted:** Restart your IDE after running `agentcontrol protect` so it reloads its configuration.
3. **Backup restoration warning:** Run `agentcontrol unprotect --force` to inspect or force rollback.

### Automated Clean Uninstall

To remove the binary, service daemons, and purge state files:

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall.ps1 | iex
```

Read the full [Removal & Recovery Guide](docs/reference/removal-and-recovery.md).

---

## Advanced & Enterprise

For production deployments, security teams, and platform engineering:

- [Enterprise Architecture & HAR Container](docs/advanced/enterprise.md)
- [Kubernetes Helm Deployment](docs/advanced/kubernetes.md)
- [OIDC Identity Binding (Okta, Entra ID, Auth0)](docs/advanced/oidc.md)
- [SIEM Log Forwarding (Splunk, Datadog, OpenSearch)](docs/advanced/siem.md)
- [OWASP Agentic Top 10 (ASI 2026) Mapping](docs/owasp_agentic_top10.md)

---

## Documentation Index

Explore the complete [Documentation Hub](docs/README.md):

- **Install:** [macOS](docs/install/macos.md) · [Linux](docs/install/linux.md) · [WSL2](docs/install/wsl.md) · [Windows PowerShell](docs/install/windows-powershell.md) · [Windows CMD](docs/install/windows-cmd.md)
- **Guides:** [Docker Deployment](docs/guides/docker-deployment.md) · [Workstation Workflow](docs/guides/workstation.md) · [Custom Agent HTTP](docs/guides/custom-agent-http.md) · [Small Team Hub](docs/guides/small-team-hub.md) · [Run Explorer](docs/guides/run-explorer.md) · [Effective Policy Explorer](docs/guides/effective-policy.md)
- **Integrations:** [Matrix](docs/integrations/README.md) · [Claude Desktop](docs/integrations/claude-desktop.md) · [Cursor](docs/integrations/cursor.md) · [Codex](docs/integrations/codex.md) · [Antigravity](docs/integrations/antigravity.md)
- **Reference:** [CLI Commands](docs/reference/cli.md) · [Configuration & Env Vars](docs/reference/configuration.md) · [Paths & State](docs/reference/paths-and-state.md) · [Troubleshooting](docs/reference/troubleshooting.md) · [Removal & Recovery](docs/reference/removal-and-recovery.md) · [Legacy Alias Migration](docs/reference/legacy-migration.md) · [Release Notes Template](docs/reference/release-notes-template.md)

---

## Architecture & Licensing

Vexa Agent Control operates on a **Single-Tenant Open-Core Dual-License Model**:

### 1. Dual Licenses
- **Core Open Source ([Apache-2.0](LICENSE)):** Covers the standalone Rust Gateway, local CLI protections (`agentcontrol protect`), MCP inspection, basic regex DLP, prompt injection guards, and community Control Plane.
- **Enterprise Features ([enterprise/LICENSE.md](enterprise/LICENSE.md)):** Source-available commercial license governing OIDC/SAML SSO, multi-team RBAC, real-time SIEM streaming, spend caps & budgets v2, and zero-knowledge CMK custody.

### 2. 3-Tier Capability Model

| Tier | Enrolled Devices | Core Capabilities | Activation |
|---|---|---|---|
| **Developer** | 1 device | Standalone gateway, local proxy, MCP guardrails, JSONL audit logs, prompt injection filters | Free / Built-in |
| **Team** | Up to 25 devices | Everything in Developer + Centralized SSE Policy Sync, Spend Caps v2, Group Policies, OTET Onboarding, Aggregated Audits | `VEXA_LICENSE_KEY` or Web UI |
| **Enterprise** | Unlimited | Everything in Team + OIDC/SAML SSO, Strict mTLS Device Identity, Real-Time SIEM Streaming, Deep DLP, CMK Custody | Ed25519 Commercial Token |

### 3. Single-Tenant Sovereign Ownership
All Control Plane deployments operate within a single private organization boundary (`organization_id`). Live keys, tool calls, and LLM payloads never leave your infrastructure. Offline cryptographic validation (Ed25519) allows air-gapped deployments without outbound telemetry.

