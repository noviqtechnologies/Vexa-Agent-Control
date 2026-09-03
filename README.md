<div align="center">

# 🛡️ Vexa Agent Control
### *The Open-Source AI Safety Layer & Zero-Trust MCP Governance Gateway*

**Let your team build & use AI agents — without leaking secrets, losing control, or blowing budgets.**

[🌐 Website](https://vexasec.io/) · [📖 Documentation Hub](docs/README.md) · [⚡ Docker Quickstart](#docker-quickstart-2-minutes) · [💻 Workstation Quickstart](#10-minute-workstation-quickstart) · [☸️ Helm Chart](chart/README.md) · [🛡️ OWASP ASI Top 10](docs/owasp_agentic_top10.md)

<br/>

[![Website](https://img.shields.io/badge/Website-vexasec.io-7C3AED.svg?style=flat-square&logo=google-chrome&logoColor=white)](https://vexasec.io/)
[![Open Source License](https://img.shields.io/badge/License-Apache%202.0-6366F1.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.73-10B981.svg?style=flat-square)](Cargo.toml)
[![Rust](https://img.shields.io/badge/Engine-Rust%201.80%2B%20(Sub--ms)-F97316.svg?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%20(ASI%202026)-8B5CF6.svg?style=flat-square)](docs/owasp_agentic_top10.md)
[![Docker](https://img.shields.io/badge/Docker-ghcr.io%2Fagentcontrol-06B6D4.svg?style=flat-square&logo=docker&logoColor=white)](docs/guides/docker-deployment.md)

<br/><br/>

<img alt="Vexa Agent Control Architecture" src="docs/architecture.png" width="100%" />

</div>

---

## Navigation

- [What is Vexa Agent Control](#what-is-vexa-agent-control)
- [Why Vexa Agent Control](#why-vexa-agent-control)
- [Supported Providers & Capabilities](#supported-providers--capabilities)
- [Interactive Features](#interactive-features)
  - [1. Universal AI Gateway & LLM Proxy](#1-universal-ai-gateway--llm-proxy)
  - [2. Zero-Trust MCP Tool Firewall](#2-zero-trust-mcp-tool-firewall)
  - [3. Fail-Closed Spend Governance & Policy Enforcement](#3-fail-closed-spend-governance--policy-enforcement)
  - [4. Forensic Dossiers & Run Explorer](#4-forensic-dossiers--run-explorer)
  - [5. Multi-Cloud OpenTofu Deployments](#5-multi-cloud-opentofu-deployments)
- [Choose Your Deployment Path](#choose-your-deployment-path)
- [Docker Quickstart (2 Minutes)](#docker-quickstart-2-minutes)
- [10-Minute Workstation Quickstart](#10-minute-workstation-quickstart)
- [Multi-Cloud OpenTofu / Terraform Blueprints](#multi-cloud-opentofu--terraform-blueprints)
- [What Changes on Your Machine](#what-changes-on-your-machine)
- [Modes Explained](#modes-explained)
- [Supported Platforms & Verified Integrations](#supported-platforms--verified-integrations)
- [Security & Cryptographic Signatures](#security--cryptographic-signatures)
- [Developer & Contributor Guide](#developer--contributor-guide)
- [Troubleshooting & Clean Removal](#troubleshooting--clean-removal)
- [Open Source & Architecture](#open-source--architecture)
- [Documentation Index](#documentation-index)

---

## What is Vexa Agent Control

**Vexa Agent Control** is an open source AI Gateway and transparent security sidecar purpose-built for AI agents, developers, and enterprise platform teams. It operates in two flexible modalities:

1. **AI Gateway (Centralized Proxy Server):** Centralizes upstream LLM routing (OpenAI, Azure OpenAI, Anthropic Claude, Google Gemini, Groq, AWS Bedrock, and local models) behind standard OpenAI-compatible endpoints with virtual keys, load balancing, real-time rate limiting, and microcent budget caps.
2. **Workstation Sentry & MCP Firewall (Transparent Local Sidecar):** Automatically wraps local agent tool configurations (Claude Desktop, Cursor, Codex, Antigravity) to intercept Model Context Protocol (MCP) and HTTP requests, enforcing Data Loss Prevention (DLP), secret redacting, and prompt-injection defense before data leaves the workstation.

---

## Why Vexa Agent Control

| Challenge | Without Vexa Agent Control | With Vexa Agent Control |
|---|---|---|
| 🛡️ **MCP Tool Security** | Agents execute arbitrary system tools, run unbounded bash commands, or exfiltrate private files. | **Zero-Trust Tool Guard:** Replay classification, strict schema checks, loop limits, and automated parameter sanitization. |
| 🔒 **Credential & DLP Leakage** | API keys, SSH private keys, and AWS credentials get sent directly to external model providers. | **21-Pattern Inline DLP:** High-entropy regex, token scanning, and credential redacting at the wire layer. |
| 🧠 **Prompt Injection Defense** | Untrusted web data or tool responses hijack the agent's system prompt and instructions. | **6-Pass Injection Shield:** Multi-layer detection for jailbreaks, covert directives, and instruction boundary overrides. |
| 🌐 **Model Lock-In & Sprawl** | Custom SDKs and incompatible payload formats for every provider across applications. | **Drop-in Wire Compatibility:** Standard `/v1/chat/completions` and `/v1/models` normalizing multi-provider LLM requests. |
| 💰 **Runaway Spend & Budgets** | Post-hoc billing surprises and asynchronous credit depletion after expensive model runs. | **Fail-Closed Spend Reservations:** Sub-millisecond atomic preflight balance reservations and exact SSE stream settlement. |
| 👁️ **Audit & Forensic Blindspots** | Fleeting terminal output with zero cryptographic proof of agent tool actions or policy evaluations. | **Tamper-Evident Outbox:** Durable HMAC-SHA256 audit logs (`audit.jsonl`) + non-blocking SIEM export (Splunk, Datadog). |
| ⚡ **Performance Overhead** | Heavy proxy layers adding tens to hundreds of milliseconds of latency. | **Ultra-Fast Rust Core:** Sub-millisecond internal routing with BSD Valkey distributed state. |

---

## Supported Providers & Capabilities

Vexa Agent Control provides native bidirectional request/response transformation across leading commercial and local model engines:

| Provider | Model Family / Examples | `/v1/chat/completions` | `/v1/models` | Streaming SSE | Tool / Function Calling | DLP & Secret Guard | Microcent Spend Settlement |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **OpenAI** | GPT-4o, GPT-4o-mini, o1, o3-mini | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Azure OpenAI** | GPT-4o, Azure Deployment Endpoints | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Anthropic Claude** | Claude 3.7 Sonnet, Claude 3.5 Haiku, Opus | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Google Gemini** | Gemini 2.0 Flash, Gemini 1.5 Pro | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Groq AI** | Llama 3.3 70B, DeepSeek R1 Distill | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AWS Bedrock** | Claude 3.5 Sonnet, Amazon Nova | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Local / OpenAI-Compatible** | Ollama, LM Studio, vLLM, LocalAI | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

---

## Interactive Features

<details open>
<summary><b>1. Universal AI Gateway & LLM Proxy</b> — Drop-in OpenAI & Anthropic Protocol Routing</summary>

### Call Any LLM Using OpenAI Client (Python / Node.js / cURL)

Point your existing OpenAI client to Vexa Agent Control. The gateway automatically translates request schemas, handles authentication, reserves spend budgets, and records tamper-evident audit trails.

#### Python (OpenAI SDK)
```python
from openai import OpenAI

# Connect to Vexa Agent Control Gateway
client = OpenAI(
    base_url="http://localhost:8080/v1",
    api_key="your-vexa-virtual-key"  # or upstream provider key in local_compat mode
)

response = client.chat.completions.create(
    model="anthropic/claude-3-7-sonnet-20250219",  # Auto-routed to Anthropic Claude
    messages=[
        {"role": "system", "content": "You are a secure coding assistant."},
        {"role": "user", "content": "Explain how zero-trust proxies protect tool calling."}
    ],
    temperature=0.2,
    stream=True
)

for chunk in response:
    content = chunk.choices[0].delta.content
    if content:
        print(content, end="", flush=True)
```

#### cURL Request
```bash
curl -X POST http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer your-vexa-virtual-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "openai/gpt-4o",
    "messages": [{"role": "user", "content": "Scan repository for security vulnerabilities."}],
    "temperature": 0.0
  }'
```

[**Read the Custom Agent HTTP Guide →**](docs/guides/custom-agent-http.md)

</details>

<details>
<summary><b>2. Zero-Trust MCP Tool Firewall</b> — 1-Command IDE & Agent Protection</summary>

Vexa automatically discovers, backs up, and wraps MCP configurations for **Claude Desktop**, **Cursor**, **Codex**, and **Antigravity**.

### One-Command Protection & Gateway Startup
```bash
# 1. Inspect discovered clients without touching files:
agentcontrol status
agentcontrol protect --dry-run

# 2. Wrap configs & start local gateway with active enforcement:
agentcontrol protect
```

### Automated 3-Point Live Verification Probe
Test that DLP exfiltration blocks and prompt-injection filters are actively protecting your workstation:

```bash
agentcontrol verify
```

**Expected Live Probe Output:**
```text
✔ [1/3] Safe Tool Execution (read_file)      ➔ ALLOWED
✔ [2/3] DLP Exfiltration Guard (AWS Secret) ➔ BLOCKED [DLP-01-HIGH-ENTROPY]
✔ [3/3] Prompt Injection (System Override)  ➔ BLOCKED [INJ-04-OVERRIDE]
```

[**Read the Cursor Governance Guide →**](docs/guides/cursor_governance_guide.md) · [**Claude Desktop Guide →**](docs/integrations/claude-desktop.md)

</details>

<details>
<summary><b>3. Fail-Closed Spend Governance & Policy Enforcement</b> — Budget Caps & Model Routing</summary>

Stop runaway loops and accidental model cost spikes before requests hit provider APIs.

```yaml
# agentcontrol-policy.yaml
version: "2"
default_action: deny

# LLM Provider Rules & Model Whitelisting
llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*", "o1*", "o3*"]
      max_tokens_per_request: 4096
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-7*", "claude-3-5*"]
    - name: "groq"
      action: "allow"
      models: ["llama-3.3-70b*", "deepseek-r1*"]
  dlp:
    actions:
      - entity: "AWS_KEY"
        action: "deny"
      - entity: "OPENAI_KEY"
        action: "deny"
      - entity: "SSH_KEY"
        action: "deny"
      - entity: "CREDIT_CARD"
        action: "deny"

# Microcent Spend Caps & Concurrency Limits
spend_caps:
  enabled: true
  concurrency_ceiling: 50
  max_tokens_per_session: 100000

# MCP Tool Whitelist & Path Traversal Guards
tools:
  - name: "read_file"
    action: allow
    parameters:
      - name: "path"
        type: string
        required: true
        validators:
          - path_traversal
```

- **Atomic Preflight Reservations:** Pre-reserves max-token microcents in memory before upstream dispatch.
- **Exact SSE Stream Settlement:** Calculates actual prompt and completion tokens upon stream finish and settles balance.

[**Read the Spend & Budgets Guide →**](docs/spend_budgets_testing_guide.md)

</details>

<details>
<summary><b>4. Forensic Dossiers & Run Explorer</b> — End-to-End Tracing & Policy Audits</summary>

Every tool call and LLM generation is cryptographically attributed to identity, policy snapshot, spend ledger, and upstream provider response.

```bash
# View real-time audit stream in JSONL format
tail -f ~/.agentcontrol/audit.jsonl | jq .

# Verify HMAC cryptographic chain integrity of audit log records
agentcontrol verify-log ~/.agentcontrol/audit.jsonl

# Generate security and risk summary report from audit records
agentcontrol report ~/.agentcontrol/audit.jsonl --format text
```

- **Forensic Dossier Envelope:** HMAC-SHA256 signature, span ID, device posture, and evaluated policy rules.
- **Multi-Turn Session Forensics:** Chronologically reconstructs entire multi-turn interactions, interleaving LLM completions (`🤖`) with local MCP tool actions (`🛡️`).
- **Prompt Cache & Token Economics:** Tracks Prompt, Completion, and Cached tokens with live Cache Hit Ratio (%) and cost avoidance calculation.
- **SIEM Streaming:** Real-time async fanout to Splunk HEC, Datadog API, and OpenSearch with zero proxy latency overhead.

[**Read the Observability & Forensics Guide →**](docs/user-guide/observability-and-forensics.md) · [**Run Explorer Guide →**](docs/guides/run-explorer.md) · [**Effective Policy Guide →**](docs/guides/effective-policy.md)

</details>

<details>
<summary><b>5. Workstation Coverage Matrix & Control Health</b> — Transparent Boundary Enclosure</summary>

Unlike central-only gateways that are blind to rogue direct connections, Vexa maintains a live boundary map of all enrolled developer environments:

- **Fleet Protection Score (%):** Continuously monitors the ratio of protected vs exposed workstations.
- **IDE Target Audit Matrix:** Auto-discovers whether Cursor, Claude Desktop, VS Code, JetBrains, Windsurf, Zed, or Cline are wrapped or bypassing proxy controls.
- **24-Hour Tamper Log:** Detects and flags unauthorized configuration reversions, manual proxy bypasses, or rogue MCP servers.

```bash
# Check local boundary status and active wrapped IDEs
agentcontrol status

# Wrap an IDE target into the zero-trust mesh
agentcontrol wrap cursor
```

[**Read the Coverage & Boundary Health Guide →**](docs/user-guide/observability-and-forensics.md#4-workstation-coverage--control-health)

</details>

<details>
<summary><b>5. Multi-Cloud OpenTofu Deployments</b> — AWS, Azure & GCP Infrastructure</summary>

Deploy production-grade, highly cost-effective (~$0–$25/mo) control hubs on serverless container infrastructure:

```bash
# Example: Deploying to Google Cloud Run (v2) with Multi-Container Sidecars
cd infra/gcp
cp terraform.stage.tfvars.example terraform.stage.tfvars
terraform init
terraform apply -var-file="terraform.stage.tfvars"
```

- **AWS ECS Fargate:** Spot task execution with Application Load Balancer and AWS Secrets Manager.
- **Azure Container Apps:** Scale-to-zero microservices with built-in Envoy ingress and free managed TLS.
- **GCP Cloud Run (v2):** Multi-container revision with Valkey sidecar and Secret Manager integration.

[**Read the Multi-Cloud Infra Hub →**](infra/README.md)

</details>

---

## Choose Your Deployment Path

| Profile | Typical Use Case | Recommended Starting Point |
|---|---|---|
| **Local Workstation** | Protecting local Cursor/Claude Desktop tools, inspecting tool calls, blocking secret leaks. | [Workstation Quickstart](#10-minute-workstation-quickstart) · [Workstation Guide](docs/guides/workstation.md) |
| **Team Self-Hosted** | Centralized control plane, shared policy hub, team-wide spend caps, aggregated audit logs via Docker. | [Docker Quickstart](#docker-quickstart-2-minutes) · [Docker Guide](docs/guides/docker-deployment.md) |
| **Production Kubernetes** | Scalable cluster deployment with Helm sidecars, OIDC SSO, and SIEM log forwarding. | [Helm Chart Guide](chart/README.md) · [Kubernetes Reference](docs/advanced/kubernetes.md) |
| **Cloud Serverless** | 1-Click cost-effective cloud deployments on GCP Cloud Run, AWS ECS, or Azure Container Apps. | [Terraform Blueprints](infra/README.md) |

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
- **Web Console UI:** `http://localhost:3000` (Default Login: `admin@vexa.local` / `admin12345678`)
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

- **Expected Result:** Prints `agentcontrol 1.0.73`.
- **Troubleshooting:** Check platform-specific guides: [macOS](docs/install/macos.md) · [Linux](docs/install/linux.md) · [WSL2](docs/install/wsl.md) · [Windows PowerShell](docs/install/windows-powershell.md) · [Windows CMD](docs/install/windows-cmd.md).

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

## Multi-Cloud OpenTofu / Terraform Blueprints

Deploy the production stack to your cloud provider using the included OpenTofu/Terraform modules:

```
infra/
├── aws/    # AWS ECS Fargate + ALB + Secrets Manager
├── azure/  # Azure Container Apps + Envoy + Managed TLS
└── gcp/    # Google Cloud Run (v2) + Multi-Container Sidecars
```

### AWS Deployment (ECS Fargate + ALB)
```bash
cd infra/aws/ecs
cp terraform.stage.tfvars.example terraform.stage.tfvars
terraform init && terraform apply -var-file="terraform.stage.tfvars"
```
[**AWS Deployment Reference →**](infra/aws/README.md)

### Azure Deployment (Azure Container Apps)
```bash
cd infra/azure
cp terraform.stage.tfvars.example terraform.stage.tfvars
terraform init && terraform apply -var-file="terraform.stage.tfvars"
```
[**Azure Deployment Reference →**](infra/azure/README.md)

### GCP Deployment (Cloud Run v2 + Secret Manager)
```bash
cd infra/gcp
cp terraform.stage.tfvars.example terraform.stage.tfvars
terraform init && terraform apply -var-file="terraform.stage.tfvars"
```
[**GCP Deployment Reference →**](infra/gcp/README.md)

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
- **`local_compat` (Default):** Standalone local developer compatibility. Dispatches upstream LLM traffic directly using workstation environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `AWS_REGION`) or client request headers.
- **`central_shadow`:** Enterprise observation mode. Upstream requests are routed through the Control Plane with centralized key custody. Evaluates price books and logs would-deny events without blocking execution.
- **`central_enforce`:** Authoritative enterprise governance. Zero provider keys on workstations. Enforces preflight row-locked budget reservations, pinned active price books, and fail-closed budget caps before dispatch.

---

## Supported Platforms & Verified Integrations

### Supported Operating Systems & Runtimes

| Platform | Architecture | Status | Shell / Runtime Requirements | Notes |
|---|---|---|---|---|
| **Docker / Containers** | `x86_64` / `aarch64` | **Supported** | Docker Engine 24.0+ / Compose v2+ | Zero host setup; standalone or full stack |
| **macOS (Apple Silicon)** | `aarch64` (M1/M2/M3/M4) | **Supported** | Zsh / Bash | Mandatory SHA-256 verified |
| **macOS (Intel)** | `x86_64` | **Supported** | Zsh / Bash | Mandatory SHA-256 verified |
| **Linux** | `x86_64` / `aarch64` | **Supported** | Bash / Zsh (`curl`, `unzip`, `sha256sum`) | Ubuntu, Debian, Fedora, Arch, Alpine |
| **WSL2** | `x86_64` | **Supported** | Bash / Zsh inside WSL | Protects Linux-side tools and agents |
| **Windows 10/11** | `x86_64` (AMD64) | **Supported** | PowerShell 5.1+ / CMD | Auto-adds `%USERPROFILE%\.local\bin` to PATH |
| **Windows on ARM** | `aarch64` | *Experimental* | PowerShell | Requires specific ARM64 release asset |

### Verified Client Integrations

| Level | Client / IDE | Configuration Path Checked | Automatic Wrap Support |
|---|---|---|---|
| **Verified** | **Claude Desktop** | `%APPDATA%\Claude\claude_desktop_config.json` / `~/Library/Application Support/Claude/` | Tested & fully supported ([Guide](docs/integrations/claude-desktop.md)) |
| **Verified** | **Cursor** | `~/.cursor/mcp.json` & `User/settings.json` | Tested & fully supported ([Cursor Guide](docs/guides/cursor_governance_guide.md)) |
| **Verified** | **Codex** | `~/.codex/config.toml` | Tested & fully supported ([Guide](docs/integrations/codex.md)) |
| **Verified** | **Antigravity** | `~/.gemini/antigravity/mcp_config.json` | Tested & fully supported ([Guide](docs/integrations/antigravity.md)) |
| **Experimental** | VS Code, JetBrains, Zed, Cline, OpenCode | User-managed / hypothetical path | Requires `agentcontrol status` & manual check |
| **Custom Agent** | LangChain, LlamaIndex, CrewAI, AutoGen, Raw HTTP | `AGENTCONTROL_PROXY_URL=http://127.0.0.1:8080` | Manual proxy routing ([Guide](docs/guides/custom-agent-http.md)) |

---

## Security & Cryptographic Signatures

### Verify Docker Images with Cosign
All Vexa Agent Control container images published to GHCR are cryptographically signed. Verify authenticity using [cosign](https://docs.sigstore.dev/cosign/overview/):

```bash
cosign verify \
  ghcr.io/noviqtechnologies/agentcontrol:latest
```

### Checksum Verification for Binary Releases
Every release publishes automated SHA-256 checksums alongside release assets:

```bash
# macOS / Linux
sha256sum -c agentcontrol_1.0.73_checksums.txt

# Windows PowerShell
Get-FileHash -Algorithm SHA256 .\agentcontrol.exe
```

---

## Developer & Contributor Guide

We welcome contributions to Vexa Agent Control!

### Rust Gateway Development
```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control

# Run syntax and type checks
cargo check

# Run the complete test suite
cargo test

# Run Rust linter (Clippy)
cargo clippy --all-targets --all-features -- -D warnings

# Format source code
cargo fmt --all
```

### Control Plane & Web Console UI Development
```bash
cd control-plane/ui
npm install
npm run dev
```

---

## Troubleshooting & Clean Removal

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

## Open Source & Architecture

### High-Level Architecture

Vexa Agent Control is architected as a lightweight, modular security layer designed for sub-millisecond execution:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AI Agents & Developer IDEs                       │
│           (Claude Desktop, Cursor, Codex, Antigravity, Custom)          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │ (MCP / HTTP / Wire Interception)
                                     ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                 Vexa Security Core (Rust Gateway Engine)                │
│  ├─ 21-Pattern Inline DLP & Credential Redactor                         │
│  ├─ 6-Pass Prompt Injection & Jailbreak Shield                          │
│  ├─ Zero-Trust MCP Tool Firewall & Path Traversal Validator             │
│  ├─ Microcent Spend Ledger & Preflight Atomic Reservations              │
│  └─ Tamper-Evident HMAC-SHA256 Audit Logger (audit.jsonl)               │
└───────────────────┬─────────────────────────────────┬───────────────────┘
                    │                                 │
                    ▼                                 ▼
┌───────────────────────────────────────┐ ┌───────────────────────────────┐
│         Upstream LLM Providers        │ │  Vexa Control Hub (Optional)  │
│ (OpenAI, Anthropic, Gemini, Groq, etc)│ │  (PostgreSQL + Valkey + UI)   │
└───────────────────────────────────────┘ └───────────────────────────────┘
```

- **Client Interception & Sentry:** Transparently wraps local tool configs (Claude Desktop, Cursor, Codex, Antigravity) and proxies tool execution and model completions without modifying agent workflows.
- **Ultra-Fast Rust Core:** Executes inline DLP scanning, prompt injection defense, schema verification, and budget governance in sub-millisecond timeframes.
- **Durable Cryptographic Audit Outbox:** Emits tamper-evident HMAC-SHA256 signed audit dossiers to local outbox logs and real-time SIEM streams (Splunk, Datadog).

---

### Open Source Core (Apache 2.0)

The core gateway primitives, local CLI protections, MCP interception engine, and developer tools are **100% Free and Open Source** under the permissive **[Apache 2.0 License](LICENSE)**:

- **Unrestricted Self-Hosting:** Run on unlimited developer workstations, local machines, servers, or private Kubernetes clusters with zero device caps or artificial seat limits.
- **Zero Telemetry:** No phone-home pings, cloud tracking, or metric exfiltration. Your data, prompts, and credentials stay entirely within your infrastructure.
- **No License Keys Required:** Spin up the local CLI or the full team control plane (`docker compose up -d`) with zero license files or activation codes.
- **Sovereign Single-Tenant Ownership:** All proxy evaluation, DLP redaction, and audit logs execute strictly on your own hardware or private cloud. Live keys, tool calls, and LLM payloads never touch third-party servers.

---

### Commercial Editions for Teams & Enterprise *(Coming Soon)*

For organizations requiring centralized governance, enterprise compliance, and advanced scale, commercial license tiers for **Teams and Enterprise** will be available in the near future:

- **Centralized Fleet Orchestration:** Global policy distribution, device enrollment verification, and automated workstation configuration drift correction.
- **Multi-Tenant RBAC & ABAC:** Fine-grained team hierarchies, workspace isolation, and custom security role definitions.
- **Enterprise SSO & Identity Binding:** SAML 2.0 / OIDC integrations with Okta, Microsoft Entra ID, Google Workspace, and Ping Identity.
- **High-Availability Distributed Broker Mesh:** Clustered gateway deployments with Redis/Valkey state replication and multi-region load balancing.
- **Enterprise SIEM Streaming & Compliance:** Native real-time streaming to Splunk HEC, Datadog API, OpenSearch, and SOC 2 / HIPAA compliance audit readiness.
- **Dedicated Enterprise Support & Custom SLAs:** 24/7 dedicated engineering support, custom upstream provider adapters, and sovereign deployment assistance.

---

### Contact Us

Have questions, feedback, or interested in early access to our upcoming Teams & Enterprise commercial editions?

- 📧 **Email:** [contact@vexasec.io](mailto:contact@vexasec.io)
- 🌐 **Website:** [vexasec.io](https://vexasec.io/)

---

## Documentation Index

Explore the complete [Documentation Hub](docs/README.md):

- **Install Guides:** [macOS](docs/install/macos.md) · [Linux](docs/install/linux.md) · [WSL2](docs/install/wsl.md) · [Windows PowerShell](docs/install/windows-powershell.md) · [Windows CMD](docs/install/windows-cmd.md)
- **Feature Guides:** [Docker Deployment](docs/guides/docker-deployment.md) · [Workstation Workflow](docs/guides/workstation.md) · [Custom Agent HTTP](docs/guides/custom-agent-http.md) · [Small Team Hub](docs/guides/small-team-hub.md) · [Run Explorer](docs/guides/run-explorer.md) · [Effective Policy Explorer](docs/guides/effective-policy.md) · [Spend & Budgets Testing](docs/spend_budgets_testing_guide.md)
- **Integrations:** [Integrations Matrix](docs/integrations/README.md) · [Claude Desktop](docs/integrations/claude-desktop.md) · [Cursor](docs/integrations/cursor.md) · [Codex](docs/integrations/codex.md) · [Antigravity](docs/integrations/antigravity.md)
- **Architecture & Enterprise:** [Architecture V2](docs/ARCHITECTURE_V2.md) · [Enterprise Architecture](docs/advanced/enterprise.md) · [Kubernetes Helm Deployment](docs/advanced/kubernetes.md) · [OIDC Identity Binding](docs/advanced/oidc.md) · [SIEM Log Forwarding](docs/advanced/siem.md) · [OWASP ASI Top 10](docs/owasp_agentic_top10.md)
- **Reference:** [CLI Commands](docs/reference/cli.md) · [Configuration & Env Vars](docs/reference/configuration.md) · [Paths & State](docs/reference/paths-and-state.md) · [Troubleshooting](docs/reference/troubleshooting.md) · [Removal & Recovery](docs/reference/removal-and-recovery.md) · [Legacy Alias Migration](docs/reference/legacy-migration.md) · [Release Notes Template](docs/reference/release-notes-template.md) · [Multi-Cloud Terraform](infra/README.md)
