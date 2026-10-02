<div align="center">

# 🛡️ Vexa Agent Control
### *The Zero-Trust AI Security Gateway & MCP Tool Firewall for Engineering Teams*

**Secure AI agent execution, prevent credential exfiltration, enforce deterministic tool & spend policies, and eliminate provider key sprawl.**

[🌐 Website](https://vexasec.io/) · [📖 Documentation Hub](docs/README.md) · [⚡ 2-Minute Quickstart](#-quickstart) · [💻 Workstation Guide](docs/guides/workstation.md) · [🏢 Team Hub Guide](docs/team_hub_guide.md) · [🛡️ OWASP ASI Top 10](docs/owasp_agentic_top10.md)

<br/>

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-6366F1.svg?style=flat-square)](LICENSE)
[![Release Version](https://img.shields.io/badge/Version-1.0.93-10B981.svg?style=flat-square)](Cargo.toml)
[![Rust Core](https://img.shields.io/badge/Engine-Rust%201.80%2B%20(Sub--ms)-F97316.svg?style=flat-square&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Docker Image](https://img.shields.io/badge/Docker-ghcr.io%2Fnoviqtechnologies%2Fagentcontrol-06B6D4.svg?style=flat-square&logo=docker&logoColor=white)](docs/guides/docker-deployment.md)
[![OWASP ASI](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%20(ASI%202026)-8B5CF6.svg?style=flat-square)](docs/owasp_agentic_top10.md)
[![Security Policy](https://img.shields.io/badge/Security-Policy-blue.svg?style=flat-square)](SECURITY.md)

<br/>

<img alt="Vexa Agent Control System Architecture" src="docs/architecture.png" width="100%" />

</div>

---

## 📌 Table of Contents

- [Overview](#-overview)
- [Why Vexa Agent Control](#-why-vexa-agent-control)
- [Key Capabilities](#-key-capabilities)
- [Supported Ecosystem](#-supported-ecosystem)
- [Quickstart](#-quickstart)
  - [Option A: Standalone Developer Workstation (CLI)](#option-a-standalone-developer-workstation-cli)
  - [Option B: Universal LLM Gateway (OpenAI / Python / cURL)](#option-b-universal-llm-gateway-openai--python--curl)
  - [Option C: Team Hub & Web Console (Docker Compose)](#option-c-team-hub--web-console-docker-compose)
  - [Option D: Standalone Docker Proxy](#option-d-standalone-docker-proxy)
- [Architecture & Data Flow](#-architecture--data-flow)
- [Declarative Policy Specification](#-declarative-policy-specification)
- [CLI Reference & Day-to-Day Operations](#-cli-reference--day-to-day-operations)
- [Production & Cloud Deployment](#-production--cloud-deployment)
- [Security, Privacy & Sovereign Independence](#-security-privacy--sovereign-independence)
- [Documentation Index](#-documentation-index)
- [Community & Support](#-community--support)

---

## 💡 Overview

**Vexa Agent Control** is an ultra-fast, open-source security gateway and transparent runtime proxy purpose-built for AI agents, developer IDEs, and enterprise platform teams. It intercepts Model Context Protocol (MCP) and HTTP/LLM communications to provide deterministic safety, secret protection, token economics, and tamper-evident auditability in sub-millisecond execution times.

### Two Flexible Operating Modes:
1. **Workstation Sentry & MCP Firewall:** Runs locally (`127.0.0.1:18080`) as a zero-overhead transparent sidecar. Natively wraps coding assistants (**Cursor**, **Claude Desktop**, **Claude Code**, **Codex**, **Antigravity**, **VS Code**) to enforce parameter sanitization, loop prevention, and secret redacting before any payload leaves the machine.
2. **Centralized Enterprise AI Gateway:** Deploys in your private VPC or cloud cluster to unify upstream model routing (OpenAI, Anthropic, Azure, Google Gemini, Groq, AWS Bedrock, Ollama) behind a single OpenAI-compatible endpoint with virtual key custody, spend caps, and SIEM streaming.

---

## ⚖️ Why Vexa Agent Control

| Vector / Risk | Without Vexa Agent Control | With Vexa Agent Control |
|---|---|---|
| 🛡️ **MCP Tool Execution** | Agents run arbitrary shell commands, destructive filesystem operations, or untrusted network egress. | **Zero-Trust Tool Guard:** Replay classification, strict JSON schema validation, loop counters, and path traversal blockers. |
| 🔒 **Secret & DLP Leaks** | API keys, SSH private keys, and cloud credentials leak directly into third-party LLM training or logs. | **21-Pattern Inline DLP:** High-entropy regex, token scanning, and automatic wire-layer redacting (`[REDACTED:API_KEY]`). |
| 🧠 **Prompt Injections** | Web pages, tool results, or external data hijack the agent system prompt and directive boundaries. | **Deterministic Heuristic Scanner:** Multi-pass pattern detection for system overrides and jailbreaks with ReDoS execution deadlines. |
| ⚡ **Redundant Token Spend** | Paraphrased or repeated prompts repeatedly hit cloud APIs at full cost and 1–2s latency. | **Dual-Tier Semantic Vector Cache:** L1 exact SHA-256 + L2 cosine similarity (sub-3ms lookup, 100% avoided token egress). |
| 💰 **Budget Overruns** | Billing surprises discovered post-run after runaway recursive agent loops. | **Atomic Preflight Spend Reservations:** Microcent budget ceilings, concurrency limits, and exact SSE stream settlement. |
| 👁️ **Audit & Forensics** | Transient terminal output with zero cryptographic proof of agent tool actions or policy verdicts. | **Cryptographic Audit Outbox:** HMAC-SHA256 hash-chained `audit.jsonl` + non-blocking SIEM export (Splunk, Datadog). |
| 🚀 **Runtime Latency** | Bulky multi-container proxies adding 50–200ms of latency per LLM frame. | **Pure Rust Core:** Sub-millisecond internal routing with zero garbage collection pauses. |

---

## 🚀 Key Capabilities

```
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                        Developer IDEs & AI Agents                       │
  │        Cursor · Claude Code · Claude Desktop · Antigravity · Codex      │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       │ Wire / MCP / HTTP Proxy (18080)
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │                 VEXA AGENT CONTROL CORE (Pure Rust Engine)              │
  │  ├─ 🔒 21-Pattern Inline DLP & Credential Redactor                      │
  │  ├─ 🧠 Deterministic Heuristic Prompt Injection Shield                  │
  │  ├─ ⚡ Dual-Tier Semantic Vector Cache (L1 SHA-256 + L2 Cosine Vector)   │
  │  ├─ 🛡️ Zero-Trust MCP Tool Firewall & Path Traversal Validator          │
  │  ├─ 💰 Microcent Spend Ledger & Preflight Budget Reservations           │
  │  └─ 📜 Tamper-Evident HMAC-SHA256 Audit Stream                          │
  └───────────────────┬─────────────────────────────────┬───────────────────┘
                      │                                 │
                      ▼                                 ▼
  ┌───────────────────────────────────────┐ ┌───────────────────────────────┐
  │         Upstream LLM Providers        │ │  Vexa Control Hub (Optional)  │
  │  OpenAI · Anthropic · Azure · Gemini  │ │  PostgreSQL · Web Console     │
  │  Groq · AWS Bedrock · Local / Ollama  │ │  OIDC SSO · Policy Repository │
  └───────────────────────────────────────┘ └───────────────────────────────┘
```

- **Universal OpenAI-Compatible LLM Gateway:** Drop-in routing for `/v1/chat/completions` and `/v1/models`. Translates schemas seamlessly between OpenAI, Anthropic, Gemini, Groq, Bedrock, and Ollama.
- **Transparent Workstation Sentry:** 1-command connection and atomic rollback for local developer assistants with zero manual proxy configuration.
- **Enterprise Semantic Vector Caching:** Built-in L1 exact SHA-256 and L2 vector cosine similarity engine (in-memory or Qdrant) delivering sub-3ms responses and 100% token cost elimination on repeated queries.
- **Fail-Closed Spend Governance:** Enforces microcent rate caps, concurrent connection ceilings, and 500ms upstream cancellation on client disconnects.
- **Tamper-Evident Forensic Dossiers:** Every request and MCP tool action is recorded with cryptographic HMAC-SHA256 verification and device posture attribution.
- **Scoped Virtual Keys:** Issue admin-governed developer tokens with model allowlists, spend caps, and CIDR network boundaries without distributing live provider credentials.

---

## 🔌 Supported Ecosystem

### Upstream LLM Providers

| Provider | Supported Models / Families | Chat Completions | Models API | Streaming SSE | Tool Calling | Spend Ledger |
|---|---|:---:|:---:|:---:|:---:|:---:|
| **OpenAI** | GPT-4o, GPT-4o-mini, o1, o3-mini | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Azure OpenAI** | GPT-4o, Custom Deployments | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Anthropic Claude** | Claude 3.7 Sonnet, Claude 3.5 Haiku, Opus | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Google Gemini** | Gemini 2.0 Flash, Gemini 1.5 Pro | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Groq AI** | Llama 3.3 70B, DeepSeek R1 Distill | ✅ | ✅ | ✅ | ✅ | ✅ |
| **AWS Bedrock** | Claude 3.5 Sonnet, Amazon Nova | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Local / OpenAI-Compatible** | Ollama, vLLM, LM Studio, LocalAI | ✅ | ✅ | ✅ | ✅ | ✅ |

### Supported Coding Assistants & IDEs

| Client / Agent | Interception Method | Completion Traffic | MCP Tool Sandbox | Verified Status |
|---|---|:---:|:---:|:---:|
| **Cursor IDE** | `settings.json` (`http.proxy`) | ✅ Proxied (18080) | ✅ Proxied (18080) | **Verified** |
| **Claude Code (CLI)** | `settings.json` (`ANTHROPIC_BASE_URL`) | ✅ Proxied (18080) | ✅ Proxied (18080) | **Verified** |
| **Claude Desktop** | `claude_desktop_config.json` (`stdio-proxy`) | ℹ️ Direct Cloud | ✅ Sandboxed (18080) | **Verified** |
| **Google Antigravity** | `mcp_config.json` (`proxy_url`) | ✅ Proxied (18080) | ✅ Proxied (18080) | **Verified** |
| **OpenAI Codex CLI** | Shell Wrapper (`codex-intercept.sh`) | ✅ Proxied (18080) | ✅ Proxied (18080) | **Verified** |
| **VS Code (Continue)** | `config.yaml` / `settings.json` | ✅ Proxied (18080) | ✅ Proxied (18080) | **Verified** |
| **Custom Agents (Python/TS)** | `AGENTCONTROL_PROXY_URL=http://127.0.0.1:18080` | ✅ Proxied (18080) | ✅ Proxied (18080) | **Verified** |

---

## ⚡ Quickstart

### Option A: Standalone Developer Workstation (CLI)

Run a complete local MCP firewall, inline DLP secret redaction, and developer dashboard on your machine in under 2 minutes (100% offline, zero cloud dependency, no account required):

#### Step 1: Install the Standalone Binary

**macOS / Linux / WSL (Bash/Zsh):**
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

#### Step 2: Configure Upstream Model Provider & Start Gateway

Set your upstream LLM provider API key (or point to local models like Ollama/LM Studio):

**PowerShell (Windows):**
```powershell
$env:OPENAI_API_KEY = "sk-proj-..."
# or: $env:ANTHROPIC_API_KEY = "sk-ant-..."
agentcontrol.exe start
```

**Bash / Zsh (macOS / Linux):**
```bash
export OPENAI_API_KEY="sk-proj-..."
# or: export ANTHROPIC_API_KEY="sk-ant-..."
agentcontrol start
```

*(Alternatively, add `OPENAI_API_KEY=sk-proj-...` to a `.env` file in your working directory, or run local engines like Ollama on `http://localhost:11434` / LM Studio).*

> [!NOTE]
> Keep this terminal open or run it as a service. The proxy actively intercepts local tool calls, enforces DLP & prompt security, and serves the developer dashboard on loopback (`http://127.0.0.1:18080`).

#### Step 3: Open the Local Developer Dashboard

Open your web browser and navigate to:
👉 **[http://127.0.0.1:18080](http://127.0.0.1:18080)**

You will see the **"This Device"** dashboard displaying active listener health, loaded DLP patterns, and an event feed waiting for agent traffic.

#### Step 4: Connect Your AI Coding Assistant

In a **new terminal window**, connect the AI coding assistant(s) installed on your machine:

```bash
# Connect Cursor IDE:
agentcontrol connect cursor

# Or connect Claude Desktop / Claude Code:
agentcontrol connect claude

# Or connect OpenAI Codex / VS Code Continue:
agentcontrol connect codex
```

*What happens behind the scenes:* Agent Control writes a safe, cryptographically hashed ownership manifest (`~/.agentcontrol/manifests/<client>.manifest.json`) and points your IDE's MCP and LLM routing to `127.0.0.1:18080`.

#### Step 5: Verify Active Posture & Live Telemetry

1. Check your connected assistants and gateway health:
```bash
agentcontrol status     # Inspect target capability vectors & LLM routing
agentcontrol clients    # List all detected vs protected clients
agentcontrol doctor     # Run read-only diagnostic checks (returns 0 if healthy)
```
2. Now, prompt your AI assistant in Cursor, Claude, or Codex. Watch prompts, token counts, and DLP redactions immediately stream live across your open dashboard at `http://127.0.0.1:18080`!

#### Step 6: Non-Destructive Disconnect & Cleanup

Whenever you wish to return your IDE configurations to their pristine original state:

```bash
# Cleanly restore original client configurations anytime:
agentcontrol disconnect cursor
agentcontrol disconnect claude
```

---

### Option B: Universal LLM Gateway (OpenAI / Python / cURL)

Point your existing OpenAI SDK client directly to Vexa Agent Control to gain automatic DLP scanning, spend caps, and semantic vector caching:

#### Python Example
```python
from openai import OpenAI

# Point client to Vexa Agent Control Gateway
client = OpenAI(
    base_url="http://localhost:18080/v1",
    api_key="your-vexa-virtual-key" # or provider key in local_compat mode
)

response = client.chat.completions.create(
    model="anthropic/claude-3-7-sonnet-20250219", # Auto-translated & routed
    messages=[
        {"role": "system", "content": "You are a secure coding assistant."},
        {"role": "user", "content": "Scan this repository for security risks."}
    ],
    temperature=0.2,
    stream=True
)

for chunk in response:
    content = chunk.choices[0].delta.content
    if content:
        print(content, end="", flush=True)
```

#### cURL Example
```bash
curl -X POST http://localhost:18080/v1/chat/completions \
  -H "Authorization: Bearer your-vexa-virtual-key" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "openai/gpt-4o",
    "messages": [{"role": "user", "content": "Review authorization policies."}],
    "temperature": 0.0
  }'
```

---

### Option C: Team Hub & Web Console (Docker Compose)

Deploy the complete centralized control plane (PostgreSQL, Go Control Plane API, React Management Console, and Security Gateway):

```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control

# Configure local environment
cp .env.team.example .env

# Launch full team stack
docker compose -f docker-compose.team.yml up -d
```

| Service | Endpoint | Description |
|---|---|---|
| **Web Console UI** | `http://localhost:18300` | Guardrail presets, model gateways, cost & budgets, audit logs |
| **Control Plane API** | `http://localhost:18081` | Policy distribution, enrollment, audit checkpoint API |
| **Security Gateway** | `http://localhost:18080` | High-throughput Rust LLM and MCP proxy |

#### Developer Workstation Enrollment to Team Hub:
```bash
# Authenticate workstation via browser SSO and enroll machine identity with the Hub:
agentcontrol login --hub http://localhost:18081
agentcontrol connect cursor
```

---

### Option D: Standalone Docker Proxy

Run a zero-dependency, non-root (UID 10001) proxy bound strictly to loopback (`127.0.0.1:18080`):

```bash
docker compose -f docker-compose.standalone.yml up -d
```

---

## 🏛️ Architecture & Data Flow

Vexa Agent Control operates across 4 coordinated architectural layers:

1. **Edge Execution Plane (Developer Workstation):**
   - Background daemon listens on loopback (`127.0.0.1:18080`).
   - Stdio process sandbox enforces memory RSS ceilings (< 64MB) on child MCP servers.
   - Authoritative ownership manifests guarantee 100% reversible client configuration changes.
2. **Gateway Broker Plane (Rust Proxy Core):**
   - High-throughput asynchronous Hyper 1.0 engine with sub-millisecond evaluation overhead.
   - Dual-tier semantic vector cache resolves frequent queries locally in ~2.4ms.
   - Fail-closed atomic spend reservation engine.
3. **Control & Governance Plane (Team Control Hub):**
   - Multi-tenant PostgreSQL datastore with BSD Valkey distributed state.
   - OIDC identity binding (Google Workspace, Microsoft Entra ID, Okta, Auth0, Keycloak).
   - Cryptographically signed Ed25519 policy distributions.
4. **Audit & Analytics Plane:**
   - Sequential HMAC-SHA256 hash-chained tamper-evident audit ledger (`audit.jsonl`).
   - Asynchronous fanout to enterprise SIEM platforms (Splunk HEC, Datadog).

---

## 📜 Declarative Policy Specification

Policies are defined in standard GitOps-friendly YAML (`agentcontrol-policy.yaml`):

```yaml
version: "2"
default_action: deny

# LLM Provider Controls & Whitelisting
llm:
  providers:
    - name: "openai"
      action: "allow"
      models: ["gpt-4o*", "o1*", "o3*"]
      max_tokens_per_request: 4096
    - name: "anthropic"
      action: "allow"
      models: ["claude-3-7*", "claude-3-5*"]
  
  # Inline Data Loss Prevention
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

  # Enterprise Semantic Vector Caching
  semantic_cache:
    enabled: true
    similarity_threshold: 0.88
    backend: "in_memory" # "in_memory" | "qdrant"
    embedder:
      engine: "local"

# Microcent Budget Governance
spend_caps:
  enabled: true
  concurrency_ceiling: 50
  max_tokens_per_session: 100000

# MCP Tool Sandboxing & Path Traversal Guards
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

---

## 🖥️ Unified UI Experience Across Workstation & Fleet

Vexa Agent Control provides a seamless, unified governance interface designed for two distinct scopes:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                 VEXA AGENT CONTROL UI                                  │
├───────────────────────────────────────────┬────────────────────────────────────────────┤
│ 💻 THIS DEVICE (`127.0.0.1:18080`)        │ 🏢 TEAM HUB (`localhost:18300` / Cloud)    │
│ • Local Workstation Developer Dashboard   │ • Multi-Workstation Fleet Governance       │
│ • Zero External Dependencies (Embedded)   │ • Organization SSO & Policy Distribution   │
│ • Live SSE Traffic & DLP Redactions       │ • Global Spend Caps & Virtual Key Vault    │
│ • Interactive HITL Approval Prompts       │ • Multi-Agent Audits & SIEM Export         │
│ • Client Connection & Port Posture        │ • Centralized SOC 2 / ISO 27001 Dossiers   │
└───────────────────────────────────────────┴────────────────────────────────────────────┘
```

---

## 🛠️ Complete CLI Reference & Operations

The `agentcontrol` CLI conforms strictly to PRD §12, providing deterministic, cross-platform lifecycle commands:

| Command | Arguments / Flags | Description |
|---|---|---|
| `agentcontrol start` | `[--listen <addr>] [--centralized]` | Launch local security gateway proxy daemon (`127.0.0.1:18080`) |
| `agentcontrol stop` | `[--gateway <url>]` | Gracefully shut down active local gateway proxy |
| `agentcontrol status` | `[--json]` | Display active target capability vectors, MCP routing, and traffic freshness |
| `agentcontrol clients` | `[--json]` | List detected, connected, and protected IDE clients and MCP runtimes |
| `agentcontrol connect <target>` | `[--mode local\|cloud-direct] [--key <k>]` | Connect an IDE assistant (Cursor, Claude, Codex, Antigravity, VS Code) |
| `agentcontrol disconnect <target>` | — | Non-destructively disconnect an assistant and restore original configs |
| `agentcontrol policy init` | `[-o <file>]` | Generate standard baseline security policy YAML |
| `agentcontrol policy validate` | `[-p <file>]` | Validate policy YAML schema and security invariants |
| `agentcontrol policy show` | `[--json]` | Inspect active effective policy rules (secrets automatically redacted) |
| `agentcontrol policy test` | `[--policy <p>] [--dry-run]` | Test synthetic fixtures or calls against active policy |
| `agentcontrol doctor` | `[--json]` | Read-only diagnostic health check (0: healthy, 1: critical, 2: degraded) |
| `agentcontrol logs` | `[-n <limit>] [-f] [--format text\|json]` | Query or live-stream local audit events and security decisions |
| `agentcontrol approve <id>` | `[--session]` | Approve a pending Human-in-the-Loop (HITL) action request |
| `agentcontrol deny <id>` | — | Deny a pending Human-in-the-Loop (HITL) action request |
| `agentcontrol login` | `[--hub <url>]` | Authenticate via browser PKCE and enroll machine identity with Team Hub |
| `agentcontrol logout` | — | Clear local session tokens and return to standalone offline mode |
| `agentcontrol unenroll` | `[--force]` | Disconnect device from Control Hub and clear local identity state |
| `agentcontrol verify` | `[--json]` | Run live 4-point security verification probe against gateway |
| `agentcontrol scan` | `[--path <file>] [--format text\|json]` | Scan local MCP server configurations and tool definitions for vulnerabilities |
| `agentcontrol cache` | `status \| clear` | Manage semantic vector cache, tokens saved, and prompt economics |
| `agentcontrol spend` | `status \| set-cap \| export` | Enforce FinOps microcent rate caps, budgets, and token accounting |
| `agentcontrol support-bundle` | `[--output-dir <dir>] [-y]` | Generate sanitized, secret-redacted diagnostic bundle (< 10MB) |
| `agentcontrol verify-db` | — | Verify SQLite integrity and cryptographic HMAC-SHA256 audit log chain |

---

## ☁️ Production & Cloud Deployment

Deploy Vexa Agent Control to your production infrastructure using enterprise-grade infrastructure-as-code:

### 1. Kubernetes (Helm Chart)
Deploy scalable gateway pods with sidecar injection and native Horizontal Pod Autoscaling:
```bash
helm repo add vexa https://charts.vexasec.io
helm install agentcontrol ./chart -f values.yaml
```
[**Read the Kubernetes Guide →**](chart/README.md)

### 2. Multi-Cloud OpenTofu / Terraform
Production blueprints with ~$0–$25/mo baseline cost:
- **AWS ECS Fargate:** Spot task execution, ALB, AWS Secrets Manager ([`infra/aws`](infra/README.md))
- **Azure Container Apps:** Scale-to-zero microservices with built-in Envoy ingress ([`infra/azure`](infra/README.md))
- **Google Cloud Run (v2):** Multi-container revisions with Secret Manager integration ([`infra/gcp`](infra/README.md))

---

## 🔒 Security, Privacy & Sovereign Independence

- **100% Free & Open-Source Core:** Released under the permissive **[Apache 2.0 License](LICENSE)**.
- **Zero Telemetry Guarantee:** Absolutely no tracking pings, metrics exfiltration, or cloud phone-home in standalone mode. Your prompts, code, and credentials remain 100% within your perimeter.
- **Zero Private Key Ingestion:** Workstations generate Ed25519 device keypairs locally in OS hardware/secure storage (DPAPI/Keychain). Private keys never leave the host.
- **Cryptographic Audit Chain:** Every single log entry in `audit.jsonl` is linked via HMAC-SHA256 hash chaining to guarantee tamper-evidence.
- **Continuity Guarantee:** Read our [Continuity & Sovereign Guarantee](docs/CONTINUITY_GUARANTEE.md) detailing why your team will never be stranded or locked in.

---

## 📚 Documentation Index

Explore the complete [Documentation Hub](docs/README.md):

- **Getting Started:** [10-Minute Developer Quickstart](docs/quickstart.md) · [Workstation Guide](docs/guides/workstation.md) · [Docker Deployment](docs/guides/docker-deployment.md)
- **Integration Guides:** [Integrations Matrix](docs/integrations/README.md) · [Cursor](docs/integrations/cursor.md) · [Claude Desktop](docs/integrations/claude-desktop.md) · [Claude Code](docs/integrations/claude-desktop.md) · [Antigravity](docs/integrations/antigravity.md) · [Codex](docs/integrations/codex.md) · [Custom Python/TS Agents](docs/guides/custom-agent-http.md)
- **Enterprise & Governance:** [Team Hub Guide](docs/team_hub_guide.md) · [Organization Admin & Virtual Keys](docs/organization_admin_guide.md) · [OIDC Identity Binding](docs/advanced/oidc.md) · [SIEM Forwarding](docs/advanced/siem.md) · [Kubernetes Helm](docs/advanced/kubernetes.md)
- **Technical Reference:** [CLI Commands](docs/reference/cli.md) · [Policy Configuration](docs/reference/configuration.md) · [Semantic Cache Specification](docs/reference/semantic-cache-methodology.md) · [Audit Threat Model](docs/security/audit-threat-model.md) · [Troubleshooting](docs/reference/troubleshooting.md)

---

## 💬 Community & Support

- 💬 **Discord:** [Join the Vexa Community](https://discord.gg/vexasec)
- 🐞 **GitHub Issues:** [Report Bugs & Request Features](https://github.com/noviqtechnologies/Vexa-Agent-Control/issues)
- 🔒 **Security Advisories:** [SECURITY.md](SECURITY.md) · [Report Vulnerability](https://github.com/noviqtechnologies/Vexa-Agent-Control/security/advisories/new)
- 🏢 **Enterprise Inquiries:** [contact@vexasec.io](mailto:contact@vexasec.io) · [vexasec.io](https://vexasec.io)
