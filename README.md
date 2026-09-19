<div align="center">

# 🛡️ Vexa Agent Control
### *The Open-Source AI Safety Layer & Zero-Trust MCP Governance Gateway*

**Let your team build & use AI agents — without leaking secrets, losing control, or blowing budgets.**

[🌐 Website](https://vexasec.io/) · [📖 Documentation Hub](docs/README.md) · [⚡ Docker Quickstart](#docker-quickstart-2-minutes) · [💻 Workstation Quickstart](#10-minute-workstation-quickstart) · [☸️ Helm Chart](chart/README.md) · [🛡️ OWASP ASI Top 10](docs/owasp_agentic_top10.md)

<br/>

[![Website](https://img.shields.io/badge/Website-vexasec.io-7C3AED.svg?style=flat-square&logo=google-chrome&logoColor=white)](https://vexasec.io/)
[![Open Source License](https://img.shields.io/badge/License-Apache%202.0-6366F1.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.87-10B981.svg?style=flat-square)](Cargo.toml)
[![Changelog](https://img.shields.io/badge/Changelog-SemVer%202.0-blueviolet.svg?style=flat-square)](CHANGELOG.md)
[![Security Policy](https://img.shields.io/badge/Security-Policy-blue.svg?style=flat-square)](SECURITY.md)
[![Contributing](https://img.shields.io/badge/PRs-Welcome-brightgreen.svg?style=flat-square)](CONTRIBUTING.md)
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
  - [6. Pluggable Routing Engine & Pipeline Hooks](#6-pluggable-routing-engine--pipeline-hooks)
  - [7. Enterprise Semantic Vector Caching](#7-enterprise-semantic-vector-caching)
  - [8. Desired-State Routing & Verification Probe](#8-desired-state-routing--verification-probe)
  - [9. Control Hub v2 Architecture & Multi-State Observability](#9-control-hub-v2-architecture--multi-state-observability)
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
| 🧠 **Prompt Injection Defense** | Untrusted web data or tool responses hijack the agent's system prompt and instructions. | **Deterministic Heuristic Injection Scanner:** Multi-category pattern detection for jailbreaks, covert directives, credential solicitation, and instruction boundary overrides with ReDoS execution deadlines. |
| ⚡ **Redundant Token Spend** | Repetitive or paraphrased prompts hit cloud providers every time, paying full token rates, suffering 1-2s latency, and egressing data over the WAN. | **Dual-Tier Semantic Vector Cache:** L1 exact SHA-256 hash + L2 vector cosine similarity (partitioned in-memory cosine-similarity cache with optional Qdrant integration). Cuts token costs on allowlisted read-only workloads with 100% zero-egress cost elimination and sub-3ms response. |
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
    base_url="http://localhost:18080/v1",
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
curl -X POST http://localhost:18080/v1/chat/completions \
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

### Zero-Touch Workstation Quickstart
```bash
# 1. Authenticate your workstation via browser OAuth PKCE:
agentcontrol login

# 2. Connect your installed coding assistants:
agentcontrol connect codex
agentcontrol connect claude

# 3. Check health and multi-state status:
agentcontrol status
agentcontrol doctor
```

### Automated 4-Point Live Verification Suite
Test that DLP exfiltration blocks, prompt-injection filters, and workstation IDE client interception are active:

```bash
agentcontrol verify
```

**Expected Live Probe Output:**
```text
✔ [1/4] Safe Tool Execution (read_file)         ➔ POLICY ALLOWED
✔ [2/4] DLP Exfiltration Guard (AWS Secret)    ➔ BLOCKED [DLP-01-HIGH-ENTROPY]
✔ [3/4] Prompt Injection (System Override)     ➔ BLOCKED [INJ-04-OVERRIDE]
✔ [4/4] Workstation Client Sentry (IDE Config)  ➔ PROTECTED
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

  # Model Groups with Pluggable Routing (AR-2)
  model_groups:
    - name: "production-chat"
      routing_strategy: "lowest_latency" # priority | lowest_latency | weighted_random | region_affinity
      allowed_regions: ["us-east-1", "eu-central-1"]
      deployments:
        - id: "openai-primary"
          provider: "openai"
          model_name: "gpt-4o"
          endpoint_url: "https://api.openai.com/v1"
          priority: 1
          weight: 80
        - id: "azure-failover"
          provider: "azure"
          model_name: "gpt-4o"
          endpoint_url: "https://my-eu.openai.azure.com"
          priority: 2
          weight: 20

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

- **GitOps Policy Precedence (Central Ceiling):** Centralized policies define hard ceiling boundaries. Repository-local `.agentcontrol.yaml` policies can only tighten rules, never loosen or bypass Central permissions.
- **4-Tier Client & Project Attribution:** Attributions (`client_id`, `project_id`, `cost_center`) resolve with strict precedence: `HTTP Header > Env Var > GitOps Policy YAML > Fallback ("default")`, with automated slug sanitization and Central Tenant Boundary Locks.
- **Zero-Payload Privacy by Default:** Local SQLite databases only persist SHA-256 hashes of prompts/responses by default. Raw bodies are recorded only when explicitly opting in via `--record-payloads`.
- **Autonomous Local Spend CLI & Invoicing Exports:**
  ```bash
  # Check local spend & active budget caps
  agentcontrol spend status --agent-id alice

  # Export invoice-ready token accounting records to CSV or JSON
  agentcontrol spend export --format=csv --client=acme_corp --output=./invoices/spend_acme.csv

  # Configure local agent daily, weekly, or monthly budget cap
  agentcontrol spend set-cap --agent-id alice --cap-cents 500 --period daily
  ```
- **Atomic Preflight Reservations:** Pre-reserves max-token microcents in memory before upstream dispatch.
- **Exact SSE Stream Settlement:** Calculates actual prompt and completion tokens upon stream finish and settles balance.

[**Read the Spend & Budgets Guide →**](docs/spend_budgets_testing_guide.md) · [**GitOps Policy Precedence Guide →**](docs/user-guide/gitops-policy-precedence.md)

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

<details>
<summary><b>6. Pluggable Routing Engine & Pipeline Hooks</b> — Dynamic Model Groups & Modular Lifecycle Interception</summary>

Tailor request routing and wire-level transformations to meet rigorous latency, cost, and data residency standards.

### Pluggable Upstream Routing Strategies (AR-2)
Model groups support 4 dynamic selection strategies:
* **`priority` (Default):** Deterministic failover based on ascending deployment priority with health check circuit breakers.
* **`lowest_latency`:** Automatically dispatches incoming requests to the deployment exhibiting the lowest rolling exponential moving average (EMA) response latency.
* **`weighted_random`:** Proportional distribution based on configured traffic weights (e.g. 80% primary, 20% canary).
* **`region_affinity`:** Strict sovereign data residency compliance. Evaluates authoritative typed deployment `region` metadata (with strict delimiter-bounded fallback) and fails closed immediately (HTTP 503 `routing_policy_violation`) if the target deployment resides in an unapproved jurisdiction.

### Extensible Pipeline Hook Lifecycle & Unified Scanners (AR-1)
Intercept and mutate traffic at each processing phase across both raw HTTP and structured MCP tool calls:
* **`PreRoute` Stage:** Intercept raw HTTP requests, inject custom audit headers, and redact wire payloads.
* **`PreExecute` Stage:** Inspect structured MCP tool calls (`serde_json::Value`), enforcing in-place parameter redaction (`ModifyJson`) or blocking dangerous actions (`Block`).
* **`PostExecute` Stage:** Inspect downstream response chunks and streaming SSE token frames (`ModifyBytes`) to prevent data exfiltration.
* **`SharedScanners` Construction:** Security detectors (SafeMode, DLP, Prompt Injection, Schema Drift) are compiled once at gateway startup inside a unified `SharedScanners` suite, eliminating duplicate RegexSet compilations across proxy handlers and pipeline hooks.

### High-Throughput Asynchronous Control Plane (AR-3, AR-4, AR-5)
* **`SpendEventWriter`:** Bounded in-memory event buffer with PostgreSQL batch ingestion (`pgx.Batch`), exponential backoff retry on transient errors, in-memory replay buffer, graceful shutdown draining, and backpressure shed protection. Production-wired directly to transactional `Store.Authorize`, `Store.Settle`, and `Store.Release` commit flows.
* **Centralized `Scheduler`:** Deterministic background daemon managing periodic database sweeps (e.g. expiring stale reservation holds, stale assignment convergence) with authenticated live introspection at `/internal/jobs`.

</details>

<details open>
<summary><b>7. Enterprise Semantic Vector Caching</b> — 100% Zero-Egress Cost Elimination &amp; Sub-3ms Retrieval</summary>

LiteLLM and native cloud providers rely on exact string prefix hashes. If a developer or automated agent asks *"how to sort numbers in python"* vs *"in python how to sort a list of numbers"*, traditional prompt caches miss completely—incurring full token rates, 1-2 second WAN latency, and egressing sensitive prompts.

Vexa Agent Control features a **Dual-Tier Semantic Vector Caching Engine** baked directly into its Rust core:
1. **Tier 1 (L1 Exact Hash):** Instant SHA-256 hash lookup in local memory (`< 0.1ms`).
2. **Tier 2 (L2 Semantic Vector Similarity):** L2-normalized cosine similarity vector search across partitioned in-memory vector stores or optional **Qdrant**-backed vector storage (`~2.4ms`).

```
                    ┌──────────────────────────────────────────────┐
                    │       Incoming Agent Prompt Query            │
                    └──────────────────────┬───────────────────────┘
                                           │
                        ┌──────────────────┴──────────────────┐
                        ▼                                     ▼
             [ L1: Exact SHA-256 Hash ]             [ L2: Vector Embedder ]
              Matches identical prompt?             (OpenAI / Ollama / Local)
                        │                                     │
                 Yes ───┼─── No                        Cosine Similarity
                        │       │                     ≥ Threshold (e.g. 0.88)?
                        │       ▼                             │
                        │   Compute Vector ───────────────────┼─── Yes
                        │                                     │      │
                        ▼                                     ▼      ▼
        ┌───────────────────────────────────────────────────────────────┐
        │  ⚡ 100% Vexa Gateway Cache HIT (Sub-3ms Serving)             │
        │  • 100% Input + 100% Output Tokens Avoided ($0.00 Billed)     │
        │  • 0 Bytes WAN Network Egress (Zero Data Exfiltration)        │
        │  • Header: X-AgentControl-Cache: HIT-SEMANTIC (sim: 0.94)    │
        └───────────────────────────────────────────────────────────────┘
```

### Gateway Semantic Cache vs. Provider Prompt Cache

| Evaluation Dimension | ⚡ Vexa Gateway Semantic Cache | 🌐 Provider Prompt Cache (Anthropic/OpenAI) |
|---|---|---|
| **Matching Algorithm** | Vector Cosine Similarity (threshold ≥ 0.88) + SHA256 Exact | Strict exact prefix text hash |
| **Token Cost Avoidance** | **100% Input + 100% Output** ($0.00 billed) | ~50–90% Input discount only (100% output billed) |
| **Network Egress & Latency** | **~2.4ms** (0 bytes egress, resolved locally) | ~450ms – 1,200ms (Full prompt sent over WAN) |
| **Model Portability** | Universal across OpenAI, Anthropic, Ollama, DeepSeek | Vendor locked to single provider |
| **Storage Engine** | Partitioned in-memory vector store + Optional remote Qdrant cluster | Ephemeral provider cache (5 min to 1 hr TTL) |

### Policy Configuration (`agentcontrol.yaml`)

```yaml
llm:
  semantic_cache:
    enabled: true
    similarity_threshold: 0.88        # Cosine similarity cutoff (0.0 to 1.0)
    max_entries: 10000                # In-memory capacity
    ttl_seconds: 86400                # Max cache entry retention (workload-configurable)
    backend: "in_memory"              # "in_memory" | "qdrant" | "hybrid"
    embedder:
      engine: "local"                 # "local" (deterministic 384-dim baseline) | "openai" | "ollama"
      model: "text-embedding-3-small"
```

### CLI Cache Controls & Live Status

```bash
# Check hit rate, tokens avoided, and total cost savings
agentcontrol cache status

# Purge cache entries across memory and Qdrant clusters
agentcontrol cache clear
```

### Developer Dashboard Telemetry

Open `http://localhost:18080/dashboard` and navigate to **Token Economics & Cache**:
- **3 Hero Metric Cards:** Explicitly visualizes Vexa Gateway 100% Avoided Spend vs. Provider-side prefix discounts.
- **Proportional Attribution Bar:** Live percentage split showing direct gateway savings vs upstream provider discounts.
- **Live Semantic Cluster Inspector:** Inspects incoming queries and cached clusters side-by-side with exact cosine similarity scores and per-query dollar savings.

- [**Read the Semantic Caching Methodology & Economics Specification →**](docs/reference/semantic-cache-methodology.md)
- [**Read the Localhost Proxy Bypass & Boundary Model Specification →**](docs/security/direct-proxy-bypass-model.md)
- [**Read the Observability & Forensics Guide →**](docs/user-guide/observability-and-forensics.md#3-dual-tier-token-economics--enterprise-semantic-vector-caching)

</details>

<details>
<summary><b>8. Desired-State Routing & Verification Probe</b> — Convergence Reconciler & Attributed Governance</summary>

Replace fragile fire-and-forget push channels with a formal 9-state desired-state reconciler and authenticated identity verification:

- **State Machine Lifecycle:** Assignments transition deterministically: `desired` → `eligible` → `delivered` → `applied` → `verified` (with explicit `stale`, `failed`, `revoked`, and `rolled_back` safety states).
- **Hybrid Push / Pull Model:** Real-time SSE push for instant in-memory key hot-swapping backed by a 60-second pull reconciler ensuring eventual consistency across sleep/wake and offline cycles.
- **Two-Tier Identity (REQ-VER-002):** Cryptographically distinguishes IdP-verified users (`oidc`) from unverified local machine identities (`local_os`).
- **5-Point Verification Probe (REQ-VER-004):**
  ```bash
  # Assert effective routing, injection safety, DLP redaction, and Hub identity correlation
  agentcontrol verify --gateway http://127.0.0.1:18080 --hub https://console.vexasec.io --user-id $(whoami)
  ```
- **Correlated Request Attribution (REQ-VER-008):** Centralized broker permanently stamps every routed LLM request with authenticated device ID, user ID, active assignment hash, and token usage metrics.

[**Read the Desired-State & Verification Guide →**](docs/user_guide.md#17-desired-state-routing--verification-architecture)

</details>

<details>
<summary><b>9. Control Hub v2 Architecture & Multi-State Observability</b> — Zero Private Key Ingestion & Signed Policy Manifests</summary>

The enterprise Control Hub v2 provides centralized governance, multi-state capability tracking, and signed policy distributions without ever ingesting private keys:

- **Zero Private Key Ingestion:** Workstations generate local Ed25519 keypairs within OS secure storage (DPAPI/Keychain). Only raw public key bytes are registered via `/api/v2/devices/enroll`.
- **Signed Device Assertions (`X-Device-Authorization`):** Workstation daemons sign every gateway transaction using short-lived (300s) Ed25519 assertions with sliding 5-minute replay nonce deduplication (`jti`).
- **Multi-State Capability Vectors:** Replaces binary compliance with verified operational states: `CONFIGURED` (proxy locked), `MCP_WRAPPED` (tools routed), and `TRAFFIC_VERIFIED` (attested transactions).
- **Freshness Tiers:** Continuous liveness tracking categorized into `ACTIVE_FRESH` (≤ 15m), `ACTIVE_RECENT` (≤ 24h), and `STALE` (&gt; 24h).
- **Cryptographically Signed Effective Policies:** Control Hub distributes canonical JSON policy manifests signed with an Ed25519 authority key (`GET /api/v2/policy/effective`).
- **Cryptographic Audit Checkpoints:** Telemetry events are sequentially hash-chained (`event_hash` / `prev_event_hash`) and sealed into verifiable checkpoints (`GET /api/v2/audit/checkpoints`).

[**Read the Control Hub v2 API Reference →**](docs/guides/control_hub_api_guide.md) · [**SOC Web Console User Guide →**](docs/guides/web_console_user_guide.md)

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

Choose the setup that matches your goal:

### 🌟 Option 1: Full-Stack Control Hub with Web UI (Recommended for Team Hub Evaluation)

*Best for exploring the complete team platform: visual policy editor, audit logs, PostgreSQL storage, and real-time React web console.*

**macOS / Linux / WSL (Bash / Zsh):**
```bash
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
cp .env.team.example .env
docker compose -f docker-compose.team.yml up -d
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
Copy-Item .env.team.example .env
docker compose -f docker-compose.team.yml up -d
```

**Windows (Command Prompt - CMD):**
```cmd
git clone https://github.com/noviqtechnologies/Vexa-Agent-Control.git
cd Vexa-Agent-Control
copy .env.team.example .env
docker compose -f docker-compose.team.yml up -d
```

- **Web Management Console UI:** Open [http://localhost:3000](http://localhost:3000) (Sign in with your configured administrator credentials set via `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env`)
- **Control Plane API:** `http://localhost:8085` (internal port 8081)
- **Security Gateway Endpoint:** `http://localhost:8080`
- **Pre-enrolled Evaluation Gateway:** The bundled gateway automatically registers as `vexa-demo-gateway` in **Device Governance** as an active evaluation node. To enroll your host machine / IDEs, click **`+ Generate Enrollment Token`** in the UI.
- Read the complete [Docker Deployment Guide](docs/guides/docker-deployment.md).

---

### ⚡ Option 2: Headless Security Proxy (`docker run`)

*Best for lightweight background proxying (~7MB RAM) of IDE MCP tools and LLM traffic on port `8080`.*

**Windows (PowerShell):**
```powershell
docker run -d `
  --name agentcontrol `
  -p 8080:8080 `
  -v agentcontrol-data:/app/data `
  -v agentcontrol-logs:/var/log/agentcontrol `
  -e AGENTCONTROL_ADMIN_TOKEN="admin123456" `
  ghcr.io/noviqtechnologies/agentcontrol:latest `
  start --listen 0.0.0.0:8080
```

**Windows (Command Prompt - CMD):**
```cmd
docker run -d ^
  --name agentcontrol ^
  -p 8080:8080 ^
  -v agentcontrol-data:/app/data ^
  -v agentcontrol-logs:/var/log/agentcontrol ^
  -e AGENTCONTROL_ADMIN_TOKEN="admin123456" ^
  ghcr.io/noviqtechnologies/agentcontrol:latest ^
  start --listen 0.0.0.0:8080
```

**macOS / Linux / WSL (Bash / Zsh):**
```bash
docker run -d \
  --name agentcontrol \
  -p 8080:8080 \
  -v agentcontrol-data:/app/data \
  -v agentcontrol-logs:/var/log/agentcontrol \
  -e AGENTCONTROL_ADMIN_TOKEN="admin123456" \
  ghcr.io/noviqtechnologies/agentcontrol:latest \
  start --listen 0.0.0.0:8080
```

#### Verifying the Headless Gateway

1. **Check Status:**
   ```bash
   docker ps --filter "name=agentcontrol"
   ```
   *(Status should show `Up ... (healthy)` on `0.0.0.0:8080->8080/tcp`)*

2. **Test Admin API:**
   - **Windows (PowerShell):** `curl.exe -s -H "Authorization: Bearer admin123456" http://localhost:8080/`
   - **macOS / Linux / WSL:** `curl -s -H "Authorization: Bearer admin123456" http://localhost:8080/`
   - **Windows (CMD):** `curl -s -H "Authorization: Bearer admin123456" http://localhost:8080/`

3. **Stream Live Logs:**
   ```bash
   docker logs -f agentcontrol
   ```

---

## 10-Minute Workstation Quickstart

This quickstart is designed for individual software developers to experience Vexa Agent Control directly on their local workstation. **Zero Docker, zero external databases, and zero Control Hub required** — everything runs locally via a single statically-linked binary with an embedded developer web dashboard.

---

### Step 0: Preflight Check

Confirm your local architecture and verify port `18080` is available:

```bash
# macOS / Linux / WSL
uname -m && netstat -an | grep 18080 || echo "Port 18080 is available"
```

```powershell
# Windows (PowerShell)
$env:PROCESSOR_ARCHITECTURE; Get-NetTCPConnection -LocalPort 18080 -ErrorAction SilentlyContinue
```

---

### Step 1: Install Vexa Agent Control Binary

Download and install the standalone binary to `~/.local/bin` (or `%USERPROFILE%\.local\bin` on Windows):

**macOS / Linux / WSL (Bash / Zsh):**
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

**Windows (Command Prompt - CMD):**
```cmd
curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 -o "%TEMP%\install.ps1" && powershell.exe -ExecutionPolicy Bypass -File "%TEMP%\install.ps1" && del "%TEMP%\install.ps1"
set PATH=%USERPROFILE%\.local\bin;%PATH%
agentcontrol.exe --version
```

- **Expected Result:** Prints `agentcontrol 1.0.87` (or current release).

---

### Step 2: Start the Local Security Gateway (`agentcontrol start`)

Launch the local security gateway and governance proxy on your workstation:

```bash
agentcontrol start
```

- **What happens automatically:**
  - Binds locally to `127.0.0.1:18080` (or dynamic fallback `18080..=18090` written to `~/.agentcontrol/daemon.port`).
  - Initializes a high-entropy local bearer token in `~/.agentcontrol/local.token` (restricted with POSIX `0600` / Windows ACL permissions).
  - Initializes the embedded SQLite audit engine at `~/.agentcontrol/events.db` in Write-Ahead Logging (WAL) mode.
  - Serves the **embedded Local Developer Dashboard** directly at `http://127.0.0.1:18080`.

*(To connect to a Control Hub and register a persistent background daemon, run `agentcontrol login --hub <url>`. This handles PKCE authentication, device enrollment, and service installation in one step.)*

---

### Step 3: Connect Your Coding Assistants (`agentcontrol connect <target>`)

In a new terminal window, connect your installed coding assistants with non-destructive ownership tracking:

```bash
# Connect OpenAI Codex CLI:
agentcontrol connect codex

# Connect Anthropic Claude Desktop (MCP tool governance):
agentcontrol connect claude

# Connect Anthropic Claude Code CLI (full LLM completion + spend governance):
agentcontrol connect claude-code

# Connect Cursor IDE:
agentcontrol connect cursor

# Connect Google Antigravity IDE:
agentcontrol connect antigravity

# Connect VS Code Continue extension:
agentcontrol connect vscode-continue
```

#### Client Governance & Support Matrix

| Client / Agent | LLM Routing & Spend Caps | MCP Tool Interception | Virtual Key Custody | Governance Layer |
| :--- | :---: | :---: | :---: | :--- |
| **OpenAI Codex CLI** | ✅ Full | ✅ Full | ✅ Injected (`auth.json`) | `config.toml` (`openai_base_url`) |
| **Anthropic Claude Code (CLI)** | ✅ Full | ✅ Full | ✅ Injected (`settings.json`) | `~/.claude/settings.json` (`env.ANTHROPIC_BASE_URL`) |
| **Cursor IDE** | ✅ Full | ✅ Full | ✅ Injected (`settings.json`) | `settings.json` (`http.proxy`) |
| **Google Antigravity IDE** | ✅ Full | ✅ Full | ✅ Injected (`mcp_config.json`) | `mcp_config.json` (`proxy_url`) |
| **Claude Desktop (GUI)** | ℹ️ *Direct Cloud* | ✅ Full | 🔒 Preserved | `claude_desktop_config.json` (`stdio-proxy`) |
| **VS Code (Continue)** | ✅ Full | ✅ Full | ✅ Injected (`config.json`) | `config.json` (`apiBase`) |

- **Zero Cloud Dependencies:** Automatically uses your local proxy token (`~/.agentcontrol/local.token`) and configures loopback routing (`http://127.0.0.1:18080/v1`).
- **MCP Process Sandboxing:** Wraps MCP servers with `agentcontrol stdio-proxy` under strict memory limits and credential redaction.
- **Baseline Backup & Ownership Manifest:** Backs up existing configs to `<config>.baseline.bak` and tracks all mutations in `~/.agentcontrol/manifests/<target>.manifest.json` for risk-free reversal.

---

### Step 4: Experience Live Protection in the Local Developer Dashboard (`http://127.0.0.1:18080`)

Open the embedded **Local Developer Dashboard** in your web browser:

```text
http://127.0.0.1:18080
```

- **Zero-Dependency Local UI:** Rendered 100% locally from the running binary — no Node.js, React build steps, or external services required.
- **Interactive Developer Experience:**
  1. **Prompt Your Assistant:** Ask your connected assistant (e.g. Codex or Claude Desktop) to write code or execute a tool call.
  2. **Activity Stream (Live SSE):** Watch intercepted LLM completions and MCP tool executions stream in real time.
  3. **Detections & DLP:** Observe automatic parameter secret redactions (`[REDACTED:API_KEY]`, `[REDACTED:CONNECTION_STRING]`) and prompt injection shield triggers.
  4. **Token Economics & Cache:** Track real-time token spend, budget burn-down, and cache hits.
  5. **Live Policy Wizard:** Review active safe-mode rules and tune tool permissions interactively.

Inspect verified target capabilities and freshness tiers from your terminal:

```bash
agentcontrol status
```

```text
Target: codex           [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
Target: claude          [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
Target: vscode-continue [CONFIGURED, PROBE_VERIFIED]                   (🟢 ACTIVE_FRESH)
```

---

### Step 5: Run Health Diagnostics (`agentcontrol doctor`)

Execute a 7-point health and security verification check:

```bash
agentcontrol doctor
```

```text
✔ Binary Integrity:          Pass (v1.0.87)
✔ Local Token Health:        Pass (~/.agentcontrol/local.token, 0600)
✔ Daemon Reachability:       Pass (127.0.0.1:18080 responsive)
✔ Local Database Health:     Pass (~/.agentcontrol/events.db, WAL active)
✔ Target Configuration:      Pass (codex: verified, claude: verified)
✔ Security Hygiene:          Pass (Zero plaintext keys detected in env)

Overall Health: HEALTHY (Exit Code 0)
```

*(Use `agentcontrol doctor --json` for machine-readable output in CI/CD).*

---

### Step 6: Non-Destructive Reversal Anytime (`agentcontrol disconnect <target>`)

To cleanly disconnect an assistant and restore original settings at any time:

```bash
agentcontrol disconnect codex
agentcontrol disconnect claude
agentcontrol disconnect vscode-continue
agentcontrol disconnect cursor
```

- Restores only the managed settings recorded in the `OwnershipManifest`.
- Unwraps MCP servers back to their original commands and arguments.
- **Developer Preserving:** Any custom themes, model settings, keybindings, or personal tool configs added while connected are preserved completely.

---

### Workstation Security Guarantees & Built-in Protections

Agent Control implements comprehensive workstation-level security guarantees automatically in the background:

1. **Socket-Level Loopback Assertion & Dynamic Fallback:**
   - Background daemon listens on `127.0.0.1:18080`.
   - If port `18080` is busy, dynamically binds to an available fallback port in range `18080..=18090` and writes the active port to `~/.agentcontrol/daemon.port`.
   - Inbound connections are asserted at the TCP socket layer (accepting strictly `127.0.0.0/8`, `::1`, or `::ffff:127.0.0.1`). Non-loopback attempts are dropped immediately.
   - Ambient browser requests (`Origin`, `Sec-Fetch-Site: cross-site`) are rejected with HTTP 403 Forbidden to prevent Web-to-Localhost CSRF / DNS rebinding attacks.

2. **FinOps Spend Governance & 500ms Stream Cancellation:**
   - Atomic preflight token reservations enforce monthly workspace spend limits.
   - When spend caps are reached, immediately returns HTTP 429 (`BUDGET_EXCEEDED`) without retry storms.
   - Premature client SSE disconnects (canceling long reasoning runs) trigger upstream cancellation within **500ms**, reconciling exact tokens streamed.
   - Read the [FinOps Spend Management Guide](docs/guides/finops_spend_management.md).

3. **Multi-OS MCP Stdio Process Sandboxing:**
   - Child MCP processes run with a strict **< 64MB Memory RSS Ceiling** (Windows Job Objects, Linux `RLIMIT_AS`, macOS `RLIMIT_DATA`).
   - Parameter DLP automatically redacts credentials (`[REDACTED:API_KEY]`, `[REDACTED:CONNECTION_STRING]`).
   - Stderr is separated with `[mcp-stderr]` prefixes and child crashes are fully isolated from the daemon.
   - Read the [MCP Stdio Proxy Isolation Guide](docs/guides/mcp_proxy_isolation.md).

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
| **Device & Local Token** | `~/.agentcontrol/local.token` (`0600`) | `%USERPROFILE%\.agentcontrol\local.token` |
| **Credential Storage** | macOS Keychain / Secret Service | Windows Credential Manager |
| **Ownership Manifests** | `~/.agentcontrol/manifests/*.manifest.json` | `%USERPROFILE%\.agentcontrol\manifests\*.manifest.json` |
| **Baseline Backups** | `~/.agentcontrol/backups/*.baseline.bak` | `%USERPROFILE%\.agentcontrol\backups\*.baseline.bak` |
| **State & Audit Logs** | `~/.agentcontrol/audit.jsonl` | `%USERPROFILE%\.agentcontrol\audit.jsonl` |
| **Local TCP Port** | `127.0.0.1:18080` (loopback only) | `127.0.0.1:18080` (loopback only) |

---

## Modes Explained

### Security Enforcement Modes
- **Observation / Shadow Mode (`--shadow`):** Logs all tool calls and evaluated policy decisions without blocking any execution. Ideal for testing and policy baseline generation (`agentcontrol generate-policy`).
- **Enforcement Mode (`--enforce`):** Actively denies tool executions that violate DLP, schema validation, or prompt injection rules.
- **Custom Agent Proxy Mode:** Routes custom Python/Node.js agents via HTTP proxy variables:
  ```bash
  export AGENTCONTROL_PROXY_URL=http://127.0.0.1:18080
  export HTTP_PROXY=http://127.0.0.1:18080
  ```

### LLM Key & Spend Governance Modes (`llm_mode`)
- **`local_compat` (Default):** Standalone local developer compatibility. Dispatches upstream LLM traffic directly using workstation environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `GROQ_API_KEY`, `AWS_REGION`) or client request headers.
- **`central_shadow`:** Enterprise observation mode. Upstream requests are routed through the Control Plane with centralized key custody. Evaluates price books and logs would-deny events without blocking execution.
- **`central_enforce`:** Authoritative enterprise governance. Zero upstream provider keys on workstations (isolated in Control Plane vault). Enforces preflight row-locked budget reservations, pinned active price books, and fail-closed budget caps before dispatch. Workstations authenticate to the broker via scoped device PKI.

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
| **Verified** | **Codex** | `~/.codex/config.toml` | Supported ([Guide](docs/integrations/codex.md)) — wraps MCP tools & injects shell environment policy |
| **Verified** | **Antigravity** | `~/.gemini/antigravity/mcp_config.json` | Tested & fully supported ([Guide](docs/integrations/antigravity.md)) |
| **Experimental** | VS Code, JetBrains, Zed, Cline, OpenCode | User-managed / hypothetical path | Requires `agentcontrol status` & manual check |
| **Custom Agent** | LangChain, LlamaIndex, CrewAI, AutoGen, Raw HTTP | `AGENTCONTROL_PROXY_URL=http://127.0.0.1:18080` | Manual proxy routing ([Guide](docs/guides/custom-agent-http.md)) |

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
sha256sum -c agentcontrol_1.0.87_checksums.txt

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
1. **Port 18080 in use:** The daemon automatically falls back to an open port in `18080..=18090` and writes the active port to `~/.agentcontrol/daemon.port`.
2. **IDE tool calls not intercepted:** Restart your IDE after running `agentcontrol connect <target>` so it reloads its configuration.
3. **Configuration rollback:** Run `agentcontrol disconnect <target>` to non-destructively revert configurations from manifests, or run `agentcontrol repair` to diagnose and fix configuration drift.

### Automated Clean Uninstall
To remove the binary, service daemons, and purge state files:

**macOS / Linux:**
```bash
curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall/uninstall.sh | bash
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/uninstall/uninstall.ps1 | iex
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
- **Continuity & Sovereign Guarantee:** Read our explicit [Continuity & Sovereign Independence Guarantee](docs/CONTINUITY_GUARANTEE.md) detailing why your deployment will never be stranded or locked in.

---

### Open-Core Architecture & Early Access

- **Community Core (Apache 2.0):** Workstation proxy, local MCP tool firewall, prompt injection protection, safe-mode execution, and JSONL audit logging. **100% Free and Open Source forever.**
- **Team Control Hub (Early Access):** Centralized SSE policy push, OIDC group identity binding, vault credential custody, live spend ledger, and fleet governance. **Free for 90 days during Early Access** (up to 5 devices, expanding to 50 devices post-v1.0 GA).
- **Enterprise & Sovereign Deployments:** Dedicated enterprise SLAs, custom DLP classifiers, air-gapped sovereign deployments, SIEM log forwarding, and compliance reporting. Available for design partners and commercial pilots.

---

### Community & Early Access Support

Have questions, feedback, or testing a complex agent toolchain?

- 💬 **Discord Community:** [discord.gg/vexasec](https://discord.gg/vexasec)
- 🐞 **GitHub Issues:** [github.com/noviqtechnologies/Vexa-Agent-Control/issues](https://github.com/noviqtechnologies/Vexa-Agent-Control/issues)
- 📧 **Email:** [contact@vexasec.io](mailto:contact@vexasec.io)
- 🔒 **Security:** [SECURITY.md](SECURITY.md) (Report via [GitHub Advisory](https://github.com/noviqtechnologies/Vexa-Agent-Control/security/advisories/new) or `contact@vexasec.io`)
- 🌐 **Website:** [vexasec.io](https://vexasec.io/)

---

## Documentation Index

Explore the complete [Documentation Hub](docs/README.md):

- **Install Guides:** [macOS](docs/install/macos.md) · [Linux](docs/install/linux.md) · [WSL2](docs/install/wsl.md) · [Windows PowerShell](docs/install/windows-powershell.md) · [Windows CMD](docs/install/windows-cmd.md)
- **Feature Guides:** [Docker Deployment](docs/guides/docker-deployment.md) · [Workstation Workflow](docs/guides/workstation.md) · [Custom Agent HTTP](docs/guides/custom-agent-http.md) · [Small Team Hub](docs/guides/small-team-hub.md) · [Run Explorer](docs/guides/run-explorer.md) · [Effective Policy Explorer](docs/guides/effective-policy.md) · [Spend & Budgets Testing](docs/spend_budgets_testing_guide.md)
- **Integrations:** [Integrations Matrix](docs/integrations/README.md) · [Claude Desktop](docs/integrations/claude-desktop.md) · [Cursor](docs/integrations/cursor.md) · [Codex](docs/integrations/codex.md) · [Antigravity](docs/integrations/antigravity.md)
- **Architecture & Enterprise:** [Architecture V2](docs/ARCHITECTURE_V2.md) · [Enterprise Architecture](docs/advanced/enterprise.md) · [Kubernetes Helm Deployment](docs/advanced/kubernetes.md) · [OIDC Identity Binding](docs/advanced/oidc.md) · [SIEM Log Forwarding](docs/advanced/siem.md) · [OWASP ASI Top 10](docs/owasp_agentic_top10.md) · [Audit Threat Model](docs/security/audit-threat-model.md) · [Continuity Guarantee](docs/CONTINUITY_GUARANTEE.md)
- **Reference & Governance:** [CLI Commands](docs/reference/cli.md) · [Configuration & Env Vars](docs/reference/configuration.md) · [Paths & State](docs/reference/paths-and-state.md) · [Troubleshooting](docs/reference/troubleshooting.md) · [Removal & Recovery](docs/reference/removal-and-recovery.md) · [Legacy Alias Migration](docs/reference/legacy-migration.md) · [Release Notes Template](docs/reference/release-notes-template.md) · [Versioning & Releases](docs/reference/versioning-and-releases.md) · [Contributing Guide](CONTRIBUTING.md) · [Multi-Cloud Terraform](infra/README.md)
