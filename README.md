<h1 align="center">Vexa AgentWall</h1>

<p align="center">
  <strong>Enterprise-Grade Default-Deny AI Security Gateway & Firewall for MCP, HTTP, HTTPS, and WebSockets</strong>
</p>

<p align="center">
  Vexa AgentWall intercepts, sandboxes, audits, and actively enforces strict security policies on AI agent tool calls and outbound LLM API traffic across developer workstations, team staging environments, and production fleets. It features inline DLP scanning, stateful multi-step sequence rules, OIDC identity binding, centralized API key custody, HMAC-chained tamper-evident audit logging, passive shadow discovery mode with Risk Delta reporting, verified MCP security scoring, Human-in-the-Loop policy escalation with HMAC-signed webhook callbacks, hardened WebSocket egress tunneling, real-time AI threat intelligence feed integration, multi-tenant project and task policy sharding, zero-knowledge customer-managed-key SIEM export, a pre-built Hardened Agent Container Runtime (HAR) for Kubernetes deployments, and a built-in ADR (AI Detection & Response) security benchmark suite.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/Version-1.0.19-green.svg?style=flat-square" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-1.89%2B-orange.svg?style=flat-square" alt="Rust"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg?style=flat-square" alt="Go"></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/Frontend-React%20%7C%20TypeScript-blue.svg?style=flat-square" alt="React"></a>
  <a href="docs/README.md"><img src="https://img.shields.io/badge/Documentation-Hub-1f6feb.svg?style=flat-square" alt="Documentation"></a>
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#why-vexa-agentwall">Why Vexa AgentWall</a> ·
  <a href="#capabilities-by-operating-profile">Capabilities</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#security-and-control">Security & Control</a> ·
  <a href="#deployment-options">Deployment options</a> ·
  <a href="#management-consoles">Management consoles</a> ·
  <a href="#configuration">Configuration</a> ·
  <a href="docs/README.md">Documentation</a>
</p>

---

## Quick start

Vexa AgentWall can be deployed across multiple environments: as a zero-config standalone CLI sidecar on a developer workstation, via Docker Compose for engineering teams, as a Kubernetes Helm release for enterprise production fleets, or built directly from source.

### Standalone Developer CLI

Install the statically-linked `agentwall` binary and launch the shadow gateway with an embedded web dashboard:

**macOS / Linux / WSL:**
```bash
curl -fsSL https://vexasec.io/install.sh | bash
agentwall dev
```

**Windows (PowerShell):**
```powershell
irm https://vexasec.io/install.ps1 | iex
agentwall.exe dev
```

Open `http://127.0.0.1:8080` in your browser to inspect live traffic, parameter schema telemetry, risk flags, DLP findings, and policy generator tools.

> 💡 **Generating Instant Test Telemetry**: Running the optional demonstration test script requires **Python 3.8+**. The installer places `quickstart_agent.py` in your local binary path (`~/.local/bin` / `%USERPROFILE%\.local\bin`). If you see *"No tool calls recorded yet"*, run the test script in a new terminal:
> 
> **macOS / Linux / WSL:**
> ```bash
> python3 ~/.local/bin/quickstart_agent.py
> ```
> 
> **Windows (PowerShell):**
> ```powershell
> python "$env:USERPROFILE\.local\bin\quickstart_agent.py"
> ```

### Team / Staging Control Hub (Docker Compose)

Deploy the self-hosted Control Hub stack (Go REST API, React Management Console, PostgreSQL database) alongside gateway instances:

```bash
# 1. Start the Control Hub stack
cd control-plane
docker compose up -d --build

# 2. Start Gateway in Centralized Mode
export DASHBOARD_API_URL="http://localhost:8400"
export POLICY_READ_SECRET="team-policy-read-secret"
export GATEWAY_SECRET="team-gateway-secret"

agentwall start --listen 127.0.0.1:8080 --centralized --log-path ./team-audit.log
```

Access the Team Management Console at `http://localhost:8081` and the Control Hub API at `http://localhost:8400`.

### Enterprise Fleet Production (Kubernetes & Helm)

Deploy the high-availability gateway fleet and Hardened Agent Container Runtime (HAR) on Kubernetes:

```bash
# 1. Create namespace & TLS secret
kubectl create namespace agentwall-system
kubectl create secret tls agentwall-tls --cert=/etc/certs/tls.crt --key=/etc/certs/tls.key -n agentwall-system

# 2. Deploy via Helm Chart
helm install agentwall ./chart \
  --namespace agentwall-system \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName="agentwall-tls" \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true

# 3. Build & run the HAR OCI sidecar container (<100MB distroless footprint)
docker build -f Dockerfile.har -t agentwall-har:2.0 .
docker run -e AGENTWALL_POLICY_PATH=/etc/agentwall/policy.yaml agentwall-har:2.0
```

### Build from Source

Requires Rust 1.89+ toolchain:

```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
cargo build --release
# Compiled binary located at: ./target/release/agentwall
```

---

## Why Vexa AgentWall

Autonomous AI agents possess powerful capabilities—executing terminal commands, reading files, and invoking external APIs over Model Context Protocol (MCP). Without runtime guardrails, agents are vulnerable to prompt injection, credential leaks, recursive loops, and unauthorized data access. Vexa AgentWall enforces deterministic security boundaries around AI agent execution.

**Default-Deny Zero Trust Security.** Every tool invocation and LLM egress request is blocked by default unless explicitly granted by policy rules, eliminating implicit authorization.

**Real-Time Dual-Pass DLP & Threat Interception.** Performs pre-execution scanning of tool parameters and post-execution scanning of outputs to redact or block AWS keys, SSH credentials, PII, and custom secrets before they escape your security boundary.

**OIDC Identity Binding & Task Sharding.** Dynamically resolves user identity from JWT claims (Okta, Keycloak, Entra ID) and scopes policies in real-time to multi-tenant project and task identifiers.

**Human-in-the-Loop Interception.** Intercepts high-risk actions with real-time interactive browser modals or async Slack/Teams webhooks featuring cryptographic HMAC approval callbacks.

**Continuous Compliance & Tamper-Evident Auditing.** Cryptographically chains all system events into an immutable HMAC audit trail while supporting client-side zero-knowledge AES-256-GCM encryption for SIEM export (Splunk, Datadog, OpenSearch).

---

## Capabilities by Operating Profile

Vexa AgentWall scales seamlessly across three operational deployment profiles:

| Capability | What it gives you | Workstation Sidecar | Team Control Hub | Enterprise Fleet |
|---|---|:---:|:---:|:---:|
| **Default-Deny Policy Engine** | Block unauthorized tool calls and LLM egress unless permitted by policy rules | ✓ | ✓ | ✓ |
| **15 Out-of-the-Box Safe Rules** | Pre-configured detection for sensitive paths, exfiltration, persistence, and destructive commands | ✓ | ✓ | ✓ |
| **9 Prompt Injection Scanners** | Active defense against jailbreaks, instruction overrides, memory poisoning, and tool poisoning | ✓ | ✓ | ✓ |
| **Dual-Pass DLP Scanning** | Inline regex scanning and redaction for API tokens, private keys, PII, and secrets | ✓ | ✓ | ✓ |
| **Passive Shadow AI Discovery** | Observe traffic without blocking and generate pre-enforcement Risk Delta reports | ✓ | ✓ | ✓ |
| **MCP Security Scoring Engine** | Evaluate local MCP server manifests and assign a 0–100 Vexa Security Score | ✓ | ✓ | ✓ |
| **IDE Auto-Wrapping Engine** | Transparently route tool calls for Claude Desktop, Cursor, VS Code, JetBrains, and Zed | ✓ | ✓ | ✓ |
| **ADR Security Benchmark** | Evaluate security posture against 303 tasks across 17 real-world AI attack categories | ✓ | ✓ | ✓ |
| **Tamper-Evident HMAC Logging** | Cryptographically chained audit trail with local integrity verification (`agentwall verify-log`) | ✓ | ✓ | ✓ |
| **Centralized Policy Push (SSE)** | Hot-swap policies across running proxy instances without service restarts | — | ✓ | ✓ |
| **OIDC Identity Binding** | Authenticate agent sessions and map JWT group claims (Okta, Keycloak, Entra ID) to policies | — | ✓ | ✓ |
| **Project & Task Policy Sharding** | Dynamically resolve sub-millisecond policy scopes via `agent_project_id` and `agent_task_id` | — | ✓ | ✓ |
| **Centralized Vault & API Keys** | Securely inject LLM provider keys at proxy boundary; agents never touch raw secrets | — | ✓ | ✓ |
| **Async HITL Webhook Queue** | Dispatch dangerous action approvals to Slack, Teams, or Webhooks with HMAC callbacks | — | ✓ | ✓ |
| **Spend Caps & Token Ledger** | Enforce per-session token budgets, model pricing catalogs, and concurrency limits | — | ✓ | ✓ |
| **Loop Detection & Countermeasures** | Intercept repetitive failure loops with `PivotError`, `Block`, or `PauseInteractive` actions | — | ✓ | ✓ |
| **Hardened Container Runtime (HAR)** | Pre-built <100MB Distroless/Alpine OCI sidecar image for Kubernetes pods | — | — | ✓ |
| **Hardened Egress Tunneling** | High-performance WebSocket proxy bridging cloud agents to local MCP servers (<5ms latency) | — | — | ✓ |
| **Real-Time Threat Intel Feed** | Subscribe to live AI malware signature streams via SSE without dropping connections | — | — | ✓ |
| **Zero-Knowledge CMK Encryption** | Client-side AES-256-GCM encryption of audit streams using Customer-Managed Keys prior to SIEM export | — | — | ✓ |
| **Pure-Rust TLS Termination** | Native HTTPS listening powered by `rustls`, eliminating C-library attack surfaces | — | — | ✓ |

### Workstation & Local Sidecar Profile

Provides individual developers with instant, zero-configuration security guardrails and complete traffic visibility on local workstations.

- **Safe Mode & Default-Deny Guardrails** — Enforces zero-trust boundaries over MCP tool calls with 15 built-in safe mode rules.
- **Prompt Injection & Response Poisoning Protection** — Intercepts incoming tool responses for jailbreaks, instruction manipulation, and memory poisoning.
- **Dual-Pass DLP Redaction** — Scans and redacts sensitive data (AWS keys, SSH private keys, PII) in real-time.
- **Passive Shadow AI Discovery Mode** — Run `agentwall dev` or `agentwall start --shadow-mode` to observe agent behavior and generate a **Risk Delta Report** (`agentwall report --risk`).
- **MCP Security Scoring Engine** — Run `agentwall scan` to audit local MCP servers, assigning a Vexa Security Score (0–100) and enforcing CI/CD quality gates.
- **Local Developer Web Console** — Embedded dashboard at `http://127.0.0.1:8080` for live traffic monitoring, risk analysis, and interactive approvals.
- **IDE Wrapping Engine** — Auto-patches Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity IDE configuration files (`agentwall wrap`, `agentwall watch`).
- **ADR AI Detection & Response Benchmark** — Execute the 303-task security benchmark across 17 attack classes (`agentwall bench --full`) to score security posture.

### Team & Staging Control Hub Profile

Extends governance across engineering teams and staging environments with centralized policy coordination, identity binding, and budget controls.

- **Centralized Policy Push (SSE)** — Broadcast versioned security policies from the Control Hub to distributed gateway instances in real-time via Server-Sent Events.
- **OIDC Identity Binding** — Map corporate identity provider JWT group claims (Keycloak, Okta, Entra ID, Auth0, Ping) directly to dynamic policy rulesets.
- **Multi-Tenant Policy Sharding** — Resolves and scopes policies dynamically based on `agent_project_id` and `agent_task_id` request context headers.
- **Vault Integration & API Key Custody** — Holds LLM provider credentials securely within the proxy, eliminating API key distribution to developer workstations or agent code.
- **Asynchronous HITL Approval Queue** — Routes high-risk tool execution prompts to Slack, Microsoft Teams, or Webhooks with HMAC signature verification.
- **Spend Caps & Budget Ledger** — Enforce token consumption caps, track model pricing metrics, and manage concurrent agent execution limits via SQLite.
- **Loop Detection & Pivot Error Countermeasures** — Detects stuck agents trapped in repetitive failure patterns and triggers auto-corrective actions (`PivotError`).
- **Multi-Backend SIEM Export** — Stream structured JSON audit events to Splunk HEC, Datadog Logs, or OpenSearch with zero-blocking local fallbacks.

### Enterprise Fleet Production Profile

Delivers high-availability security governance, cryptographic privacy, and zero-trust protection for enterprise cloud workloads and multi-tenant agent fleets.

- **Hardened Agent Container Runtime (HAR)** — Light-footprint OCI container image (<100MB) designed as an entrypoint sidecar proxy for Kubernetes container deployments.
- **Hardened Egress WebSocket Tunneling** — Secure WebSocket proxy connecting remote cloud-hosted agents to local on-premise MCP servers with <5ms frame latency.
- **Real-Time Threat Intelligence Feed** — Dynamically ingests Vexa AI Malware signature feeds via SSE, updating DLP patterns in-flight without connection loss.
- **Zero-Knowledge Customer-Managed Key (CMK) Encryption** — Client-side AES-256-GCM encryption of audit logs using Customer-Managed Keys prior to SIEM egress.
- **Pure-Rust TLS Termination** — Memory-safe HTTPS listener powered by `rustls`, eliminating C-library vulnerabilities and OpenSSL dependencies.
- **Fleet-Wide Telemetry & Monitoring** — Monitor gateway fleet health, pod status, policy sync state, and socket performance natively in Kubernetes.

---

## How it works

<p align="center">
  <img src="docs/system_architecture_diagram.png" alt="Vexa AgentWall System Architecture Diagram" width="750">
</p>

```
  [ Operating Surfaces & IDEs ] ──► (Claude Desktop / Cursor / VS Code / Antigravity / CLI)
             │
             ▼
 ┌───────────────────────────┐
 │ 1. Session & Identity     │ ◄── OIDC JWT Claims & Multi-Tenant Project / Task Policy Sharding
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 2. MCP Scoring & Schema   │ ◄── Vexa Security Score (0-100) & Parameter JSON Schema Validation
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 3. Safe Mode & Injection  │ ◄── 15 Out-of-the-Box Safe Mode Rules & 9 Prompt Injection Detectors
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 4. Dual-Pass DLP Engine   │ ◄── Inline PII & Secret Redaction / Dynamic Threat Intel Feed
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 5. Spend & Loop Control   │ ◄── Repeat Failure Loop Intercept (PivotError) & Token Budget Ledger
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 6. HITL & Action Ladder   │ ◄── Default-Deny Evaluation & HMAC Webhook / Browser Escalation
 └─────────────┬─────────────┘
               │
    [ Upstream MCP / LLM ]  ───►  Control Hub Telemetry & Zero-Knowledge Encrypted SIEM Export
```

### 6-Pass Security & Policy Engine Pipeline

Every agent tool call and LLM egress payload traversing Vexa AgentWall passes sequentially through a 6-pass deterministic pipeline before reaching upstream services:

1. **Session & Identity Binding** — Validates OIDC JWT claims and dynamically resolves multi-tenant project (`agent_project_id`) and task (`agent_task_id`) policy shards.
2. **MCP Scoring & Schema Validation** — Evaluates tool parameter schemas and verifies the target MCP server's Vexa Security Score (0–100).
3. **Safe Mode & Injection Defense** — Applies 15 out-of-the-box safe mode rules and scans tool calls/responses for 9 prompt injection attack categories.
4. **Dual-Pass DLP Engine** — Executes pre-execution and post-execution regex scanning, redacting sensitive credentials, private keys, and PII against dynamic threat intelligence feeds.
5. **Spend Control & Loop Prevention** — Enforces session token budgets and interrupts repetitive agent failure loops via `PivotError` responses.
6. **HITL Intercept & Action Ladder** — Evaluates final default-deny authorization rules, triggering interactive browser modals or HMAC-signed webhook approvals for high-risk actions.

### Supported Operating Surfaces & IDE Integrations

| Surface / IDE | Integration Mode | Features |
|---|---|---|
| **Claude Desktop** | `agentwall wrap claude` | Automated config patching, stdio tool proxying, real-time DLP |
| **Cursor / VS Code** | `agentwall wrap cursor` | Native MCP config interception, shadow discovery, risk reporting |
| **JetBrains / Zed** | `agentwall wrap jetbrains` | Transparent stdio proxying, default-deny policy enforcement |
| **Container Workloads** | HAR Sidecar Container | Entrypoint container proxying, OIDC binding, spend management |
| **CLI & Custom Agents** | `agentwall dev --stdio -- <cmd>` | Native HTTP/HTTPS proxying, stdio stream wrapper, audit logging |
| **Web Dashboard** | Native Browser | Live traffic inventory, HITL approval modals, ADR benchmark runner |

---

## Security and control

Vexa AgentWall enforces security controls at the network and runtime boundaries rather than relying on prompt-based instructions.

- **Default-Deny Runtime Boundary** — Tool calls and egress requests are rejected by default unless granted by explicit YAML policy statements.
- **Interactive Human-in-the-Loop (HITL)** — High-impact actions prompt for manual approval via embedded web UI modals or HMAC-signed Slack/Teams webhook callbacks.
- **Tamper-Evident Cryptographic Audit Logging** — Log records are linked in a cryptographic HMAC-SHA256 hash chain, verifiable via `agentwall verify-log`.
- **Zero-Knowledge CMK SIEM Export** — Audit data is encrypted with client-side AES-256-GCM using Customer-Managed Keys prior to external SIEM transmission.
- **Memory-Safe Pure-Rust Architecture** — Built with Rust and `rustls` to eliminate memory corruption bugs, buffer overflows, and C-library vulnerabilities.
- **Real-Time Threat Intelligence Integration** — Subscribes to live Vexa threat feeds via SSE, updating DLP pattern signatures on-the-fly without downtime.

---

## Deployment options

Vexa AgentWall adapts to your existing deployment infrastructure:

| Deployment Profile | Orchestration & Deployment | Infrastructure & State Storage |
|---|---|---|
| **Workstation Local Sidecar** | Standalone Binary (`agentwall dev`) or IDE Wrapper (`agentwall wrap`) | Local workstation, embedded SQLite database, local disk audit logs |
| **Team Staging Control Hub** | Docker Compose (`docker compose up`) | Shared team host / VM, PostgreSQL database, central control API |
| **Enterprise Fleet Production** | Kubernetes Helm Release (`helm install agentwall ./chart`) | Cloud Kubernetes cluster, HA database, external SIEM export |
| **Hardened Agent Runtime (HAR)** | Distroless/Alpine OCI Image (`Dockerfile.har`) | Kubernetes pod sidecar, production agent containers (<100MB memory footprint) |

---

## Management consoles

Vexa AgentWall provides dedicated management interfaces tailored to each operational profile:

| Console Profile | Access Endpoint | Core Capabilities & Telemetry |
|---|---|---|
| **Local Developer Console** | `http://127.0.0.1:8080` (`agentwall dev`) | Real-time traffic monitor, shadow mode Risk Delta reporting, Vexa Security Score view, HITL browser modal, ADR benchmark runner |
| **Team Control Hub Console** | `http://localhost:8081` (Docker Compose) | Centralized policy editor, SSE hot-reload controller, async HITL approval queue, project/task policy sharding, team spend analytics |
| **Enterprise Control Hub Console** | Kubernetes Ingress / TLS Endpoint | HAR container pod telemetry, threat intelligence feed monitor, zero-knowledge CMK SIEM status, fleet security compliance overview |

---

## Configuration

### Policy YAML Schema (v2 Schema)

AgentWall policies operate on a **default-deny** model (`agentwall-policy.yaml`):

```yaml
version: 2
default_action: deny

identity:
  provider: "oidc"
  issuer: "https://auth.corp.com/oauth2/default"
  audience: "agentwall-gateway-prod"
  group_claim_key: "groups"

policy_bindings:
  - group: "secops-team"
    policy: "admin-unrestricted"
  - group: "dev-team"
    policy: "developer-standard"

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
        deny_patterns: ["\\.ssh", "\\.env", "\\.aws"]

dlp:
  scannable_tools: ["read_file", "execute_command"]
  safe_tools: ["list_directory"]
  patterns:
    - name: "aws_access_key"
      regex: "AKIA[0-9A-Z]{16}"
      action: block
    - name: "credit_card"
      regex: "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
      action: redact

spend:
  max_tokens_per_session: 100000
  max_concurrent_sessions: 10

loop_detection:
  threshold: 3
  action: PivotError

audit:
  log_file: "/var/log/agentwall/audit.jsonl"
  siem_export:
    type: "splunk_hec"
    endpoint: "https://splunk.corp.com:8088/services/collector/event"
    token: "${SPLUNK_HEC_TOKEN}"
```

### Environment Variables

| Variable | Description | Default |
|---|---|---|
| `HTTP_PROXY` / `HTTPS_PROXY` | Standard HTTP proxy routing URLs for outbound agent traffic | — |
| `AGENTWALL_LISTEN` | Gateway listen socket address | `127.0.0.1:8080` |
| `AGENTWALL_POLICY_PATH` | Path to YAML policy configuration file | — |
| `DASHBOARD_API_URL` | Control Hub API endpoint URL for centralized management | — |
| `POLICY_READ_SECRET` | Shared authentication secret for real-time policy hot-reloading | — |
| `GATEWAY_SECRET` | Shared secret for publishing gateway telemetry events | — |
| `AGENTWALL_LOG_PATH` | Path to durable audit log file | `audit.log` |
| `AGENTWALL_OIDC_ISSUER` | OIDC issuer URL for identity binding and group claim mapping | — |
| `AGENTWALL_SIEM_BACKEND` | SIEM backend target (`splunk`, `datadog`, `opensearch`, `local`) | `local` |
| `AGENTWALL_SIEM_ENDPOINT` | External SIEM log ingestion endpoint URL | — |
| `AGENTWALL_SIEM_TOKEN` | Authentication token for external SIEM API | — |
| `AGENTWALL_SHADOW_MODE` | Passive observation mode — log events without blocking calls | `false` |
| `AGENTWALL_DRY_RUN` | Log policy violations without denying tool executions | `false` |
| `AGENTWALL_TLS_CERT` | Path to TLS certificate PEM file (`rustls`) | — |
| `AGENTWALL_TLS_KEY` | Path to TLS private key PEM file (`rustls`) | — |
| `AGENTWALL_HITL_SECRET` | Cryptographic HMAC secret for HITL approval callbacks | — |

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).
