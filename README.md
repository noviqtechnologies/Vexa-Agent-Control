# Vexa AgentWall

Vexa AgentWall is an enterprise-grade default-deny security gateway and LLM agent egress proxy operating over MCP (Model Context Protocol), HTTP, HTTPS, and WebSocket connections. It intercepts, sandboxes, audits, and actively enforces strict security policies on AI agent tool calls and outbound LLM API traffic across developer workstations, team staging environments, and production fleets — featuring inline DLP scanning, stateful multi-step sequence rules, OIDC identity binding, centralized API key custody, HMAC-chained tamper-evident audit logging, passive shadow discovery mode with Risk Delta reporting, verified MCP security scoring, Human-in-the-Loop policy escalation with HMAC-signed webhook callbacks, hardened WebSocket egress tunneling, real-time AI threat intelligence feed integration, multi-tenant project and task policy sharding, zero-knowledge customer-managed-key SIEM export, a pre-built Hardened Agent Container Runtime (HAR) for Kubernetes and Obot deployments, and a built-in **ADR (AI Detection & Response)** security benchmark suite.

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/version-1.0.6-green.svg" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8.svg" alt="Go"></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/frontend-React%20%7C%20TypeScript-blue.svg" alt="React"></a>
</p>

<p align="center">
  <a href="https://vexasec.io/">Website</a> · <a href="docs/user_guide.md">User Guide</a> · <a href="docs/index.md">Documentation Hub</a> · <a href="docs/oidc_identity_binding.md">OIDC Guide</a> · <a href="https://github.com/noviqtechnologies/agentwall/issues">Issues</a> · <a href="mailto:security@vexasec.io">Security</a>
</p>

---

## Capabilities by Deployment Tier

AgentWall provides unified governance across the entire AI agent lifecycle, scaling from local developer sidecars to high-throughput enterprise security fleets.

### 🖥️ Tier 1 — Developer Workstation (Local Sidecar)

The local sidecar mode provides developers with instant, zero-configuration security and full traffic visibility without external infrastructure.

- **Default-Deny Policy Enforcement** — Blocks unauthorized tool calls and outbound LLM requests unless explicitly permitted by a YAML policy, with Safe Mode active by default.
- **Out-of-the-Box Safe Mode** — Pre-configured detection for 15 high-signal rules covering Sensitive Files, Secrets & Config, System Paths, Data Exfiltration, Persistence/Shell Execution, Destructive Operations, and Network/SSRF.
- **Prompt Injection & Response Poisoning Detection** — Scans incoming tool responses for 9 attack categories including Jailbreaks, Instruction Manipulation, Credential Solicitation, Memory/State Poisoning, Covert Action Directives, CJK Instruction Overrides, and Tool Poisoning.
- **Inbound & Outbound DLP Scanning** — Dual-pass regex scanning and inline redaction/blocking for AWS keys, SSH private keys, OpenAI/Anthropic/GitHub/Stripe API tokens, PII, and credit card numbers.
- **Passive Shadow AI Discovery Mode** — Observe agent traffic without blocking calls (`agentwall dev` or `agentwall start --shadow-mode`). Generates a **Risk Delta Report** (`agentwall report --risk`) summarizing potential policy violations prior to enforcement.
- **MCP Security Scoring Engine (`agentwall scan`)** — Evaluates local MCP server definitions to assign a Vexa Security Score (0–100) based on permission footprint, file access depth, and schema complexity. Fails CI/CD pipelines automatically on low scores.
- **Local Web Dashboard** — Live traffic monitor at `http://127.0.0.1:8080` displaying real-time tool call logs, risk timelines, Vexa Security Score cards, WebSocket tunnel latencies, and interactive approval modals.
- **Human-in-the-Loop (HITL) Local Intercept** — Intercepts high-risk tool calls with an interactive browser modal, prompting the developer to Allow Once, Permanently Authorize, or Block.
- **IDE Wrapping Engine & Watch Daemon** — Auto-patches Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity IDE configuration files to transparently route MCP tool calls through AgentWall (`agentwall wrap`, `agentwall watch`).
- **Automatic Policy Generation** — Analyzes shadow-mode dev traffic and synthesizes a production-ready, lint-passing `agentwall-policy.yaml` (`agentwall generate-policy`).
- **ADR AI Detection & Response Benchmark** — Includes a 303-task security benchmark across 17 attack classes (`agentwall bench --full`), scoring your posture against industry baselines (GuardAgent, LlamaFirewall, ALRPHFS).
- **Tamper-Evident HMAC Audit Logging** — Cryptographically chained audit trail written to local disk, verifiable at any time via `agentwall verify-log`.
- **Opt-In Dual-Agent Threat Detector** — Worker mode leveraging a local LLM (e.g., via Ollama) to perform semantic threat reasoning on ambiguous tool calls (`agentwall dev --dual-agent`).
- **Stdio Proxy Wrapper** — Wraps stdio-based MCP servers over stdin/stdout streams (`agentwall dev --stdio -- <command>`), making CLI-based tools fully observable and policy-enforced.

---

### 👥 Tier 2 — Team / Staging (Control Hub & Docker Compose)

The Control Hub extends governance to staging environments and engineering teams with centralized policy synchronization, identity binding, and spend management.

- **Centralized Policy Management & Real-time SSE Push** — Version and push policy updates hot from the Control Hub to all connected gateway instances via Server-Sent Events without restarting services.
- **OIDC Identity & Group Claim Binding** — Authenticates agent sessions against corporate Identity Providers (Keycloak, Okta, Entra ID, Auth0, Cognito, Google Workspace, Ping) and dynamically enforces policies matched to JWT group claims.
- **Multi-Tenant Project & Task Policy Sharding** — Dynamically resolves and scopes policies to `agent_project_id` and `agent_task_id` session headers in sub-millisecond execution time.
- **Vault Backend & Credential Management** — Integrated credential issuance, rotation, and revocation supporting HashiCorp Vault (AppRole), AWS Secrets Manager (IAM), and Azure Key Vault (Managed Identity).
- **Centralized Provider API Key Custody** — Holds LLM provider credentials securely in the gateway. Agents and developers never handle raw API keys; the proxy injects them dynamically on egress.
- **HITL Async Approval Queue** — Dispatches asynchronous webhook alerts for intercepted dangerous commands to Slack, Microsoft Teams, or the Control Hub UI, validating HMAC-signed callback approvals.
- **Token Spend Cap & SQLite Ledger** — Tracks per-session token usage, applies model pricing catalogs, enforces concurrency caps, and manages database retention.
- **Agent Loop Detection & Pivot Error Handling** — Identifies agents trapped in repetitive failure loops and executes configured countermeasures (`PivotError`, `Block`, or `PauseInteractive`).
- **Self-Healing Behavioral Learning** — Calculates Z-score parameter anomalies, applies confidence decay over time, and automatically drafts GitOps policy pull requests.
- **Multi-Backend SIEM Export** — Asynchronously streams structured JSON audit events to Splunk HEC, Datadog Logs, or OpenSearch with zero-blocking timeout fallbacks to local disk.

---

### 🏢 Tier 3 — Enterprise Production (Kubernetes & Fleet Security)

Enterprise fleet deployments deliver high-availability agent governance, compliance-grade cryptographic privacy, and zero-trust data protection at scale.

- **Hardened Agent Container Runtime (HAR)** — Pre-configured Alpine/Distroless OCI container image (<100MB footprint) operating as an entrypoint proxy for Obot, Docker, and Kubernetes agent pods.
- **Hardened Rust Egress Tunneling** — High-performance WebSocket proxy bridging cloud-hosted agents to local MCP servers with inline DLP scanning and <5ms frame latency.
- **Real-Time Threat Intelligence Feed** — Subscribes to Vexa AI Malware signature feeds via SSE, hot-swapping DLP pattern matching rules without dropping active connections.
- **Zero-Knowledge Customer-Managed Key (CMK) Encryption** — Client-side AES-256-GCM encryption of audit logs using Customer-Managed Keys prior to SIEM egress, ensuring no third party can read sensitive audit data.
- **Memory-Safe Pure-Rust TLS Termination** — Native HTTPS listening powered by `rustls`, eliminating OpenSSL CVE attack surface and C library dependencies.
- **Semantic Policy Inspection & Caching** — Performs async or sync semantic threat evaluation against tool description poisoning and instruction manipulation with TTL-based caching.
- **Fleet-Wide HAR Container Telemetry** — Kubernetes-native monitoring of running AgentWall sidecars, tracking policy sync status, image versions, pod health, and socket performance.
- **Zero-Downtime Policy Hot-Reloading** — Applies policy modifications atomically across production gateway clusters without dropping inflight requests or splitting evaluation states.

---


## Installation

AgentWall provides flexible installation methods tailored to your deployment tier across macOS, Linux, and Windows:

### 1. Developer / Binary Install (Standalone CLI)
Installs the statically-linked `agentwall` binary:

* **macOS / Linux / WSL:**
  ```bash
  curl -fsSL https://vexasec.io/install.sh | bash
  agentwall --version
  ```
  > **Permanent PATH Setup (Set Once):**
  > - **Bash (Linux/WSL):** `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc`
  > - **Zsh (macOS / modern Linux):** `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc`
  > - **Fish:** `fish_add_path ~/.local/bin`

* **Windows (PowerShell / CMD / Git Bash):**
  ```powershell
  irm https://vexasec.io/install.ps1 | iex
  agentwall.exe --version
  ```
  > **Permanent PATH Setup (Set Once):**
  > - **PowerShell (Run once):**
  >   ```powershell
  >   [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.local\bin", "User")
  >   ```
  > - **Command Prompt (CMD):**
  >   ```cmd
  >   setx PATH "%PATH%;%USERPROFILE%\.local\bin"
  >   ```
  > - **Git Bash / MSYS2:**
  >   ```bash
  >   echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile && source ~/.bash_profile
  >   ```

Or build from source (requires Rust 1.89+):
```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
cargo build --release
# Binary path: ./target/release/agentwall
```

### 2. Team / Staging Install (Docker Compose)
Run the self-hosted Control Hub stack (Go REST API, React UI, PostgreSQL DB) and connect gateway instances:

1. **Deploy Control Hub Stack:**
   ```bash
   cd control-plane
   docker compose up -d --build
   ```
   * **Control Hub UI:** `http://localhost:8081`
   * **Control Hub API:** `http://localhost:8400`

2. **Start Gateway in Centralized Mode:**
   ```bash
   export DASHBOARD_API_URL="http://localhost:8400"
   export POLICY_READ_SECRET="team-policy-read-secret"
   export GATEWAY_SECRET="team-gateway-secret"

   agentwall start --listen 127.0.0.1:8080 --centralized --log-path ./team-audit.log
   ```

### 3. Enterprise Production Install (Kubernetes & Helm)
Deploy the centralized enforcement fleet and Control Hub on Kubernetes:

1. **Create Namespace & TLS Secret:**
   ```bash
   kubectl create namespace agentwall-system
   kubectl create secret tls agentwall-tls --cert=/etc/certs/tls.crt --key=/etc/certs/tls.key -n agentwall-system
   ```

2. **Deploy Helm Chart:**
   ```bash
   helm install agentwall ./chart \
     --namespace agentwall-system \
     --set gateway.tls.enabled=true \
     --set gateway.tls.secretName="agentwall-tls" \
     --set dashboardApi.enabled=true \
     --set dashboardDb.enabled=true \
     --set dashboardFrontend.enabled=true
   ```

3. **Deploy Hardened Agent Container Runtime (HAR):**
   ```bash
   # Build the <100MB OCI sidecar image
   docker build -f Dockerfile.har -t agentwall-har:2.0 .

   # Run as entrypoint proxy in Obot / Docker / Kubernetes
   docker run -e AGENTWALL_POLICY_PATH=/etc/agentwall/policy.yaml agentwall-har:2.0
   ```

---

## Architecture

![AgentWall System Architecture](docs/system_architecture_diagram.png)

### 6-Pass Security & Policy Engine Pipeline

Every agent tool call and LLM egress payload traversing AgentWall passes sequentially through a 6-pass deterministic pipeline before reaching upstream services:

```
  [ Agent / Client / IDE ]
             │
             ▼
 ┌────────────────────────┐
 │ 1. Session & Identity  │ ◄── OIDC JWT Claims / Multi-Tenant Task & Project Policy Sharding
 └───────────┬────────────┘
             ▼
 ┌────────────────────────┐
 │ 2. MCP Scoring & Schema│ ◄── Vexa Security Score (0-100) & Parameter Regex/Path Validation
 └───────────┬────────────┘
             ▼
 ┌────────────────────────┐
 │ 3. Safe Mode & Injection│ ◄── 15 Out-of-the-Box Safe Mode Rules & 9 Prompt Injection Detectors
 └───────────┬────────────┘
             ▼
 ┌────────────────────────┐
 │ 4. Dual-Pass DLP Engine│ ◄── Real-Time Regex PII & Secret Redaction / Dynamic Threat Intel Feed
 └───────────┬────────────┘
             ▼
 ┌────────────────────────┐
 │ 5. Loop & Spend Control│ ◄── Repeat Failure Loop Intercept (PivotError) & Token Budget Ledger
 └───────────┬────────────┘
             ▼
 ┌────────────────────────┐
 │ 6. HITL & Action Ladder│ ◄── Default-Deny Evaluation & HMAC Webhook / Browser Approval Escalation
 └───────────┬────────────┘
             │
   [ Upstream MCP / LLM ]  ───►  Zero-Knowledge Encrypted SIEM Export (AES-256-GCM)
```

### Deployment Tiers

| Tier | Components | Deployment Target | Guide & Installation Links |
|------|-----------|------------------|---------------------------|
| **Local Sidecar** | Gateway + SQLite + Stdio Proxy + IDE Wrappers | Standalone Developer Workstation (`agentwall dev`) | [Binary Install](#1-developer--binary-install-standalone-cli) · [Tier 1 Guide](docs/user_guide.md#tier-1-developer--workstation) |
| **Team Hub** | Gateway Fleet + Hub API + Hub UI + PostgreSQL + Vault Adapters | Team Staging / Shared Server (Docker Compose) | [Docker Compose Install](#2-team--staging-install-docker-compose) · [Tier 2 Guide](docs/user_guide.md#tier-2-team--staging) |
| **Enterprise** | HAR Containers + WebSocket Tunnel + Threat Feed + CMK SIEM | Enterprise Multi-Tenant (Kubernetes & Helm) | [Helm Production Install](#3-enterprise-production-install-kubernetes--helm) · [Tier 3 Guide](docs/user_guide.md#tier-3-enterprise-cloud--production) |

### Dashboard Tiers

| Dashboard | Access | Key Panels |
|-----------|--------|-----------|
| **Tier 1 — Local Sidecar** (`127.0.0.1:8080`) | `agentwall dev` | Traffic inventory, Risk Delta (shadow mode), Vexa Security Score, Egress Tunnel latency, HITL intercept modal |
| **Tier 2 — Team Control Hub** | Docker Compose (`localhost:8081`) | HITL Approval queue, Fleet MCP security audit, Project/Task policy sharding editor, Group spend caps |
| **Tier 3 — Enterprise Control Hub** | Kubernetes Ingress | HAR container telemetry, Threat Intelligence feed monitor, Zero-Knowledge SIEM status, Enterprise license management |

---


## Quick Start

### 1. Local Shadow Proxy & Embedded Dashboard (`agentwall dev`)

**Prerequisites:**
- **AgentWall CLI Installed**: `agentwall` binary installed locally.
- **Node.js / npx (Optional for stdio MCP wrapping)**: Required if wrapping stdio MCP servers like `@modelcontextprotocol/server-filesystem` (`node >= 18` & `npx`).
- **Available Socket Address**: Local port `127.0.0.1:8080` (or custom address via `--listen`).

Launch the shadow proxy in observation mode. This automatically starts the local Web UI at `http://127.0.0.1:8080` and opens your browser:

```bash
agentwall dev
```
* Use `--no-browser` to prevent automatic browser launching.
* Use `--enforce` to test active DLP and policy blocking locally.
* Wrap stdio-based MCP servers directly:
  ```bash
  agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem ~/workspace
  ```
  *(Note: Ensure Node.js/npx is installed and target directory exists).*

### 2. Route Local Agent Traffic
Set standard proxy environment variables in your shell:

* **macOS / Linux (Bash/Zsh):**
  ```bash
  export HTTP_PROXY=http://127.0.0.1:8080
  export HTTPS_PROXY=http://127.0.0.1:8080
  export AGENTWALL_PROXY_URL=http://127.0.0.1:8080
  python my_agent.py
  ```
* **Windows (PowerShell):**
  ```powershell
  $env:HTTP_PROXY="http://127.0.0.1:8080"
  $env:HTTPS_PROXY="http://127.0.0.1:8080"
  $env:AGENTWALL_PROXY_URL="http://127.0.0.1:8080"
  python my_agent.py
  ```

### 3. Wrap Local IDEs (`agentwall wrap`)
Automatically patch IDE configuration files (Claude Desktop, Cursor) to route MCP server tool calls through AgentWall:

```bash
# Wrap Claude Desktop
agentwall wrap claude

# Inspect IDE status across all supported editors
agentwall status
```

### 4. Auto-Generate & Enforce Policy
Draft a YAML security policy from observed shadow-mode traffic, lint it, and switch to enforcement mode:

```bash
# Generate policy draft from observed events
agentwall generate-policy --decay-window 30
agentwall lint agentwall-policy.yaml

# Start gateway in active enforcement mode
agentwall start --policy agentwall-policy.yaml --listen 127.0.0.1:8080
```

### 5. Run the ADR Security Benchmark
Measure your security posture against 17 real-world AI attack categories (303 tasks total):

```bash
agentwall bench --full
# Report saved to: target/benchmark-report.html
```

The benchmark produces an overall **A/B/C security grade** with per-category pass rates and comparative baselines against GuardAgent, LlamaFirewall, and ALRPHFS. The **ADR Benchmark** tab in the local dashboard (`http://127.0.0.1:8080`) displays the report interactively.

---

## v2.0 Feature Workflows

### Passive Shadow AI Risk Delta Report
Run in non-blocking mode and generate a report of what *would* have been blocked:

```bash
# Observe without enforcing
agentwall start --shadow-mode --log-path audit.log

# Generate Risk Delta summary
agentwall report audit.log --risk
```

### Vexa Security Scan — CLI & CI/CD ( / )
Scan MCP server configurations for vulnerabilities before deployment:

```bash
# Text output (for developer review)
agentwall scan --path agentwall-policy.yaml

# JSON output (for CI/CD pipeline integration)
agentwall scan --path agentwall-policy.yaml --format json
# Exit code: 0 = score ≥ 60 (safe), 1 = score < 60 (CI/CD gate failure)
```

### Human-in-the-Loop Policy Escalation
Configure asynchronous approval for P0 dangerous commands via HMAC-signed callbacks:

```yaml
# In agentwall-policy.yaml
hitl_escalation:
  enabled: true
  secret_key: "env:AGENTWALL_HITL_SECRET"
  webhook_url: "https://hooks.slack.com/services/..."
  timeout_seconds: 300
```

### Zero-Knowledge SIEM Export
Encrypt audit logs client-side with a Customer-Managed Key before SIEM egress:

```bash
agentwall start \
  --siem-backend splunk \
  --siem-endpoint https://splunk.corp.com:8088/services/collector/event \
  --siem-token "${SPLUNK_HEC_TOKEN}" \
  --cmk-key "${CUSTOMER_MANAGED_KEY}"
```

---

## Configuration

### Policy YAML Example (v2 Schema)

AgentWall policies operate on a **default-deny** principle (`agentwall-policy.yaml`):

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

| Variable | CLI Command | Description | Default |
|---|---|---|---|
| `HTTP_PROXY` / `HTTPS_PROXY` | `dev`, client | Standard HTTP proxy routing URLs | — |
| `AGENTWALL_LISTEN` | `start`, `dev` | Gateway listen socket address | `127.0.0.1:8080` |
| `AGENTWALL_POLICY_PATH` | `start` | Path to YAML policy file | — |
| `DASHBOARD_API_URL` | `start`, proxy | Control Hub API endpoint URL | — |
| `POLICY_READ_SECRET` | `start` | Shared secret for policy hot-reload SSE | — |
| `GATEWAY_SECRET` | `start` | Shared secret for telemetry publishing | — |
| `AGENTWALL_LOG_PATH` | `start` | Path to durable audit log file | `audit.log` |
| `AGENTWALL_OIDC_ISSUER` | `start` | OIDC issuer URL for identity binding | — |
| `AGENTWALL_SIEM_BACKEND` | `start` | SIEM backend (`splunk`, `datadog`, `opensearch`, `local`) | `local` |
| `AGENTWALL_SIEM_ENDPOINT` | `start` | SIEM ingestion URL | — |
| `AGENTWALL_SIEM_TOKEN` | `start` | SIEM authentication token | — |
| `AGENTWALL_SHADOW_MODE` | `start` | Observation mode — log without blocking | `false` |
| `AGENTWALL_DRY_RUN` | `start` | Log policy violations without denying calls | `false` |
| `AGENTWALL_STRICT_CREDENTIAL_SCOPE` | `start` | Reject credential scope mismatches with 403 | `false` |
| `AGENTWALL_TLS_CERT` | `start` | Path to TLS certificate PEM file (`rustls`) | — |
| `AGENTWALL_TLS_KEY` | `start` | Path to TLS private key PEM file (`rustls`) | — |
| `AGENTWALL_HITL_SECRET` | `start` | HMAC secret for HITL escalation callbacks | — |

---

## User Guide & Documentation Links

Consult our comprehensive documentation suite for detailed guides, architecture specifications, and provider configurations:

- 📖 **[Vexa AgentWall Detailed User Guide](docs/user_guide.md)** — Comprehensive guide covering deployment tiers, v2 policy creation, DLP tuning, OIDC identity binding, Control Hub setup, audit verification, troubleshooting, and all v2.0 War Plan features.
- 🔐 **[OIDC Identity Binding & Auth Provider Guide](docs/oidc_identity_binding.md)** — Step-by-step setup guides, claims mappings, and policy examples for Okta, Keycloak, Entra ID, Auth0, AWS Cognito, Google Workspace, and PingIdentity.
- 🚀 **[Quickstart Guide](docs/quickstart.md)** — Real-world tutorial for securing Claude Desktop and MCP tools.
- 📦 **[Deployment & Installation Guide](docs/deployment.md)** — Step-by-step installation for macOS, Linux, Windows, Docker, Kubernetes, and HAR container images.
- ⚙️ **[Configuration & Policy Reference](docs/configuration.md)** — In-depth reference for Schema v2 policies, sequence rules, Safe Mode rules, HITL escalation configuration, and DLP regex patterns.
- 📚 **[Documentation Hub](docs/index.md)** — Centralized documentation index.
- 🛠️ **[Comprehensive Functional Walkthrough](docs/comprehensive_guide.md)** — Command-line scenario walkthroughs for developers across all core capabilities including ADR Benchmark, Sequence Rules, and v2.0 strategic features.
- 🛡️ **[ADR Security Benchmark Guide](docs/adr_benchmark.md)** — Deep-dive into the 303-task benchmark suite: attack categories, scoring, report interpretation, and policy recommendations.
- 📋 **[Functional Requirements](design/requirements/functional-requirements.md)** — Full v2.0 functional specification (22 requirements, P0–P2).
- 📋 **[Non-Functional Requirements](design/requirements/non-functional-requirements.md)** — Performance, security, and operational SLAs (21 NFRs, P0–P2).

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).
