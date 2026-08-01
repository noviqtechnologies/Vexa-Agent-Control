# Vexa AgentWall

Vexa AgentWall is an enterprise-grade default-deny security gateway and LLM agent egress proxy operating over MCP (Model Context Protocol), HTTP, HTTPS, and WebSocket connections. It intercepts, sandboxes, audits, and actively enforces strict security policies on AI agent tool calls and outbound LLM API traffic across developer workstations, team staging environments, and production fleets — featuring inline DLP scanning, OIDC identity binding, centralized API key custody, and HMAC-chained tamper-evident audit logging.

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/version-1.0.16-green.svg" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8.svg" alt="Go"></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/frontend-React%20%7C%20TypeScript-blue.svg" alt="React"></a>
</p>

<p align="center">
  <a href="https://vexasec.io/">Website</a> · <a href="docs/user_guide.md">User Guide</a> · <a href="docs/index.md">Documentation</a> · <a href="https://github.com/noviqtechnologies/agentwall/issues">Issues</a> · <a href="mailto:security@vexasec.io">Security</a>
</p>

---

## Installation

AgentWall provides flexible installation methods tailored to your deployment tier:

### 1. Developer / Binary Install (Standalone CLI)
Installs the statically-linked `agentwall` binary into `~/.local/bin/agentwall`:

```bash
curl -fsSL https://vexasec.io/install.sh | sh
```

Or build from source (requires Rust 1.89+):
```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall
cargo build --release
# Binary path: ./target/release/agentwall
```

### 2. Team / Staging Install (Docker Compose)
Run the complete self-hosted Control Hub stack (Go API, React UI, PostgreSQL DB):

```bash
cd control-plane
docker compose up -d --build
```
- **Control Hub UI:** `http://localhost:8081`
- **Control Hub API:** `http://localhost:8400`

### 3. Enterprise Production Install (Kubernetes & Helm)
Deploy the centralized enforcement fleet and Control Hub using the official Helm chart:

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true
```

---

## Architecture

AgentWall implements a Hub-and-Spoke governance model for AI agents across local developer workstations, team environments, and enterprise infrastructure:

![AgentWall System Architecture](docs/system_architecture_diagram.png)

### Deployment Tiers

| Tier | Components | Deployment Target |
|------|-----------|------------------|
| **Local Sidecar** | Gateway + SQLite | Standalone Developer Workstation (`agentwall dev`) |
| **Team Hub** | Gateway + Hub API + Hub UI + PostgreSQL | Team Staging / Shared Server (Docker Compose) |
| **Enterprise** | Gateway Fleet + Hub API Cluster + PostgreSQL | Enterprise Multi-Tenant (Kubernetes & Helm) |

---

## Quick Start

### 1. Local Shadow Proxy & Embedded Dashboard (`agentwall dev`)
Launch the shadow proxy in observation mode. This automatically starts the local Web UI at `http://127.0.0.1:8080` and opens your browser:

```bash
agentwall dev
```
* Use `--no-browser` to prevent automatic browser launching.
* Use `--enforce` to test active DLP and policy blocking locally without running a full gateway deployment.
* Wrap stdio-based MCP servers:
  ```bash
  agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem /workspace
  ```

### 2. Route Local Agent Traffic
Set standard proxy environment variables in your terminal:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export AGENTWALL_PROXY_URL=http://127.0.0.1:8080
python my_agent.py
```

### 3. Wrap Local IDEs (`agentwall wrap`)
Automatically patch IDE configuration files to route all MCP server tool calls through AgentWall:

```bash
# Wrap Claude Desktop
agentwall wrap claude

# Inspect IDE status across all supported editors
agentwall status
```

### 4. Auto-Generate & Lint Policy
Draft a YAML security policy from observed shadow-mode traffic and lint it:

```bash
agentwall generate-policy --decay-window 30
agentwall lint agentwall-policy.yaml
```

---

## Configuration

### Policy YAML Example (v2 Schema)

AgentWall policies operate on a **default-deny** principle (`agentwall-policy.yaml`):

```yaml
version: 2
default_action: deny

identity_binding:
  oidc_discovery_url: "https://auth.corp.com/.well-known/openid-configuration"
  allowed_audiences: ["agentwall-gateway-prod"]
  group_claim: "groups"

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
| `HTTP_PROXY` / `HTTPS_PROXY` | `dev`, client | Standard HTTP proxy routing URLs | - |
| `AGENTWALL_LISTEN` | `start`, `dev` | Gateway listen socket address | `127.0.0.1:8080` |
| `AGENTWALL_POLICY_PATH` | `start` | Path to YAML policy file | - |
| `DASHBOARD_API_URL` | `start`, proxy | Control Hub API endpoint URL | - |
| `POLICY_READ_SECRET` | `start` | Shared secret for policy hot-reload SSE | - |
| `GATEWAY_SECRET` | `start` | Shared secret for telemetry publishing | - |
| `AGENTWALL_LOG_PATH` | `start` | Path to durable audit log file | `audit.log` |
| `AGENTWALL_OIDC_ISSUER` | `start` | OIDC issuer URL for identity binding | - |
| `AGENTWALL_SIEM_BACKEND` | `start` | SIEM backend (`splunk`, `datadog`, `opensearch`, `local`) | `local` |
| `AGENTWALL_SIEM_ENDPOINT` | `start` | SIEM ingestion URL | - |
| `AGENTWALL_SIEM_TOKEN` | `start` | SIEM authentication token | - |
| `AGENTWALL_SHADOW_MODE` | `start` | Observation mode (log without blocking) | `false` |
| `AGENTWALL_DRY_RUN` | `start` | Log policy violations without denying calls | `false` |
| `AGENTWALL_STRICT_CREDENTIAL_SCOPE` | `start` | Reject credential scope mismatches with 403 | `false` |
| `AGENTWALL_TLS_CERT` | `start` | Path to TLS certificate PEM file (`rustls`) | - |
| `AGENTWALL_TLS_KEY` | `start` | Path to TLS private key PEM file (`rustls`) | - |

---

## User Guide & Documentation Links

For detailed, step-by-step documentation, architecture specs, and advanced deployment guides, consult our documentation suite:

- 📖 **[Vexa AgentWall Detailed User Guide](docs/user_guide.md)** — Comprehensive guide covering deployment tiers, v2 policy creation, DLP tuning, OIDC identity binding, Control Hub setup, audit verification, and troubleshooting.
- 📚 **[Documentation Hub](docs/index.md)** — Core documentation index and capabilities overview.
- 🛠️ **[Comprehensive Functional Walkthrough](docs/comprehensive_guide.md)** — Scenario-based command walkthroughs for developers.
- 🏗️ **[Architecture & API Specifications](design/architecture/api-specifications.md)** — Control Hub REST API, SSE streaming schemas, and data flow specifications.

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).