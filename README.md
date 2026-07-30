# Vexa AgentWall

Vexa AgentWall is a full egress proxy, default-deny security gateway, and governance platform for AI agents operating over MCP (Model Context Protocol), HTTP, HTTPS, and WebSocket connections. It intercepts, sandboxes, audits, and actively blocks unauthorized agent tool calls, data exfiltration attempts, and prompt injections across developer workstations and centralized production infrastructure.

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License"></a>
  <a href="Cargo.toml"><img src="https://img.shields.io/badge/version-1.0.15-green.svg" alt="Version"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.89%2B-orange.svg" alt="Rust"></a>
  <a href="https://go.dev/"><img src="https://img.shields.io/badge/go-1.22%2B-00ADD8.svg" alt="Go"></a>
  <a href="https://react.dev/"><img src="https://img.shields.io/badge/frontend-React%20%7C%20TypeScript-blue.svg" alt="React"></a>
</p>

<p align="center">
  <a href="https://vexasec.io/">Website</a> · <a href="docs/index.md">Documentation</a> · <a href="https://github.com/noviqtechnologies/agentwall/issues">Issues</a> · <a href="mailto:security@vexasec.io">Security</a>
</p>

---

## Architecture Overview

AgentWall operates as a multi-tier governance ecosystem spanning local developer environments and enterprise cloud infrastructure:

<p align="center">
  <img src="docs/architecture.png" alt="Vexa AgentWall Architecture Diagram" width="100%">
</p>

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   VEXA AGENTWALL ARCHITECTURE                                    │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘

 [ 1. Workstations & IDEs ]        [ 2. Local Egress Proxy ]             [ 3. Production Fleet ]
  VS Code / Claude / Cursor         Stdio & HTTP MCP Agents               Production AI Agents
             │                                    │                                  │
             ▼                                    ▼                                  ▼
 ┌───────────────────────┐            ┌───────────────────────┐            ┌───────────────────┐
 │ AgentWall Watch Daemon│            │   Shadow Proxy        │            │ Enforcement       │
 │ (agentwall watch)     │            │   (agentwall dev)     │            │ Gateway (Rust)    │
 └───────────┬───────────┘            └───────────┬───────────┘            └─────────┬─────────┘
             │ Auto-wrap MCP                      │ Log events                       │ 9-Step Pipeline
             ▼                                    ▼                                  │ (DLP, Identity,
 ┌───────────────────────┐            ┌───────────────────────┐                      │  Safe Mode)
 │  IDE Config Files     │            │ Local SQLite Store    │                      │
 └───────────────────────┘            │ (Auto-Policy Draft)   │                      │
                                      └───────────────────────┘                      │
                                                                                     │ Redacted Events
 ┌───────────────────────────────────────────────────────────────────────────────────┼─────────────┐
 │ 4. Enterprise SaaS Dashboard & Management Platform                                │             │
 │                                                                                   ▼             │
 │   ┌───────────────────────────┐  Remote Policy Sync  ┌──────────────────────────────┐   │
 │   │  React Web Dashboard      │◄────────────────────►│  Dashboard API (Go Backend)  │   │
 │   │  Fleet, Policy Editor,    │                      │  PostgreSQL Store & Auth     │   │
 │   │  SSO, RBAC, Threats       │                      └──────────────────────────────┘   │
 └─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Core Capabilities

### 🔍 IDE Visibility & Persistent Watch Daemon
* **IDE Wrap Status Inspection (`agentwall status`):** Inspects config paths, file existence, path verification posture, and wrap status across 8 supported IDEs.
* **Persistent Event-Driven Watcher (`agentwall watch`):** Background daemon using OS-native filesystem events (`inotify` / `FSEvents` / `ReadDirectoryChangesW`) to automatically wrap new `mcpServers` entries before the IDE's next restart. Includes 300ms debounce and SHA-256 self-write suppression.
* **IDE Discovery Matrix:** Supports Claude Desktop, Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity. *(Note: Claude Desktop path is fully verified; remaining IDE paths are unverified previews).*

### 🛡️ 9-Step Gateway Enforcement Pipeline
Every tool call routed through the centralized Rust gateway undergoes sequential validation:
1. **Identity Validation:** Validates OIDC JWT tokens and extracts subject/aud claims.
2. **Credential Scope:** Enforces mandatory identity scopes (`X-AgentWall-Credential-Scope`) per tool rule.
3. **Default-Deny Policy Engine:** Evaluates tool allowlists, parameter types, bounds, regex patterns, and JSON schema constraints.
4. **Data Loss Prevention (DLP):** Content-aware scanning for secrets and PII (21 built-in patterns + community rules).
5. **Prompt Injection Defense:** 16-pattern injection scanner with a 6-pass normalizer (NFKC, zero-width, homoglyph mapping, URL decode, Base64, leetspeak).
6. **Semantic Anomaly Scanner:** Heuristic scoring interface for payload intent anomalies. *(Heuristic scoring stub; full 3B Phi-4-Mini LLM model in active development).*
7. **Agent-to-Agent (A2A) Protocol Scan:** Inter-agent messaging validation *(Planned Phase 2)*.
8. **Response Scanner:** Scans and redacts secret leakage in tool responses (`--scan-responses`).
9. **HMAC Audit Logger:** Writes tamper-evident, cryptographically chained audit events to disk or SIEM.

### 🛡️ Out-of-the-Box Safe Mode
* **Enabled by default.** Safe Mode evaluates 15 high-signal security rules before policy checks, providing instant protection even in shadow mode (`agentwall dev`).
* **Sensitive File Paths (10 rules):** Blocks access to SSH keys (`.ssh/`, `id_rsa`), `.env` files, AWS credentials (`.aws/credentials`), kubeconfig (`.kube/config`), `/etc/shadow`, Docker config, and sockets.
* **Dangerous Shell Commands (4 rules):** Blocks pipe-to-shell patterns (`curl ... | bash`), netcat listeners (`nc -l`), reverse shells, and root deletion (`rm -rf /`).
* **Cloud Metadata / SSRF (1 rule):** Blocks requests to AWS/GCP/Azure metadata IP addresses (`169.254.169.254`, `metadata.google.internal`).

### 🔐 Hybrid DLP & Secret Detection
* **21 Built-in Regex Patterns:** Detects AWS Keys, GitHub Tokens, OpenAI/Anthropic API Keys, Stripe Keys, SSH Private Keys, Azure Storage Keys, GCP API Keys, Slack Tokens, SendGrid Keys, Database URIs (PostgreSQL, MongoDB, Redis), Credit Cards (Luhn validated), UAE Emirates ID, US SSN, and environment variable references.
* **Deep Scanning:** Base64 recursive decoding (up to 3 layers deep), Shannon entropy analysis (> 4.5 bits/char on strings > 32 chars), and BIP-39 mnemonic seed phrase validation.
* **Community Rules:** Extensible YAML pattern loader for custom organizational secrets.

### 💻 Local Developer Dashboard & Shadow Mode
* **Embedded Web UI:** Minimal single-page event log served directly by `agentwall dev` at `http://127.0.0.1:8080` (automatically opens in browser; use `--no-browser` to disable).
* **Zero External Dependencies:** No Docker, no PostgreSQL, and no signup required. All events are recorded locally to `~/.agentwall/events.db` via SQLite.
* **Real-time Event Inspection:** Real-time visibility into MCP JSON-RPC tool calls, parameter payloads, risk flags, and HTTP/HTTPS traffic. Includes search filtering and CSV/JSON export.
* **Auto-Policy Generator (`agentwall generate-policy`):** Automatically drafts YAML security policies (`agentwall-policy.yaml`) from observed local event logs with self-healing confidence decay scoring.

### 🏢 Enterprise SaaS Dashboard & Policy Synchronization
* **Centralized Policy Management:** Web-based YAML policy editor (`PolicyEditor`) backed by PostgreSQL with live validation and version publishing.
* **Remote Policy Sync (`DASHBOARD_API_URL`):** Deployed gateways automatically fetch active policies (`GET /api/v1/policy/active`) using `POLICY_READ_SECRET` authentication and hot-swap policy structures in memory without dropping connections.
* **Enterprise Auth & SSO:** Local authentication and OIDC/OAuth2 Single Sign-On (Okta, Keycloak, Microsoft Entra ID).
* **Role-Based Access Control (RBAC):** Granular user roles: `Admin`, `Operator`, and `Auditor`.
* **MCP Server Inventory:** Fleet-wide view of wrapped MCP servers discovered across developer workstations.
* **Privacy Boundary:** Enforced Rust `RawEventForRedaction` → `RedactedEvent` boundary strips parameter values and response payloads before publishing to the dashboard API.

### 💰 Spend Caps (Paid Tier)
* **Budget Hierarchy:** Enforces spend limits at User, Group, and Organization levels (User override > Group default > Org default). Limits operate as circuit breakers rather than exact billing sources of truth; always reconcile against actual upstream provider invoices.
* **Concurrency Ceiling Warning:** Spend counters rely on a local SQLite write path. While optimal for typical workloads, scaling above 100 concurrent sessions on a single gateway instance may encounter lock contention. This is an open risk under active evaluation.
* **Period Resets & Timezones:** Budget periods (daily, weekly, monthly) reset strictly at `00:00 UTC`.
* **Local Durable PII Store (Admin API):** The Spend Caps feature is managed via a dedicated Admin API, which is **disabled by default**. Enabling this API transforms the backing SQLite store into a durable, local PII database for spend and audit history. This data never leaves your infrastructure, but you must implement standard data retention and purge policies to remain compliant with privacy regulations.

---

## Installation

### One-Command Quick Install (Linux, macOS, Windows bash)

```bash
curl -fsSL https://vexasec.io/install.sh | sh
```
Installs the statically-linked `agentwall` binary into `~/.local/bin/agentwall`.

### Build from Source
Requires Rust 1.89+ and Go 1.22+ (for dashboard API).

```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall

# Build Rust gateway CLI
cargo build --release
# Binary location: ./target/release/agentwall

# Build Go Dashboard API (optional)
cd control-plane/api && go build -o dashboard-api main.go
```

---

## Quick Start — Local Development & Shadow Mode

### 1. Start the Shadow Proxy & Local Dashboard
Start the zero-dependency shadow proxy in observation mode. This automatically launches the embedded local single-page dashboard at `http://127.0.0.1:8080` and opens your browser:
```bash
agentwall dev
```
* Pass `--no-browser` to prevent automatic browser launching.
* Pass `--enforce` to test active DLP and prompt injection blocking in dev mode without running a gateway deployment.

For stdio-based MCP servers (e.g. Claude Desktop, Cursor):
```bash
agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

### 2. Route Agent Traffic & Inspect Events
Set standard HTTP proxy environment variables for your agent process:
```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export AGENTWALL_PROXY_URL=http://127.0.0.1:8080
python my_agent.py
```
* All intercepted tool calls, HTTP requests, and payloads are stored locally in `~/.agentwall/events.db` (SQLite).
* View live event streams, filter tool calls, and export audit data at `http://127.0.0.1:8080`.

### 3. Generate Security Policy Draft
Draft a security policy YAML from observed traffic patterns with self-healing decay metadata:
```bash
agentwall generate-policy --decay-window 30
# Output: ./agentwall-policy.yaml
```

### 4. Lint and Validate Policy
Validate policy syntax and security schema:
```bash
agentwall lint agentwall-policy.yaml
```
Test policy against a running gateway instance in CI/CD pipelines:
```bash
agentwall test --policy agentwall-policy.yaml --gateway http://localhost:8080 --oidc-token "$TOKEN" ./fixtures.json
```

### 5. Run SaaS Dashboard Stack via Local Docker
To evaluate the full enterprise SaaS Dashboard (React Frontend + Go API + PostgreSQL database) locally on your workstation using Docker Compose:

```bash
# Navigate to the dashboard directory
cd dashboard

# Build and start all services (Frontend, API, Postgres, Mock OIDC)
docker compose up -d --build
```

Or use the automated demo script from the project root:
```bash
# Linux / macOS
./run-demo.sh

# Windows PowerShell
.\run-demo.ps1
```

* **Dashboard Web UI:** Open [http://localhost:3000](http://localhost:3000) in your browser.
* **Dashboard API Endpoint:** Served at `http://localhost:8081`.
* **Connect Gateway to Local Docker Dashboard:**
  ```bash
  export DASHBOARD_API_URL="http://localhost:8081"
  export POLICY_READ_SECRET="dev-policy-read-secret"
  export GATEWAY_SECRET="dev-gateway-secret"
  agentwall start --listen 127.0.0.1:8080
  ```

---

## Ecosystem Integrations & IDE Watcher

AgentWall inspects, wraps, and watches local IDE configurations to ensure MCP tool calls route through the security proxy.

### Target IDE Verification Matrix

| Target IDE | Wrap Command | Watch Target (`agentwall watch`) | Path Status |
|---|---|---|---|
| **Claude Desktop** | `agentwall wrap claude` | `agentwall watch claude` | `[verified]` |
| **Cursor** | `agentwall wrap cursor` | `agentwall watch cursor` | `[unverified]` |
| **VS Code** | `agentwall wrap vscode` | `agentwall watch vscode` | `[unverified]` |
| **JetBrains** | `agentwall wrap jetbrains` | `agentwall watch jetbrains` | `[unverified]` |
| **Zed Editor** | `agentwall wrap zed` | `agentwall watch zed` | `[unverified]` |
| **Cline Extension** | `agentwall wrap cline` | `agentwall watch cline` | `[unverified]` |
| **OpenCode** | `agentwall wrap opencode` | `agentwall watch opencode` | `[unverified]` |
| **Antigravity** | `agentwall wrap antigravity` | `agentwall watch antigravity` | `[unverified]` |

> [!NOTE]
> **Path Verification Notice:** Only **Claude Desktop** has a fully verified configuration path across Windows, macOS, and Linux. Other IDE paths are experimental previews. Run `agentwall status` to inspect path resolution on your system.

### Inspecting IDE Status
```bash
agentwall status
```
Outputs a table detailing target name, resolved path, file existence, wrap status, and verification level.

### Running the Watch Daemon
To watch verified targets (Claude Desktop) for newly added MCP servers:
```bash
agentwall watch --all
```
To watch a specific target:
```bash
agentwall watch claude
```
*(Note: IDEs load `mcpServers` at startup. The watch daemon auto-wraps config entries so they are secured upon the IDE's next restart).*

---

## Production Deployment — Centralized Enforcement Gateway

### 1. Standalone Binary Deployment
```bash
./agentwall start \
  --policy policy.yaml \
  --listen 0.0.0.0:8080 \
  --log-path /var/log/agentwall/audit.log \
  --oidc-issuer https://auth.yourorg.com \
  --siem-backend splunk \
  --siem-endpoint https://splunk.corp.com:8088/services/collector/event \
  --siem-token "$SPLUNK_TOKEN"
```

### 2. Standalone with TLS (`rustls`)
```bash
./agentwall start \
  --policy policy.yaml \
  --listen 0.0.0.0:8443 \
  --tls-cert /etc/agentwall/certs/cert.pem \
  --tls-key /etc/agentwall/certs/key.pem
```

### 3. Remote Policy Auto-Sync with SaaS Dashboard API
When `DASHBOARD_API_URL` is configured, the gateway fetches the active policy directly from PostgreSQL:
```bash
export DASHBOARD_API_URL="http://dashboard-api.internal:8081"
export POLICY_READ_SECRET="your-policy-read-secret"
./agentwall start --listen 0.0.0.0:8080
```
* **Polling & Hot-Reload:** The gateway polls `GET /api/v1/policy/active` every 30 seconds and hot-swaps updated policies into memory without connection interruption.
* **Fallback Behavior:** If the Dashboard API is unreachable during startup, the gateway logs a warning and falls back to `--policy <file>` (if provided) or Safe Mode.

### 4. Zero-Downtime Policy Hot-Reload
* **HTTP API:** `curl -X POST http://localhost:8080/reload`
* **Linux Signal:** `kill -SIGHUP $(pidof agentwall)` — triggers immediate policy reload from disk/remote API, logs timing and policy hash, and broadcasts an SSE update to the dashboard (< 100ms reload time).

### 5. Docker Compose Demo Stack
Run the full SaaS stack (Dashboard API, React Frontend, PostgreSQL, Mock OIDC, and Gateway):
```bash
# Unix / macOS
./run-demo.sh

# Windows PowerShell
.\run-demo.ps1
```
Access the Dashboard UI at `http://localhost:3000` (or `http://localhost:8080/dashboard`).

### 6. Kubernetes Helm Deployment
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

## SaaS Dashboard Reference

The self-hosted AgentWall Control Plane (`control-plane/frontend` + `control-plane/api`) provides web-based management:

| View Panel | Description | Key Features |
|---|---|---|
| **Fleet Overview** | Fleet-wide telemetry and event rates | Active agent nodes, event velocity, risk distribution |
| **Policy Editor** | Centralized YAML policy editor | Web code editor, schema validator, live deployment to fleet |
| **Policy Insights** | Self-healing policy suggestions | Anomaly scoring, confidence decay review, policy recommendations |
| **Identity Governance** | Agent credential governance | Short-lived credential inspection, identity scope bindings |
| **MCP Servers** | Discovered MCP server inventory | Aggregated catalog of tools across all wrapped IDEs |
| **IDE Connections** | Connected IDE workstation status | Status of developer machines and active watch daemons |
| **Auth Providers** | Enterprise SSO / OIDC setup | Configure Okta, Keycloak, Entra ID integration |
| **User Management** | RBAC user administration | Assign Admin, Operator, and Auditor roles |
| **Safe Mode** | Safe Mode rule inspector | Inspect 15 default rules, view rule trigger statistics |
| **Audit Logs** | Security audit trail viewer | Search, filter, and review HMAC-verified audit logs |
| **Threat Intelligence** | Real-time security alert feed | Threat detection counters, attack pattern breakdowns |

---

## Policy Reference (`agentwall-policy.yaml`)

```yaml
version: "2"
default_action: deny

# FR-4 Self-Healing Configuration
self_healing:
  enabled: true
  decay_window: 30d
  auto_suggest: true
  suggest_threshold: 0.9
  approval_required: true

# Enterprise OIDC Authentication
auth:
  provider: okta
  jwks_uri: https://your-org.okta.com/oauth2/default/v1/keys
  audience: agentwall
  issuer: https://your-org.okta.com

# Tool Rules
tools:
  - name: read_file
    action: allow
    credential_scope: ["file:read"]
    parameters:
      - name: path
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - regex: "^/allowed/.*"

  - name: execute_query
    action: allow
    credential_scope: ["db:read", "db:write"]
    parameters:
      - name: query
        type: string
        required: true
```

---

## CLI Command Reference

| Command | Description |
|---|---|
| `agentwall dev` | Start local shadow proxy in observation mode (`--enforce` enables active blocking). |
| `agentwall start` | Launch enforcement gateway server (requires `--policy` or `DASHBOARD_API_URL`). |
| `agentwall status` | Enumerate all 8 IDE targets, showing resolved path, existence, wrap status, and path verification. |
| `agentwall watch` | Run persistent background daemon watching IDE config files to auto-wrap new MCP servers. |
| `agentwall generate-policy` | Draft a YAML security policy from recorded shadow-mode traffic. |
| `agentwall lint <policy>` | Lint YAML policy file for schema errors and security warnings. |
| `agentwall test` | Validate policy against a running gateway instance in CI/CD. |
| `agentwall validate` | Local evaluation of a single tool call payload against a policy. |
| `agentwall promote` | Production readiness check and Ed25519 cryptographic signing. |
| `agentwall wrap <target>` | Patch IDE configuration to route MCP tool calls through AgentWall wrapper. |
| `agentwall unwrap <target>` | Restore original IDE configuration from backup. |
| `agentwall verify-log <log>` | Verify HMAC cryptographic chain integrity of audit logs. |
| `agentwall report <log>` | Generate structured session report (JSON or Text) from audit log. |
| `agentwall identity create` | Provision short-lived scoped credential for an agent. |
| `agentwall identity rotate` | Rotate active agent credentials with zero downtime. |
| `agentwall identity scope` | Set per-tool-call allow/deny scoping for an agent. |
| `agentwall identity audit` | Inspect HMAC-chained identity event log. |

---

## Environment Variables

| Variable | Command | Description | Default |
|---|---|---|---|
| `HTTP_PROXY` / `HTTPS_PROXY` | `dev`, client | Standard HTTP proxy routing URLs | - |
| `AGENTWALL_LISTEN` | `start`, `dev` | Gateway listen socket address | `127.0.0.1:8080` |
| `AGENTWALL_POLICY_PATH` | `start` | Path to YAML policy file | - |
| `DASHBOARD_API_URL` | `start`, proxy | Dashboard API endpoint URL for remote policy sync & ingest | - |
| `POLICY_READ_SECRET` | `start` | Shared bearer secret for fetching active policy from Dashboard API | - |
| `GATEWAY_SECRET` | `start` | Shared bearer secret for publishing redacted events to Dashboard API | - |
| `AGENTWALL_LOG_PATH` | `start` | Path to durable audit log file | `audit.log` |
| `AGENTWALL_OIDC_ISSUER` | `start` | OIDC issuer URL for identity binding | - |
| `AGENTWALL_SIEM_BACKEND` | `start` | SIEM backend (`splunk`, `datadog`, `opensearch`, `local`) | `local` |
| `AGENTWALL_SIEM_ENDPOINT` | `start` | SIEM ingestion URL | - |
| `AGENTWALL_SIEM_TOKEN` | `start` | SIEM authentication token | - |
| `AGENTWALL_SHADOW_MODE` | `start` | Set `true` to run gateway in observation mode | `false` |
| `AGENTWALL_DRY_RUN` | `start` | Log violations without blocking tool calls | `false` |
| `AGENTWALL_STRICT_CREDENTIAL_SCOPE` | `start` | Set `true` to upgrade scope mismatches from WARN to DENY | `false` |
| `AGENTWALL_TLS_CERT` | `start` | Path to TLS certificate PEM file (`rustls`) | - |
| `AGENTWALL_TLS_KEY` | `start` | Path to TLS private key PEM file (`rustls`) | - |

---

## Security Model & Technical Disclosures

**Enforced Guarantees:**
* **Default-Deny Control:** Unlisted tools and non-conforming parameters are blocked by default.
* **Fail-Closed Architecture:** Panic hooks trigger a global connection abort (`JoinSet::abort_all()`) within 1 second on any critical failure.
* **Cryptographic Identity Binding:** Mandates OIDC JWT validation and credential scope matching.
* **Memory-Safe TLS:** TLS termination via `rustls` (pure Rust, zero OpenSSL C-vulnerability footprint).
* **Privacy Boundary:** Strict Rust type-level separation guarantees raw payloads and secrets are never sent to the dashboard.

**Technical Realities & Out of Scope:**
* **IDE Path Verification:** Claude Desktop path resolution is fully verified (`[verified]`). Paths for Cursor, VS Code, JetBrains, Zed, Cline, OpenCode, and Antigravity are `[unverified]` previews.
* **IDE Process Lifecycle:** IDEs load `mcpServers` upon startup. `agentwall watch` updates configuration files on disk, securing connections upon the IDE's next restart.
* **Semantic Scanner:** Current semantic scanning uses a heuristic scoring stub; live 3B model execution is in active development.

---

## Contributing

1. Review open issues or submit a new feature proposal.
2. Fork the repository and create a feature branch (`git checkout -b feature/my-feature`).
3. Ensure formatting and clippy checks pass:
   ```bash
   cargo fmt
   cargo clippy -- -D warnings
   cargo test
   ```
4. Submit a Pull Request.

---

## License

Copyright © [NoviqTech](https://vexasec.io). Licensed under the [Apache License 2.0](LICENSE).