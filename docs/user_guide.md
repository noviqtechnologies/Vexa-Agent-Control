# Vexa AgentWall — Detailed User Guide

Welcome to the detailed user guide for **Vexa AgentWall** — the enterprise LLM agent governance platform and default-deny security gateway.

This guide provides comprehensive instructions for deploying, configuring, securing, and maintaining AgentWall across local development workstations, team staging environments, and production enterprise infrastructure.

---

## Table of Contents

1. [Getting Started for Each Deployment Tier](#1-getting-started-for-each-deployment-tier)
   - [Tier 1: Developer / Workstation](#tier-1-developer--workstation)
   - [Tier 2: Team / Staging](#tier-2-team--staging)
   - [Tier 3: Enterprise Cloud / Production](#tier-3-enterprise-cloud--production)
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

---

## 1. Getting Started for Each Deployment Tier

AgentWall supports three graduated deployment tiers designed to fit seamlessly into any stage of development and enterprise rollout.

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                    DEPLOYMENT TIERS                                     │
├──────────────────────────┬──────────────────────────────┬───────────────────────────────┤
│ Tier 1: Developer        │ Tier 2: Team / Staging        │ Tier 3: Enterprise Production │
│ Single Binary & Sidecar  │ Docker Compose Stack         │ Kubernetes + Helm Fleet       │
│ Shadow Proxy + Local UI  │ Go API + React UI + Postgres │ TLS rustls + SIEM + OIDC SSO  │
└──────────────────────────┴──────────────────────────────┴───────────────────────────────┘
```

### Tier 1: Developer / Workstation

The Developer Tier provides local observation, automatic policy generation, and Safe Mode protection without requiring external servers, Docker, or database setups.

#### Prerequisites
- **Operating System:** Linux, macOS, or Windows (WSL / PowerShell).
- **Network / Utilities:** `curl` and `sh` installed for binary download.
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
  > **Permanent PATH Configuration (Set Once Across Terminals):**
  > - **PowerShell (User Path):**
  >   `[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.local\bin", "User")`
  > - **Command Prompt (CMD):**
  >   `setx PATH "%PATH%;%USERPROFILE%\.local\bin"`
  > - **Git Bash / MSYS2:**
  >   `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile && source ~/.bash_profile`

#### Post-Installation Activities & Verification
1. **Launch Local Observation Proxy:**
   Launch `agentwall dev` to start an observation-mode shadow proxy listening on `127.0.0.1:8080`. This automatically opens the embedded local single-page dashboard in your browser:
   ```bash
   agentwall dev
   ```
2. **Verify Embedded Web Dashboard:**
   Open `http://127.0.0.1:8080` in your web browser to view live traffic events.
3. **Configure Agent HTTP Proxy Environment:**
   Route your local agent HTTP traffic through AgentWall:

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
4. **Wrap Stdio / IDE Tools:**
   * **Stdio Wrapping:** Wrap stdio-based MCP servers directly:
     ```bash
     agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem /workspace
     ```
   * **IDE Wrapping & Diagnostics:** Secure local IDEs (e.g., Claude Desktop, Cursor):
     ```bash
     agentwall wrap claude
     agentwall status
     ```
5. **Auto-Generate YAML Policy:**
   Draft a initial policy from observed local traffic recorded in `~/.agentwall/events.db`:
   ```bash
   agentwall generate-policy --decay-window 30
   ```

---

### Tier 2: Team / Staging

The Team Tier introduces the self-hosted **Control Hub** (React Web Dashboard + Go REST API + PostgreSQL Database) running alongside local or shared gateway instances.

#### Prerequisites
1. **Control Hub Server Host:**
   - Linux / macOS / Windows host with Docker (v24.0+) and Docker Compose (v2.20+) installed.
   - Network ports available: `8081` (UI), `8400` (API), `5433` (Postgres DB).
2. **Gateway Host(s) / Developer Workstations:**
   - Installed `agentwall` binary (`curl -fsSL https://vexasec.io/install.sh | bash` on Linux/macOS or `irm https://vexasec.io/install.ps1 | iex` on Windows).
   - Network connectivity to the Control Hub server on port `8400`.

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
   - **PostgreSQL Database:** `localhost:5433`

2. **Start Gateway Instances Connected to the Control Hub:**
   Configure shared bearer secrets and start gateway instances in centralized mode:

   * **Linux / macOS (Bash / Zsh):**
     ```bash
     export DASHBOARD_API_URL="http://localhost:8400"
     export POLICY_READ_SECRET="team-policy-read-secret"
     export GATEWAY_SECRET="team-gateway-secret"

     agentwall start \
       --listen 127.0.0.1:8080 \
       --centralized \
       --log-path ./team-audit.log
     ```
   * **Windows (PowerShell):**
     ```powershell
     $env:DASHBOARD_API_URL="http://localhost:8400"
     $env:POLICY_READ_SECRET="team-policy-read-secret"
     $env:GATEWAY_SECRET="team-gateway-secret"

     agentwall.exe start `
       --listen 127.0.0.1:8080 `
       --centralized `
       --log-path ./team-audit.log
     ```
   The gateway will bootstrap its policy state directly from PostgreSQL via the Control Hub API and maintain a live SSE connection (`GET /api/v1/events`) for zero-downtime policy hot-reloading.

#### Post-Installation Activities & Verification
1. **Verify Control Hub API Health:**
   Ensure the API backend is healthy and responding:
   ```bash
   curl -i http://localhost:8400/healthz
   ```
   *(Expected response: HTTP `200 OK` with `{"status":"ok"}`).*
2. **Access Team Dashboard:**
   Open `http://localhost:8081` in your browser to view the centralized team dashboard, active policies, and real-time telemetry.
3. **Verify Gateway Hot-Reloading & Logs:**
   Inspect the gateway stdout logs to confirm policy bootstrap success:
   ```
   [INFO] Policy loaded successfully from Control Hub
   [INFO] SSE event subscription connected to http://localhost:8400/api/v1/events
   ```
4. **Verify Audit Log Integrity:**
   Periodically verify the cryptographic HMAC hash chain of the team audit log:
   ```bash
   agentwall verify-log team-audit.log
   ```

---

### Tier 3: Enterprise Cloud / Production

The Enterprise Tier deploys AgentWall as a high-availability, cloud-native gateway fleet on Kubernetes, featuring memory-safe TLS (`rustls`), enterprise OIDC SSO, direct SIEM audit streaming, and zero-downtime policy distribution.

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
   - **OIDC Provider:** Okta, Keycloak, Microsoft Entra ID (Azure AD), Auth0, or PingIdentity configured with an OIDC Discovery URL (`.well-known/openid-configuration`).
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

1. **Verify Kubernetes Workload Health:**
   Confirm all gateway pods, control plane API, database, and frontend deployments are `Running` and `1/1 Ready`:
   ```bash
   kubectl get pods -n agentwall-system -o wide
   ```
2. **Inspect Gateway Container Logs:**
   Verify zero startup errors and successful OIDC/SIEM initialization:
   ```bash
   kubectl logs -n agentwall-system -l app.kubernetes.io/component=gateway --tail=100
   ```
3. **Execute Automated Smoke Test:**
   Run the CLI policy test suite against the deployed gateway endpoint:
   ```bash
   agentwall test --policy agentwall-policy.yaml --gateway https://agentwall.corp.com
   ```
4. **Configure Automated SIEM & OIDC Monitoring:**
   Verify that test events are reaching your SIEM dashboard (e.g. Splunk index `security_events`) and OIDC JWT tokens are properly validated upon agent request.

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
              enum: ["dark", "light"]
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

In your YAML policy, define the `identity` configuration:

```yaml
identity:
  provider: "oidc"
  issuer: "https://auth.yourorg.com/oauth2/default"
  audience: "agentwall-gateway-prod"
  group_claim_key: "groups"    # IdP-specific claim key (e.g., "cognito:groups", "memberOf")
```

Or pass the discovery issuer via command line:
```bash
agentwall start --policy policy.yaml --oidc-issuer https://auth.yourorg.com
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
