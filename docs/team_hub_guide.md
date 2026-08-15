# Team Control Hub — Deployment & User Guide

> **Target Audience:** DevOps engineers, Engineering leads, and Security teams deploying centralized AI governance across engineering teams, staging, and production environments.

---

## What This Profile Provides

The **Team Control Hub** profile extends AgentWall governance beyond a single developer workstation. It introduces a self-hosted central control plane — a Go REST API, React Management Console, and PostgreSQL database — coordinating distributed gateway instances across your entire organization.

> [!NOTE]
> All Workstation Sidecar capabilities (safe-mode rules, DLP scanning, prompt injection protection, IDE wrapping, ADR benchmark) are **fully included** in this profile. This guide covers centralized deployment and control capabilities.
>
> For Workstation Sidecar setup, see → [Workstation Sidecar Guide](workstation_guide.md).

| Capability | What You Get |
|---|---|
| **Centralized Policy Push (SSE)** | Hot-swap versioned policies across all distributed gateway instances in real time — no service restarts |
| **OIDC Identity Binding** | Map corporate IdP JWT group claims (Okta, Keycloak, Entra ID, Auth0, Ping) to dynamic policy rulesets |
| **Multi-Tenant Policy Sharding** | Dynamically scope policies per `agent_project_id` and `agent_task_id` request headers |
| **Vault & API Key Custody** | Hold LLM provider credentials centrally — agents never receive raw API keys |
| **Async HITL Approval Queue** | Route high-risk tool execution prompts to Slack, Teams, or Webhooks with HMAC callbacks |
| **Spend Caps & Budget Ledger** | Enforce per-session token budgets, model pricing metrics, and concurrency limits |
| **Loop Detection & Countermeasures** | Auto-detect stuck agents in repetitive failure loops and trigger `PivotError` corrections |
| **Multi-Backend SIEM Export** | Stream structured JSON audit events to Splunk HEC, Datadog Logs, or OpenSearch |
| **Team Management Console** | Centralized web dashboard for policy admin and live telemetry |

---

## Guide Index & Deployment Options

Choose the deployment method that fits your environment requirements:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                       Deployment Guides                                         │
├────────────────────────────────────────────────┬────────────────────────────────────────────────┤
│ 1. Local Development & Testing                 │ 2. Kubernetes Production Fleet                 │
│    • Local Dev & Testing                       │    • Production Multi-Replica                  │
│    • Self-Hosted Docker Compose Stack          │    • High Availability Gateway Fleet           │
│    • Go API, React Console, PostgreSQL         │    • Helm Chart (`./chart`) & Operator CRDs    │
│    → [Local Dev](team_hub_guide/local_development.md) │ → [K8s Guide](team_hub_guide/kubernetes_deployment.md) │
└────────────────────────────────────────────────┴────────────────────────────────────────────────┘
```

- **[Local Development & Testing Guide](team_hub_guide/local_development.md)** — Step-by-step instructions for running Team Hub locally using Docker Compose (`docker compose up -d --build`), executing native gateways, connecting local agent workflows, and verifying audit logs.
- **[Kubernetes Deployment Guide](team_hub_guide/kubernetes_deployment.md)** — Comprehensive documentation for deploying Team Hub to production Kubernetes clusters using Helm (`./chart`), managing TLS secrets, configuring `AgentWallPolicy` CRDs, and handling zero-downtime rolling upgrades.

---

## Centralized Features & Administration

1. [Centralized Policy Push (SSE)](#1-centralized-policy-push-sse)
2. [OIDC Identity Binding](#2-oidc-identity-binding)
3. [Vault & API Key Custody](#3-vault--api-key-custody)
4. [Spend Caps & Authoritative Spend Ledger](#4-spend-caps--authoritative-spend-ledger)
5. [Async HITL Approval Queue](#5-async-hitl-approval-queue)
6. [Central Device Governance & Fleet Health](#6-central-device-governance--fleet-health)
7. [Shared Reference Sections](#7-shared-reference-sections)
8. [Upgrading to Enterprise Fleet](#8-upgrading-to-enterprise-fleet)

---

## 1. Centralized Policy Push (SSE)

Gateways maintain a persistent Server-Sent Events connection to receive real-time policy updates without restarts:

```
Gateway                                               Control Hub API
   │                                                         │
   │─── GET /api/v1/policy/subscribe ───────────────────────►│
   │◄── event: policy_update (id: policy-v42) ───────────────│  ← Hot-swaps policy in RAM
   │◄── event: credential_rotation (provider: openai) ───────│  ← Refreshes cached API keys
   │◄── : ping (every 15s) ──────────────────────────────────│  ← Keepalive
```

**Event Handlers:**
- `policy_update` — Atomic in-memory policy swap (via `RwLock<Option<CompiledPolicy>>`) without dropping active TCP connections. **New sessions** pick up the updated policy immediately; in-flight sessions complete under the policy active when they were established.
- `credential_rotation` — Signals a provider API key rotation; gateway fetches updated ciphertext from `GET /api/v1/credentials/:provider`.
- `: ping` — Sent every 15 seconds. No ping within 30 seconds triggers a warning and exponential backoff reconnect.

> [!IMPORTANT]
> When tightening policy during an incident, remember that revoking a tool does not interrupt agents already running. To force immediate effect everywhere, restart the gateway (`docker compose restart gateway`) or have agents open a new session.

**Connecting gateways in centralized mode:**

* **Linux / macOS (Bash / Zsh):**
  ```bash
  export DASHBOARD_API_URL="https://hub.corp.com:8080"
  export POLICY_READ_SECRET="your-policy-read-secret"
  export GATEWAY_SECRET="your-gateway-secret"

  agentwall start --listen 0.0.0.0:8080 --centralized
  ```

* **Windows (PowerShell):**
  ```powershell
  $env:DASHBOARD_API_URL="https://hub.corp.com:8080"
  $env:POLICY_READ_SECRET="your-policy-read-secret"
  $env:GATEWAY_SECRET="your-gateway-secret"

  agentwall.exe start --listen 0.0.0.0:8080 --centralized
  ```

* **Windows (Command Prompt - CMD):**
  ```cmd
  set DASHBOARD_API_URL=https://hub.corp.com:8080
  set POLICY_READ_SECRET=your-policy-read-secret
  set GATEWAY_SECRET=your-gateway-secret

  agentwall.exe start --listen 0.0.0.0:8080 --centralized
  ```

---

## 2. OIDC Identity Binding

Bind agent sessions to cryptographic OIDC identities for zero-trust attribution.

See → [Common Reference Guide — OIDC Identity Binding](common_guide.md#setting-up-oidc-identity-binding)

For complete step-by-step setup guides for Okta, Keycloak, Microsoft Entra ID, Auth0, AWS Cognito, Google Workspace, and PingIdentity, see → [OIDC Identity Binding & Auth Provider Guide](oidc_identity_binding.md).

---

## 3. Vault & API Key Custody

AgentWall eliminates long-lived LLM provider API keys on developer machines:

1. **Central Custody** — API keys are encrypted with AES-256-GCM and stored in the Hub database.
2. **Gateway Ingestion** — Authorized gateways fetch encrypted key blocks via `GET /api/v1/credentials/:provider` at bootstrap.
3. **Outbound Injection** — When an agent sends an LLM API request through the gateway, AgentWall verifies authorization, injects the real `Authorization: Bearer sk-...` key, and strips the agent's temporary credential before forwarding to OpenAI/Anthropic.

Configure provider keys via the Team Management Console at `http://localhost:8081` → **Settings → Credentials**.

---

## 4. Spend Caps & Authoritative Spend Ledger

AgentWall provides centralized, authoritative LLM spend governance backed by PostgreSQL to eliminate unbudgeted overages across all developer workstations and staging fleets.

### Spend Architecture & Enforcement Model

```
Agent Workload               Gateway Proxy (Rust)               Control Hub API (Go / PostgreSQL)
     │                                │                                         │
     │─── POST /v1/chat/completions ─►│                                         │
     │    (model: gpt-4o)             │─── POST /api/v2/spend/authorize ───────►│  ← Lock budget windows FOR UPDATE
     │                                │    (est tokens, max output tokens)      │  ← Check: reserved + settled + reserve <= limit
     │                                │◄── 200 OK (allow, reservation_id) ──────│  ← Reserved in microcents ($1 = 100M µ¢)
     │                                │                                         │
     │                                │─── POST https://api.openai.com ────────►│  (Forward to provider)
     │                                │◄── 200 OK (usage: prompt + comp tokens) │
     │                                │                                         │
     │                                │─── POST /api/v2/spend/settle ──────────►│  ← Convert reserve to actual settlement
     │                                │◄── 200 OK (settled) ────────────────────│  ← Release unused reserve balance
     │◄── 200 OK (LLM Response) ──────│                                         │
```

### Key Capabilities & Invariants
- **Integer Microcents Math**: All monetary amounts are represented as 64-bit integers in microcents (`1 USD = 100,000,000 µ¢`). Floating-point arithmetic is strictly prohibited in ledger operations.
- **Preflight Bounded Reservations**: Before any upstream LLM call is dispatched, the gateway reserves the maximum possible cost based on prompt token estimates and `max_output_tokens`.
- **Fail-Closed Hard Denial**: If `reserved + settled + reserve > limit`, the gateway denies the request immediately with HTTP 429 (`spend_budget_exhausted`). **Zero upstream tokens are consumed**.
- **Immutable Financial Event Log**: Every authorization, settlement, release, and reversal is written to an append-only `spend_events` log with actor identity and timestamp.
- **Operator Increase Requests**: Developers can submit increase requests via the Web Console (`/spend/status`), which administrators can approve or reject with automatic policy version creation in (`/spend/requests`).

**Error Response when Budget is Exhausted:**
```json
{
  "error": {
    "code": "spend_budget_exhausted",
    "message": "LLM spend budget exceeded or preflight authorization denied",
    "scope": "organization",
    "reset_at": "2026-09-01T00:00:00Z"
  }
}
```

### Loop Detection

Intercept agents stuck in repetitive failure patterns:

```yaml
loop_detection:
  threshold: 3
  action: PivotError
```

**Error when triggered:**
```json
{
  "error": {
    "code": "LOOP_DETECTED",
    "message": "Agent loop detected: tool 'read_file' repeated 3 times with identical parameters"
  }
}
```

`PivotError` signals the agent LLM to break out of its loop by attempting a different approach.

---

## 5. Async HITL Approval Queue

Intercept high-risk tool executions and route approval requests to Slack, Teams, or a custom webhook:

```yaml
hitl_escalation:
  enabled: true
  secret_key: "env:AGENTWALL_HITL_SECRET"
  webhook_url: "https://hooks.slack.com/services/..."
```

**How it works:**
1. Agent calls a high-risk tool (e.g., `delete_database`, `execute_shell`).
2. Gateway holds the request and dispatches an HMAC-signed approval payload to the configured webhook.
3. The approver clicks **Approve** or **Deny** in Slack/Teams.
4. The webhook callback (carrying a valid HMAC signature) is received by the gateway.
5. The gateway either forwards the tool call or returns a `403 Denied by HITL` response.

The HITL queue is also visible in the Team Management Console under **Approvals**.

---

## 6. Central Device Governance & Fleet Health

Control Hub provides a dedicated **Device Governance** portal (`/admin/devices`) for managing developer endpoints across macOS, Windows, Linux, and WSL.

### 1. Generating One-Time Enrollment Tokens (OTET)
Admins generate short-lived enrollment tokens in the Web Console or REST API:

* **Linux / macOS (Bash / Zsh):**
  ```bash
  curl -X POST http://localhost:8400/api/v1/admin/enrollment-tokens \
    -H "Authorization: Bearer <ADMIN_SESSION_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{"raw_token": "TOK-892A-3F91", "max_uses": 25, "ttl_hours": 24}'
  ```

* **Windows (PowerShell):**
  ```powershell
  Invoke-RestMethod -Uri "http://localhost:8400/api/v1/admin/enrollment-tokens" `
    -Method Post `
    -Headers @{ "Authorization" = "Bearer <ADMIN_SESSION_TOKEN>" } `
    -ContentType "application/json" `
    -Body '{"raw_token": "TOK-892A-3F91", "max_uses": 25, "ttl_hours": 24}'
  ```

* **Windows (Command Prompt - CMD):**
  ```cmd
  curl.exe -X POST http://localhost:8400/api/v1/admin/enrollment-tokens ^
    -H "Authorization: Bearer <ADMIN_SESSION_TOKEN>" ^
    -H "Content-Type: application/json" ^
    -d "{\"raw_token\": \"TOK-892A-3F91\", \"max_uses\": 25, \"ttl_hours\": 24}"
  ```

Developers use the generated command to onboard against your Control Hub instance:

* **Linux / macOS (Bash / Zsh):**
  ```bash
  curl -fsSL https://vexasec.io/install.sh | AGENTWALL_TOKEN="TOK-892A-3F91" AGENTWALL_HUB_URL="http://hub.yourdomain.com:8081" bash
  ```

* **Windows (PowerShell):**
  ```powershell
  $env:AGENTWALL_TOKEN = "TOK-892A-3F91"
  $env:AGENTWALL_HUB_URL = "http://hub.yourdomain.com:8081"
  irm https://vexasec.io/install.ps1 | iex
  ```

* **Windows (Command Prompt - CMD):**
  ```cmd
  set AGENTWALL_TOKEN=TOK-892A-3F91 && set AGENTWALL_HUB_URL=http://hub.yourdomain.com:8081 && curl.exe -fsSL https://vexasec.io/install.ps1 -o install.ps1 && powershell -ExecutionPolicy Bypass -File install.ps1
  ```

### 2. Device Compliance State Machine
Control Hub tracks heartbeat checkins emitted every 60 seconds from background Sentry daemons:

| Status Badge | State Criteria | System Security Action | Operational Meaning |
|---|---|---|---|
| **`COMPLIANT`** (Green) | Heartbeat $\le 3\text{ min}$, IDE base URLs locked, AND $100\%$ MCP servers wrapped | Device active, full API & proxy access granted | Workstation is fully governed. All tool calls and LLM completions pass through AgentWall DLP & spend ledger. |
| **`OFFLINE`** (Gray) | Heartbeat $> 3\text{ min}$ | Warning logged | Machine is idle, asleep, offline, or sentry daemon connection was temporarily interrupted. |
| **`NON_COMPLIANT`** (Red) | IDE Base URL modified/bypassed OR unwrapped tools detected | Console alerts dispatched, compliance violation logged | **Zero-Trust Drift**: At least 1 IDE or MCP tool has bypassed the proxy. Sentry Daemon executes auto-healing. |
| **`REVOKED`** (Red) | Manually revoked by Admin | 401 Unauthorized returned to device | Hardware certificate invalidated; all telemetry & gateway requests blocked. |

### 3. Fleet Devices & IDE Tamper Log Explorer
In the Web Console:
- **Fleet Devices (`/devices`)**: Real-time view of all enrolled developer workstations, hostnames, OS distribution, protected IDEs (Cursor, VS Code, Zed, Claude), 24h tamper counts, and compliance badges.
- **IDE Tamper Log (`/devices/tamper-log`)**: Immutable audit log of all configuration tampering, proxy bypass attempts, and sub-500ms self-healing actions across developer machines.

### 4. Single-Device Revocation & Re-enrollment
To revoke a compromised or lost device instantly:
1. Navigate to **Device Governance** in the Web Console.
2. Locate the device ID and click **Revoke**.
3. All subsequent heartbeats, telemetry, and policy pulls from that hardware key are blocked immediately (returning 401 Unauthorized) without affecting other team members.

> **Restoring Revoked Devices:**
> To re-authorize a revoked device, generate a new **Enrollment Token** in the Web Console and run `agentwall enroll --token <NEW_TOKEN> --hub-url <HUB_URL>`. Re-enrollment automatically clears the revocation flag and restores the device to **`COMPLIANT`**.

---

## 7. Shared Reference Sections

The following technical reference sections are maintained in the shared [Common Reference Guide](common_guide.md):

| Reference Topic | Link |
|---|---|
| Writing YAML Policies (v2 Schema) | [common_guide.md → YAML Policies](common_guide.md#writing-yaml-policies-v2-schema) |
| Configuring Data Loss Prevention (DLP) | [common_guide.md → DLP](common_guide.md#configuring-data-loss-prevention-dlp) |
| Setting Up OIDC Identity Binding | [common_guide.md → OIDC](common_guide.md#setting-up-oidc-identity-binding) |
| Verifying Audit Logs | [common_guide.md → Audit Logs](common_guide.md#verifying-audit-logs) |
| SIEM Export (Splunk, Datadog, OpenSearch) | [common_guide.md → SIEM Export](common_guide.md#session-reports--siem-export) |
| Stateful Sequence Rules (ADR Framework) | [common_guide.md → Sequence Rules](common_guide.md#stateful-sequence-rules-adr-framework) |
| ADR Security Benchmark Reference | [common_guide.md → ADR Benchmark](common_guide.md#adr-security-benchmark) |
| Troubleshooting Common Issues | [common_guide.md → Troubleshooting](common_guide.md#troubleshooting-common-issues) |

---

## 8. Upgrading to Enterprise Fleet

When you are ready for Kubernetes high-availability, pure-Rust TLS termination, zero-knowledge CMK SIEM encryption, real-time threat intelligence feeds, and Hardened Agent Container Runtime (HAR):

→ **[Enterprise Fleet User Guide](enterprise_guide.md)**
