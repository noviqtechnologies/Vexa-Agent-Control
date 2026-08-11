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
├──────────────────────────┬───────────────────────────────┬──────────────────────────────────────┤
│ 1. Local Development     │ 2. Kubernetes Deployment      │ 3. AWS EKS Deployment                │
│    • Local Dev & Testing │    • Production Multi-Replica │    • Production AWS Cloud            │
│    • Docker Compose      │    • High Availability        │    • EKS, EBS CSI, ACM TLS           │
│    • Proof-of-Concept    │    • Helm & Operator CRDs      │    • Step-by-Step Teardown           │
│    → [Local Dev](team_hub_guide/local_development.md) │ → [K8s Guide](team_hub_guide/kubernetes_deployment.md) │ → [AWS EKS Guide](team_hub_guide/aws_eks_deployment.md) │
└──────────────────────────┴───────────────────────────────┴──────────────────────────────────────┘
```

- **[Local Development & Testing Guide](team_hub_guide/local_development.md)** — Step-by-step instructions for running Team Hub locally using Docker Compose (`docker compose up -d --build`), executing native gateways, connecting local agent workflows, and verifying audit logs.
- **[Kubernetes Deployment Guide](team_hub_guide/kubernetes_deployment.md)** — Comprehensive documentation for deploying Team Hub to production Kubernetes clusters using Helm (`./chart`), managing TLS secrets, configuring `AgentWallPolicy` CRDs, and handling zero-downtime rolling upgrades.
- **[AWS EKS Deployment & Uninstallation Guide](team_hub_guide/aws_eks_deployment.md)** — Step-by-step walkthrough for deploying, validating, and cleanly uninstalling Team Hub on AWS EKS using `eksctl`, Helm, AWS EBS CSI storage, and ACM ingress.

---

## Centralized Features & Administration

1. [Centralized Policy Push (SSE)](#1-centralized-policy-push-sse)
2. [OIDC Identity Binding](#2-oidc-identity-binding)
3. [Vault & API Key Custody](#3-vault--api-key-custody)
4. [Spend Caps & Loop Detection](#4-spend-caps--loop-detection)
5. [Async HITL Approval Queue](#5-async-hitl-approval-queue)
6. [Shared Reference Sections](#6-shared-reference-sections)
7. [Upgrading to Enterprise Fleet](#7-upgrading-to-enterprise-fleet)

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

## 4. Spend Caps & Loop Detection

### Spend Caps

Enforce per-session token budgets via YAML policy:

```yaml
spend:
  max_tokens_per_session: 100000
  max_concurrent_sessions: 10
```

**Error when exceeded:**
```json
{
  "error": {
    "code": "SPEND_LIMIT_EXCEEDED",
    "message": "Token budget of 100,000 exceeded for current session"
  }
}
```

To reset or adjust, update the policy and push via the Control Hub (no gateway restart needed).

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
| **`COMPLIANT`** (Green) | Heartbeat $\le 3\text{ min}$ AND $100\%$ MCP servers wrapped | Device active, full API & proxy access granted | Workstation is fully governed. All tool calls pass through AgentWall DLP & policy proxy. |
| **`UNREACHABLE`** (Yellow) | $3\text{ min} < \text{Heartbeat} \le 10\text{ min}$ | Warning logged, retry polling | Machine is idle, asleep, offline, or sentry daemon connection was temporarily interrupted. |
| **`NON_COMPLIANT`** (Red) | Heartbeat $> 10\text{ min}$ OR unwrapped tools detected ($\text{wrapped} < \text{total}$) | SIEM & Slack alerts dispatched, compliance violation logged | **Zero-Trust Breach**: At least 1 unwrapped MCP server exists that bypasses prompt filtering & audit logs. |
| **`REVOKED`** (Red) | Manually revoked by Admin | 401 Unauthorized returned to device | Hardware certificate invalidated; all telemetry & gateway requests blocked. |

#### Why Unwrapped MCP Tools Trigger `NON_COMPLIANT`
AgentWall enforces a Zero-Trust security posture. If an LLM extension or developer installs an MCP tool that is not wrapped by AgentWall (`agentwall wrap`), tool executions (file reads, bash commands, DB queries) bypass the proxy without prompt redacting or DLP audit logging. To preserve enterprise security integrity, the entire workstation is marked **`NON_COMPLIANT`** until `agentwall wrap` is executed.

### 3. Single-Device Revocation & Re-enrollment
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

## 7. Upgrading to Enterprise Fleet

When you are ready for Kubernetes high-availability, pure-Rust TLS termination, zero-knowledge CMK SIEM encryption, real-time threat intelligence feeds, and Hardened Agent Container Runtime (HAR):

→ **[Enterprise Fleet User Guide](enterprise_guide.md)**
