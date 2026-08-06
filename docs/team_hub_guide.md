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
┌─────────────────────────────────────────────────────────────────────────┐
│                          Deployment Guides                              │
├─────────────────────────────────────┬───────────────────────────────────┤
│ 1. Local Development Guide          │ 2. Kubernetes Deployment Guide    │
│    • Local Dev & Testing            │    • Production Multi-Replica     │
│    • Docker Compose Stack           │    • High Availability            │
│    • Proof-of-Concept (PoC)         │    • Helm & Operator CRDs         │
│    → [Local Dev Guide](team_hub_guide/local_development.md) │    → [K8s Deployment Guide](team_hub_guide/kubernetes_deployment.md) │
└─────────────────────────────────────┴───────────────────────────────────┘
```

- **[Local Development & Testing Guide](team_hub_guide/local_development.md)** — Step-by-step instructions for running Team Hub locally using Docker Compose (`docker compose up -d --build`), executing native gateways, connecting local agent workflows, and verifying audit logs.
- **[Kubernetes Deployment Guide](team_hub_guide/kubernetes_deployment.md)** — Comprehensive documentation for deploying Team Hub to production Kubernetes clusters using Helm (`./chart`), managing TLS secrets, configuring `AgentWallPolicy` CRDs, and handling zero-downtime rolling upgrades.

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
- `policy_update` — Atomic in-memory hot-swap (`ArcSwap`) of gateway policy without dropping active TCP connections.
- `credential_rotation` — Signals a provider API key rotation; gateway fetches updated ciphertext from `GET /api/v1/credentials/:provider`.
- `: ping` — Sent every 15 seconds. No ping within 30 seconds triggers a warning and exponential backoff reconnect.

**Connecting gateways in centralized mode:**
```bash
export DASHBOARD_API_URL="https://hub.corp.com:8080"
export POLICY_READ_SECRET="your-policy-read-secret"
export GATEWAY_SECRET="your-gateway-secret"

agentwall start --listen 0.0.0.0:8080 --centralized
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

## 6. Shared Reference Sections

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
