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
4. [Spend Caps & Loop Detection](#4-spend-caps--loop-detection)
5. [Async HITL Approval Queue](#5-async-hitl-approval-queue)
6. [Multi-Tenant Teams & Zero-Trust BYOK](#6-multi-tenant-teams--zero-trust-byok)
7. [Device Governance & Sentry Compliance](#7-device-governance--sentry-compliance)
8. [Shared Reference Sections](#8-shared-reference-sections)
9. [Upgrading to Enterprise Fleet](#9-upgrading-to-enterprise-fleet)

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
  export DASHBOARD_API_URL="https://acme-health.vexasec.io"
  export POLICY_READ_SECRET="your-policy-read-secret"
  export GATEWAY_SECRET="your-gateway-secret"

  agentwall start --listen 0.0.0.0:8080 --centralized
  ```

* **Windows (PowerShell):**
  ```powershell
  $env:DASHBOARD_API_URL="https://acme-health.vexasec.io"
  $env:POLICY_READ_SECRET="your-policy-read-secret"
  $env:GATEWAY_SECRET="your-gateway-secret"

  agentwall.exe start --listen 0.0.0.0:8080 --centralized
  ```

---

## 2. OIDC Identity Binding

AgentWall supports two distinct authentication paths:

### Path A: Instant Local Team Management (Default)
Org Admins can immediately invite colleagues under **Users & Roles** using standard email and password credentials. No IdP configuration required.

### Path B: Enterprise SSO Federation (Optional)
When corporate identity compliance is required, bind your corporate Identity Provider (Okta, Microsoft Entra ID, Google Workspace, Keycloak) under **Auth Providers & SSO**.

---

## 3. Vault & API Key Custody (Zero-Trust BYOK)

AgentWall implements customer-isolated encrypted credential storage using AES-256-GCM. 
- SaaS Platform Operators **never** have visibility into customer LLM keys.
- Organization Admins configure keys inside their tenant console under **Settings ➔ LLM Providers**.
- Workstations and Gateways receive scoped credentials with automated TTL expiration.

---

## 4. Spend Caps & Loop Detection

Enforce hard spending ceilings across engineering teams and detect recursive tool call execution loops before token budgets are depleted:
- **Per-Project Budgets:** Scope spend ceilings by project name or cost center.
- **Developer Increase Requests:** Developers can submit requests from the CLI; Admins approve in one click from the console.

---

## 5. Async HITL Approval Queue

Route high-risk tool execution prompts (e.g. `DROP DATABASE`, `aws iam attach-user-policy`) to Slack or Microsoft Teams webhooks. The LLM completion pauses asynchronously until an authorized engineer clicks **Approve** or **Reject**.

---

## 6. Multi-Tenant Teams & Zero-Trust BYOK

The Team SaaS Hub is built on a shared multi-tenant architecture where every data row is scoped to your organization UUID:
- **Trial Visibility:** View remaining days on your 15-day or 30-day free evaluation in the console header.
- **Seat Allocation:** Real-time seat consumption tracker preventing license overages.
- **Seamless Upgrade:** Converting from a trial to a paid annual contract occurs in-place with zero data migration or infrastructure rebuilds.

---

## 7. Device Governance & Sentry Compliance

### 1. Generating Enrollment Tokens
Generate one-time enrollment tokens (OTET) from the console for developer onboarding.

### 2. Device Compliance State Machine
Control Hub tracks heartbeat checkins emitted every 60 seconds from background Sentry daemons:

| Status Badge | State Criteria | System Security Action | Operational Meaning |
|---|---|---|---|
| **`COMPLIANT`** (Green) | Heartbeat $\le 3\text{ min}$, IDE base URLs locked, AND $100\%$ MCP servers wrapped | Device active, full API & proxy access granted | Workstation is fully governed. All tool calls and LLM completions pass through AgentWall DLP & spend ledger. |
| **`OFFLINE`** (Gray) | Heartbeat $> 3\text{ min}$ | Warning logged | Machine is idle, asleep, offline, or sentry daemon connection was temporarily interrupted. |
| **`NON_COMPLIANT`** (Red) | IDE Base URL modified/bypassed OR unwrapped tools detected | Console alerts dispatched, compliance violation logged | **Zero-Trust Drift**: At least 1 IDE or MCP tool has bypassed the proxy. Sentry Daemon executes auto-healing. |
| **`REVOKED`** (Red) | Manually revoked by Admin | 401 Unauthorized returned to device | Hardware certificate invalidated; all telemetry & gateway requests blocked. |

---

## 8. Shared Reference Sections

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

## 9. Upgrading to Enterprise Fleet

When you are ready for Kubernetes high-availability, pure-Rust TLS termination, zero-knowledge CMK SIEM encryption, real-time threat intelligence feeds, and Hardened Agent Container Runtime (HAR):

→ **[Enterprise Fleet User Guide](enterprise_guide.md)**
