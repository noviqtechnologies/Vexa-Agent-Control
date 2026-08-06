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

## Table of Contents

1. [Prerequisites](#1-prerequisites)
   - [Docker Deployment Requirements](#docker-deployment-requirements-devtestingpoc)
   - [Kubernetes Deployment Requirements](#kubernetes-deployment-requirements-production)
2. [Deployment Options](#2-deployment-options)
   - [2.1 Docker Deployment (Local Dev, Testing & PoC)](#21-docker-deployment-local-dev-testing--poc)
   - [2.2 Kubernetes Deployment (Production)](#22-kubernetes-deployment-production)
3. [Post-Installation Verification](#3-post-installation-verification)
4. [Centralized Policy Push (SSE)](#4-centralized-policy-push-sse)
5. [OIDC Identity Binding](#5-oidc-identity-binding)
6. [Vault & API Key Custody](#6-vault--api-key-custody)
7. [Spend Caps & Loop Detection](#7-spend-caps--loop-detection)
8. [Async HITL Approval Queue](#8-async-hitl-approval-queue)
9. [Shared Reference Sections](#9-shared-reference-sections)
10. [Upgrading to Enterprise Fleet](#10-upgrading-to-enterprise-fleet)

---

## 1. Prerequisites

### Docker Deployment Requirements (Dev/Testing/PoC)

For running Team Hub locally or in test/evaluation scenarios across **Linux**, **macOS**, and **Windows**:

- **Git v2.38+** — required to clone the AgentWall repository (if deploying from source).
- **Docker Engine / Docker Desktop v24.0+** — installed and actively running (WSL2 backend required on Windows).
- **Docker Compose v2.20+** — required to orchestrate multi-container services.
- **Available host network ports:**
  - `8081`: Control Hub UI (React Console)
  - `8400`: Control Hub API (Go REST API)
  - `5433`: PostgreSQL Database
  - `8080`: AgentWall Enforcement Gateway

### Kubernetes Deployment Requirements (Production)

For running Team Hub in high-availability production Kubernetes environments:

- **Kubernetes 1.24+** cluster with worker nodes capable of running multi-replica deployments.
- **Helm 3.10+** installed locally.
- **Cluster CNI with NetworkPolicy support** (e.g., Calico, Cilium, Antrea) if enabling egress NetworkPolicy enforcement.
- **Ingress Controller** or **LoadBalancer** for external TLS ingress routing.
- **Persistent Volume provisioner** for PostgreSQL database storage.

---

## 2. Deployment Options

Choose the deployment method that fits your environment requirements:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          Deployment Pathways                            │
├─────────────────────────────────────┬───────────────────────────────────┤
│ 1. Docker Deployment                │ 2. Kubernetes Deployment          │
│    • Local Development              │    • Production Multi-Replica     │
│    • Automated Testing              │    • High Availability            │
│    • Proof-of-Concept (PoC)         │    • Helm & Operator Enforced     │
└─────────────────────────────────────┴───────────────────────────────────┘
```

---

### 2.1 Docker Deployment (Local Dev, Testing & PoC)

Deploy AgentWall Team Hub using Docker Compose for local development, automated testing, and proof-of-concept (PoC) scenarios across Linux, macOS, and Windows.

#### Step 1: Clone repository & navigate to the control plane directory

**Linux / macOS (Bash / Zsh):**
```bash
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall/control-plane
```

**Windows (PowerShell):**
```powershell
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall\control-plane
```

**Windows (Command Prompt - CMD):**
```cmd
git clone https://github.com/noviqtechnologies/agentwall.git
cd agentwall\control-plane
```

> [!TIP]
> **Already have the source code?** If you have already cloned or downloaded the AgentWall repository, simply open your terminal in the repository root folder and run `cd control-plane`.

#### Step 2: Launch the Control Hub container stack

> [!IMPORTANT]
> When running `docker compose up -d`, ensure `HTTP_PROXY` and `HTTPS_PROXY` are **not** set in your terminal session. Docker requires direct internet access to download base images.

**Linux / macOS (Bash / Zsh):**
```bash
unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy
docker compose up -d --build
```

**Windows (PowerShell):**
```powershell
$env:HTTP_PROXY=""
$env:HTTPS_PROXY=""
docker compose up -d --build
```

**Windows (Command Prompt - CMD):**
```cmd
set HTTP_PROXY=
set HTTPS_PROXY=
docker compose up -d --build
```

This provisions the complete local stack:
- **Control Hub UI:** `http://localhost:8081`
- **Control Hub API:** `http://localhost:8400` (REST API at `/api/v1`)
- **PostgreSQL 16 Database:** `localhost:5433`
- **Enforcement Gateway:** `http://localhost:8080`

#### Step 3: Start connected gateway instances

**Linux / macOS:**
```bash
export DASHBOARD_API_URL="http://localhost:8400"
export POLICY_READ_SECRET="local-dev-policy-read-secret"
export GATEWAY_SECRET="local-dev-shared-secret-change-me"

agentwall start \
  --listen 127.0.0.1:8080 \
  --centralized \
  --log-path ./team-audit.log
```

**Windows (PowerShell):**
```powershell
$env:DASHBOARD_API_URL="http://localhost:8400"
$env:POLICY_READ_SECRET="local-dev-policy-read-secret"
$env:GATEWAY_SECRET="local-dev-shared-secret-change-me"

.\agentwall.exe start `
  --listen 127.0.0.1:8080 `
  --centralized `
  --log-path .\team-audit.log
```

The gateway bootstraps its policy state from PostgreSQL via the Control Hub API and maintains a live SSE connection (`GET /api/v1/policy/subscribe`) for zero-downtime policy hot-reloading.

---

### 2.2 Kubernetes Deployment (Production)

For production deployments, use Kubernetes and Helm (`./chart`) to deploy the high-availability gateway cluster, operator, Control Hub API, PostgreSQL database, and Web Console.

#### Step 1: Create the target namespace

```bash
kubectl create namespace agentwall-system
```

#### Step 2: Configure TLS Secrets

Create a Kubernetes TLS secret containing your domain's TLS certificate and private key:

```bash
kubectl create secret tls agentwall-gateway-tls \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n agentwall-system
```

*(For dev/staging clusters without custom certificates, set `gateway.tls.createSelfSigned=true`).*

#### Step 3: Install AgentWall via Helm

Deploy the full Team Control Hub stack using Helm:

```bash
helm install agentwall ./chart \
  --namespace agentwall-system \
  --create-namespace \
  --set gateway.tls.enabled=true \
  --set gateway.tls.secretName=agentwall-gateway-tls \
  --set gateway.replicas=3 \
  --set dashboardApi.enabled=true \
  --set dashboardDb.enabled=true \
  --set dashboardFrontend.enabled=true \
  --set dashboardApi.oidc.issuer=https://your-idp.example.com \
  --set dashboardApi.oidc.clientId=agentwall-dashboard
```

#### Step 4: Apply `AgentWallPolicy` CRDs & Operator Reconciliation

The Helm chart automatically registers the `AgentWallPolicy` Custom Resource Definition (CRD) and deploys `agentwall-operator`.

Apply custom policy CR manifests:

```yaml
# policy.yaml
apiVersion: agentwall.io/v1alpha1
kind: AgentWallPolicy
metadata:
  name: team-production-policy
  namespace: agentwall-system
spec:
  networkPolicyEnforced: true
  policyYaml: |
    version: "2.0"
    mode: "enforce"
    rules:
      - name: "block-env-exfiltration"
        match:
          tools: ["read_file", "execute_shell"]
        action: "block"
```

```bash
kubectl apply -f policy.yaml
```

#### Step 5: Zero-Downtime Upgrades & Policy Hot-Reloading

**Upgrading the Helm release:**
```bash
helm upgrade agentwall ./chart -n agentwall-system
```
*Rolling upgrades maintain request continuity when `gateway.replicas >= 2`.*

**Triggering instant policy hot-reloads:**
```bash
# Method A: HTTP Endpoint
kubectl exec -n agentwall-system deploy/agentwall-gateway -- \
  wget -qO- --post-data '' http://localhost:8080/reload

# Method B: SIGHUP Signal
POD=$(kubectl get pod -n agentwall-system -l app.kubernetes.io/component=gateway -o name | head -1)
kubectl exec -n agentwall-system $POD -- kill -HUP 1
```

#### Step 6: Uninstalling

```bash
helm uninstall agentwall -n agentwall-system
```

---

## 3. Post-Installation Verification

### Step 1 — Verify Control Hub API Health

```bash
curl -i http://localhost:8400/healthz
```

**Expected response:** HTTP `200 OK` with JSON payload `{"status":"ok"}`.

This confirms the REST API and PostgreSQL backend are operational.

---

### Step 2 — Access the Team Management Console

Open `http://localhost:8081` in your browser.

**Default credentials:**

| Mode | Username | Password |
|---|---|---|
| Local Docker Compose (DEV_MODE) | `admin` | `admin` (or any string) |
| Production Mode | `admin` | Bootstrap Token — run `docker compose logs dashboard-api \| grep "Bootstrap Token"` |

**How to populate live dashboard data:**
- Connect a centralized gateway with `DASHBOARD_API_URL` and `GATEWAY_SECRET` set.
- Wrap stdio MCP tools: `agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem "$HOME"`
- Or route agent HTTP traffic through `127.0.0.1:8080`.

**What You Will See:** Active gateways, real-time event telemetry stream, threat heatmaps, and active policy rules.

---

### Step 3 — Verify Policy Bootstrap & Hot-Reloading

In the terminal running `agentwall start --centralized`, you should see:
```
[INFO] Policy loaded successfully from Control Hub
[INFO] SSE event subscription connected to http://localhost:8400/api/v1/policy/subscribe
```

This confirms zero-downtime policy hot-reload is active.

---

### Step 4 — Generate MCP Traffic & Verify Audit Log Integrity

> [!NOTE]
> **Multi-terminal workflow:**
> - **Terminal 1:** Keep `agentwall start` gateway running.
> - **Terminal 2:** Send traffic and run verification commands.

The audit log records **MCP `tools/call` JSON-RPC decisions** (allow/deny/rate-limit). Plain HTTP proxy requests do **not** create audit entries — route traffic from a real AI agent SDK.

**Quick connectivity test** (verifies session start, not audit):

```bash
# Linux/macOS
curl --proxy http://127.0.0.1:8080 \
     -H "Authorization: Bearer test-agent-session-1" \
     http://localhost:8400/healthz
```

```powershell
# Windows PowerShell
curl.exe --proxy http://127.0.0.1:8080 `
         -H "Authorization: Bearer test-agent-session-1" `
         http://localhost:8400/healthz
```

**Send an MCP tool call** (generates audit entries):

```bash
# Linux/macOS
curl -X POST http://127.0.0.1:8080 \
     -H "Authorization: Bearer test-agent-session-1" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/tmp/test.txt"}}}'
```

```powershell
# Windows PowerShell
curl.exe -X POST http://127.0.0.1:8080 `
         -H "Authorization: Bearer test-agent-session-1" `
         -H "Content-Type: application/json" `
         -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"read_file\",\"arguments\":{\"path\":\"/tmp/test.txt\"}}}'
```

> An upstream connection error is expected if no MCP server is running — the audit log entry is still written.

**Verify cryptographic audit log integrity:**

```bash
# Linux/macOS
agentwall verify-log ./team-audit.log

# Windows
.\agentwall.exe verify-log .\team-audit.log
```

**Expected output:** `Audit log verification complete: Hash chain intact. 0 tampered entries.`

---

## 4. Centralized Policy Push (SSE)

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

## 5. OIDC Identity Binding

Bind agent sessions to cryptographic OIDC identities for zero-trust attribution.

See → [Common Reference Guide — OIDC Identity Binding](common_guide.md#setting-up-oidc-identity-binding)

For complete step-by-step setup guides for Okta, Keycloak, Microsoft Entra ID, Auth0, AWS Cognito, Google Workspace, and PingIdentity, see → [OIDC Identity Binding & Auth Provider Guide](oidc_identity_binding.md).

---

## 6. Vault & API Key Custody

AgentWall eliminates long-lived LLM provider API keys on developer machines:

1. **Central Custody** — API keys are encrypted with AES-256-GCM and stored in the Hub database.
2. **Gateway Ingestion** — Authorized gateways fetch encrypted key blocks via `GET /api/v1/credentials/:provider` at bootstrap.
3. **Outbound Injection** — When an agent sends an LLM API request through the gateway, AgentWall verifies authorization, injects the real `Authorization: Bearer sk-...` key, and strips the agent's temporary credential before forwarding to OpenAI/Anthropic.

Configure provider keys via the Team Management Console at `http://localhost:8081` → **Settings → Credentials**.

---

## 7. Spend Caps & Loop Detection

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

## 8. Async HITL Approval Queue

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

## 9. Shared Reference Sections

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

## 10. Upgrading to Enterprise Fleet

When you are ready for Kubernetes high-availability, pure-Rust TLS termination, zero-knowledge CMK SIEM encryption, real-time threat intelligence feeds, and Hardened Agent Container Runtime (HAR):

→ **[Enterprise Fleet User Guide](enterprise_guide.md)**
