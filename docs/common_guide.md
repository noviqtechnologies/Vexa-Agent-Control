# Vexa AgentWall — Common Reference Guide

> This guide contains technical reference sections that apply equally across all three AgentWall deployment profiles:
> [Workstation Sidecar](workstation_guide.md) · [Team Control Hub](team_hub_guide.md) · [Enterprise Fleet](enterprise_guide.md)

---

## Table of Contents

1. [Writing YAML Policies (v2 Schema)](#1-writing-yaml-policies-v2-schema)
   - [v2 Policy Architecture](#v2-policy-architecture)
   - [Complete v2 Schema Reference & Example](#complete-v2-schema-reference--example)
   - [Policy Rules & Parameter Validation](#policy-rules--parameter-validation)
2. [Configuring Data Loss Prevention (DLP)](#2-configuring-data-loss-prevention-dlp)
   - [Built-In Regex Detectors (21 patterns)](#built-in-regex-detectors-21-patterns)
   - [Custom Pattern Definitions](#custom-pattern-definitions)
   - [Deep Scanning & Entropy Analysis](#deep-scanning--entropy-analysis)
   - [Tool Response Secret Scanning](#tool-response-secret-scanning)
3. [Setting Up OIDC Identity Binding](#3-setting-up-oidc-identity-binding)
   - [IdP Configuration](#idp-configuration)
   - [JWT Validation & Scope Matching](#jwt-validation--scope-matching)
   - [Agent Short-Lived Credential CLI](#agent-short-lived-credential-cli)
4. [Connecting to the Control Hub](#4-connecting-to-the-control-hub)
   - [Hub Architecture & API Specifications](#hub-architecture--api-specifications)
   - [Real-Time SSE Event Stream](#real-time-sse-event-stream)
   - [Provider API Key Custody & Injection](#provider-api-key-custody--injection)
   - [Telemetry Batch Uploads](#telemetry-batch-uploads)
5. [Verifying Audit Logs](#5-verifying-audit-logs)
   - [HMAC Cryptographic Hash Chaining](#hmac-cryptographic-hash-chaining)
   - [Log Integrity Verification](#log-integrity-verification)
   - [Session Reports & SIEM Export](#session-reports--siem-export)
6. [Stateful Sequence Rules (ADR Framework)](#6-stateful-sequence-rules-adr-framework)
   - [How the Sequence Engine Works](#how-the-sequence-engine-works)
   - [Writing Sequence Rules](#writing-sequence-rules)
   - [Sequence Rule Violations in Audit Logs](#sequence-rule-violations-in-audit-logs)
7. [ADR Security Benchmark](#7-adr-security-benchmark)
   - [Running the Benchmark](#running-the-benchmark)
   - [Reading the Report](#reading-the-report)
   - [Dashboard Integration](#dashboard-integration)
8. [Environment Variables](#8-environment-variables)
9. [War Plan Strategic Features (v2.0)](#9-war-plan-strategic-features-v20)
10. [Troubleshooting Common Issues](#10-troubleshooting-common-issues)
    - [Gateway Startup & YAML Validation Errors](#gateway-startup--yaml-validation-errors)
    - [Tool Call Denials & Safe Mode Interceptions](#tool-call-denials--safe-mode-interceptions)
    - [OIDC & JWT Authorization Failures](#oidc--jwt-authorization-failures)
    - [Control Hub Synchronization Issues](#control-hub-synchronization-issues)
    - [Executable & PATH Troubleshooting](#executable--path-troubleshooting)
    - [IDE Wrapping & Watch Daemon Diagnostics](#ide-wrapping--watch-daemon-diagnostics)
    - [Spend Limit & Loop Detection Triggers](#spend-limit--loop-detection-triggers)

---

## 1. Writing YAML Policies (v2 Schema)

AgentWall policies use strict, explicit YAML configuration files conforming to the **v2 schema**. AgentWall operates on a **default-deny** model: any tool call, parameter value, or LLM prompt not explicitly allowed is blocked.

### Policy Marketplace ("No More Blank YAML")

Writing security policies from scratch can be challenging. AgentWall includes a **Policy Marketplace** in the Web Console (`/policy/marketplace`) with **One-Click Templates**:

- **Safe Cursor Workstation**: Shields `.env`, `id_rsa`, and cloud credentials; blocks destructive shell operations (`rm -rf`, `mkfs`, `dd`); stops post-read exfiltration sequences.
- **Production Data Egress Control**: Locks outbound network requests to internal company domain wildcards, enables loop prevention firewalls, and enforces MCP schema-drift blocking.
- **HIPAA & Healthcare Compliance**: Auto-redacts PHI, SSNs, Medical Record Numbers (MRN), and PII across LLM requests and agent responses.
- **Full Defense in Depth**: Combines developer safety, egress boundaries, and LLM DLP redaction into a comprehensive posture.

Users can preview YAML configurations, apply postures in a single click, or save custom organization templates to PostgreSQL.

### v2 Policy Architecture

The v2 policy schema organizes security controls into distinct sections:

| Section | Purpose |
|---|---|
| `identity_binding` | IdP discovery and claim mappings |
| `policy_bindings` | Role/group mapping to policy rulesets |
| `tools` | Tool call allowlists, parameter constraints, structural validators, and JSON schemas |
| `dlp` | Scannable tool definitions and DLP regex patterns |
| `spend` | Session token budgets and concurrency limits |
| `loop_detection` | Thresholds and actions for agent loop containment |
| `audit` | Local file output and SIEM export endpoints |
| `sequence_rules` | Stateful multi-step attack pattern detection |
| `hitl_escalation` | Human-in-the-loop approval webhook configuration |

---

### Complete v2 Schema Reference & Example

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
              pattern: "^(dark|light)$"
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

# 8. HITL Escalation
hitl_escalation:
  enabled: true
  secret_key: "env:AGENTWALL_HITL_SECRET"
  webhook_url: "https://hooks.slack.com/services/..."

# 9. Stateful Sequence Rules
sequence_rules:
  - id: "no-read-then-exec"
    description: "Block shell execution that follows a file read"
    window: 5
    pattern:
      - tool: read_file
      - tool: execute_command
    action: deny
    message: "Exfiltration chain detected: read_file → execute_command"
```

---

### Policy Rules & Parameter Validation

#### Parameter Types

Parameters support: `string`, `number`, `integer`, `boolean`, and `object`.

#### Structural Validators

| Validator | What It Blocks |
|---|---|
| `path_traversal` | Directory traversal attempts: `../`, `..\`, `%2e%2e/` |
| `no_sensitive_paths` | System paths: `/etc/shadow`, `C:\Windows\System32`, `.ssh`, `.env`, `.aws/credentials` |

#### JSON Schema Validation

For complex object parameters, supply standard JSON Schema contracts under the `schema:` property. The gateway enforces object properties, types, enums, min/max bounds, and required keys.

---

## 2. Configuring Data Loss Prevention (DLP)

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

### Built-In Regex Detectors (21 patterns)

AgentWall ships with **21 built-in regex detectors** sourced from the compiled binary:

| Pattern Name | Description | Regex Pattern | Default Action |
|---|---|---|---|
| `AWS Access Key (AKIA)` | AWS Access Key ID (standard) | `AKIA[0-9A-Z]{16}` | Block |
| `AWS Access Key (ASIA)` | AWS STS Temporary Access Key | `ASIA[0-9A-Z]{16}` | Block |
| `GitHub PAT (ghp)` | GitHub Personal Access Token | `ghp_[0-9a-zA-Z-]{36,}` | Block |
| `GitHub OAuth (gho)` | GitHub OAuth Token | `gho_[0-9a-zA-Z-]{36,}` | Block |
| `GitHub Fine-Grained PAT` | GitHub Fine-Grained Personal Access Token | `github_pat_[0-9a-zA-Z_]{80,96}` | Block |
| `OpenAI API Key` | OpenAI API Key (`sk-...`) | `sk-[a-zA-Z0-9-]{20,}` | Block |
| `Anthropic API Key` | Anthropic API Key (`sk-ant-...`) | `sk-ant-[a-zA-Z0-9_-]{20,}` | Block |
| `SSH Private Key` | PEM / OpenSSH Private Key Block | `-----BEGIN (RSA\|OPENSSH\|EC\|DSA) PRIVATE KEY-----` | Block |
| `Stripe Secret Key` | Stripe Live Secret Key (`sk_live_...`) | `sk_live_[0-9a-zA-Z]{20,}` | Block |
| `Stripe Restricted Key` | Stripe Restricted API Key (`rk_live_...`) | `rk_live_[0-9a-zA-Z]{20,}` | Block |
| `PostgreSQL URI` | PostgreSQL Connection String | `postgres(ql)?://[^:]+:[^@]+@...` | Redact |
| `MongoDB URI` | MongoDB Connection String | `mongodb(\+srv)?://[^:]+:[^@]+@...` | Redact |
| `Redis URI` | Redis Connection String | `redis(s)?://(:[^@]+@)?...` | Redact |
| `US SSN` | US Social Security Number (`XXX-XX-XXXX`) | `\b[0-8][0-9]{2}-[0-9]{2}-[0-9]{4}\b` | Redact |
| `Emirates ID` | UAE Emirates ID (`784-XXXX-XXXXXXX-X`) | `\b784-[0-9]{4}-[0-9]{7}-[0-9]\b` | Redact |
| `Env Var Access` | Environment Variable References (`$VAR_NAME`) | `\$[A-Z_][A-Z0-9_]+` | Warn |
| `Azure Storage Key` | Azure Storage Account Key (`AccountKey=...`) | `(?i)AccountKey=[a-zA-Z0-9+/]{86}==` | Block |
| `GCP API Key` | Google Cloud API Key (`AIza...`) | `AIza[0-9A-Za-z-_]{35}` | Block |
| `Slack Token` | Slack Bot / App / User Token (`xox*-...`) | `xox[baprs]-[0-9a-zA-Z]{10,48}` | Block |
| `SendGrid Key` | SendGrid API Key (`SG....`) | `SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}` | Block |
| `Credit Card Number` | Credit/Debit Card Numbers (13–16 digits) | `\b(?:\d[ -]*?){13,16}\b` | Redact |

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

1. **Recursive Base64 Decoding** — Automatically decodes Base64-encoded payload segments up to 3 layers deep before applying DLP scanners.
2. **Shannon Entropy Analysis** — Flags high-entropy random strings (entropy > 4.5 bits/char on strings longer than 32 characters), identifying obfuscated secret keys.
3. **BIP-39 Mnemonic Validation** — Scans text payloads for 12/24-word cryptocurrency seed phrase combinations.

---

### Tool Response Secret Scanning

Scan and redact secret leakage in incoming tool response payloads before returning them to the agent:

```bash
agentwall start \
  --policy policy.yaml \
  --scan-responses \
  --block-on-secrets \
  --max-scan-bytes 1048576
```

| Flag | Description |
|---|---|
| `--scan-responses` | Enable response body scanning |
| `--block-on-secrets` | Block the entire tool response instead of inline redaction |
| `--max-scan-bytes` | Maximum payload size to scan (default: 1 MB) |

---

## 3. Setting Up OIDC Identity Binding

AgentWall binds agent sessions and tool call execution to cryptographic OIDC identities, ensuring zero-trust attribution and access enforcement.

> [!NOTE]
> For complete step-by-step configuration guides, claims mappings, and policy examples for **Okta**, **Keycloak**, **Microsoft Entra ID**, **Auth0**, **AWS Cognito**, **Google Workspace**, and **PingIdentity**, see the dedicated [OIDC Identity Binding & Auth Provider Guide](oidc_identity_binding.md).

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

1. **Bearer Token Extraction** — Agents pass their OIDC JWT Bearer token in the HTTP `Authorization: Bearer <jwt>` header.
2. **Signature & Claim Verification** — The gateway fetches the IdP's JWKS public keys and verifies signature, expiration (`exp`), issuer (`iss`), and audience (`aud`).
3. **Scope Enforcement** — Each tool rule can mandate required credential scopes:
   ```yaml
   tools:
     - name: "delete_database"
       action: allow
       credential_scope: ["db:admin"]
   ```
4. **Strict Scope Mode** — Upgrade scope mismatches to hard `403 Forbidden` denials:
   ```bash
   export AGENTWALL_STRICT_CREDENTIAL_SCOPE=true
   agentwall start --policy policy.yaml
   ```

---

### Agent Short-Lived Credential CLI

Manage short-lived agent credentials directly via the `agentwall identity` subcommand suite:

```bash
# Provision short-lived credential
agentwall identity create --agent financial-agent-01 --scope "file:read" --ttl 1h

# Rotate agent credentials (zero-downtime with 30-second drain)
agentwall identity rotate --agent financial-agent-01 --drain-secs 30

# Configure per-tool scoping rules
agentwall identity scope --agent financial-agent-01 --tool execute_shell --deny

# Audit identity history (HMAC-chained trail)
agentwall identity audit --agent financial-agent-01 --verify
```

---

## 4. Connecting to the Control Hub

The **Control Hub** acts as the central control plane for AgentWall fleets, providing real-time policy hot-reloading, secret custody, and centralized telemetry aggregation.

### Hub Architecture & API Specifications

- **Base URL:** `https://{hub-host}:8080/api/v1` (or `:8400` in local Docker Compose dev)
- **Protocol:** HTTP/2 over TLS with OIDC JWT Bearer Authentication

---

### Real-Time SSE Event Stream

Gateways maintain a persistent Server-Sent Events (SSE) connection to `GET /api/v1/policy/subscribe`:

```
Gateway                                               Control Hub API
   │                                                         │
   │─── GET /api/v1/events (Accept: text/event-stream) ─────►│
   │◄── event: policy_update (id: policy-v42) ───────────────│ (Hot-swaps policy in RAM)
   │◄── event: credential_rotation (provider: openai) ───────│ (Refreshes cached API keys)
   │◄── : ping (every 15s) ──────────────────────────────────│ (Keepalive ping)
```

| Event | Handler Behavior |
|---|---|
| `policy_update` | Atomic in-memory policy swap (via `RwLock<Option<CompiledPolicy>>`); **new sessions** immediately evaluate against the updated ruleset; in-flight sessions complete under the prior policy |

| `credential_rotation` | Signals key rotation — gateway fetches updated ciphertext from `GET /api/v1/credentials/:provider` |
| `: ping` | Sent every 15 seconds. No ping within 30 seconds triggers warning and exponential backoff reconnect |

---

### Provider API Key Custody & Injection

1. **Central Custody** — API keys are encrypted with AES-256-GCM and stored in the Hub database.
2. **Gateway Ingestion** — Authorized gateways fetch encrypted key blocks via `GET /api/v1/credentials/:provider` at bootstrap.
3. **Outbound Injection** — AgentWall verifies authorization, injects the real `Authorization: Bearer sk-...` key, and strips the agent's temporary credential before forwarding to OpenAI/Anthropic.

---

### Telemetry Batch Uploads

Gateways periodically flush audit logs to the Control Hub via `POST /api/v1/telemetry`:

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

## 5. Verifying Audit Logs

AgentWall records tamper-evident, cryptographically chained audit logs to ensure regulatory compliance and forensic accountability.

### HMAC Cryptographic Hash Chaining

Every audit event contains an HMAC hash calculated from its own payload combined with the HMAC hash of the preceding event:

$$\text{HMAC}_n = \text{HMAC-SHA256}(K, \text{Payload}_n \parallel \text{HMAC}_{n-1})$$

If an attacker attempts to modify, delete, or re-order any historical audit line, the hash chain breaks and verification tools instantly detect the tamper point.

---

### Log Integrity Verification

```bash
# Basic verification
agentwall verify-log audit.log

# With custom signing keys
agentwall verify-log audit.log --key-file /etc/agentwall/audit.key
```

**Sample output:**
```
[INFO] Verifying audit log: audit.log
[INFO] Records checked: 4,821
[SUCCESS] HMAC hash chain intact. Zero tampering detected.
```

---

### Session Reports & SIEM Export

**Generate session reports:**
```bash
agentwall report audit.log --format json --output report.json
```

**Stream to SIEM platforms in real time:**

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

*Fail-Safe:* If SIEM network requests time out (default: 2 seconds), the gateway automatically writes events to the local audit log to prevent data loss.

---

## 6. Stateful Sequence Rules (ADR Framework)

> **ADR** = **AI Detection & Response** — a security framework that extends AgentWall with stateful multi-step attack detection, security benchmarking, and self-healing policy synthesis.

Standard tool allowlisting evaluates each tool call in isolation. Many real-world attacks unfold across multiple steps — a legitimate-looking `read_file` followed by an `http_post` to an external endpoint is an exfiltration chain that neither call reveals alone. AgentWall's **ADR Sequence Engine** solves this with per-session sliding-window call history.

### How the Sequence Engine Works

1. The **`SessionTracker`** maintains a ring buffer of recent tool calls per session, keyed by session ID.
2. On every incoming tool call, the **Sequence Engine** evaluates all configured `sequence_rules` against the trailing call window.
3. If a rule's pattern matches (in order, within the configured `window`), the engine immediately returns a **`deny`** response and logs the violation with the rule ID.
4. Violations appear as **Sequence Rule Violation Badges** in the local dashboard at `http://127.0.0.1:8080`.

### Writing Sequence Rules

```yaml
sequence_rules:
  # Block the read_file → execute_command chain (common exfiltration pattern)
  - id: "no-read-then-exec"
    description: "Block shell execution that follows a file read"
    window: 5          # Look back over the last 5 tool calls in this session
    pattern:
      - tool: read_file
      - tool: execute_command
    action: deny
    message: "Exfiltration chain detected: read_file → execute_command"

  # Block repeated HTTP POSTs (data pump pattern)
  - id: "no-repeated-http-post"
    description: "Block more than 3 HTTP POSTs within a 10-call window"
    window: 10
    pattern:
      - tool: http_post
      - tool: http_post
      - tool: http_post
    action: deny
    message: "Repeated POST pattern blocked"

  # Detect credential file read followed by network call
  - id: "no-cred-read-then-network"
    description: "Block network calls after reading credential files"
    window: 3
    pattern:
      - tool: read_file
      - tool: http_post
    action: deny
    message: "Credential theft chain blocked: credential read → outbound network"
```

### Rule Fields Reference

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | Yes | Unique identifier, referenced in audit logs and dashboard badges |
| `description` | string | No | Human-readable explanation of the attack pattern |
| `window` | integer | Yes | Number of recent tool calls to examine in session history |
| `pattern` | list | Yes | Ordered list of `tool:` names forming the attack chain |
| `action` | enum | Yes | `deny` — block and log; `log` — observe only |
| `message` | string | No | Reason string returned to the agent and written to the audit log |

### Sequence Rule Violations in Audit Logs

```json
{
  "event_type": "sequence_rule_violation",
  "rule_id": "no-read-then-exec",
  "matched_pattern": ["read_file", "execute_command"],
  "session_id": "sess-abc123",
  "blocked_tool": "execute_command",
  "timestamp": "2026-08-04T09:00:00Z"
}
```

---

## 7. ADR Security Benchmark

The `agentwall bench` command runs an offline **303-task benchmark suite** against a local AgentWall gateway instance. It measures how well your current policy configuration detects and blocks 17 categories of AI attack patterns.

### Running the Benchmark

```bash
# Run all 303 tasks across all 17 attack categories
agentwall bench --full

# Or when building from source
cargo run -- bench --full
```

The benchmark completes in under 60 seconds and writes an HTML report to `target/benchmark-report.html`.

```bash
open target/benchmark-report.html            # macOS
xdg-open target/benchmark-report.html       # Linux
Start-Process target/benchmark-report.html  # Windows PowerShell
```

### Reading the Report

The report shows:
- **Overall security grade** (A ≥ 90%, B = 75–89%, C < 75%) with pass/fail counts
- **Per-category pass rates** with plain-English descriptions of what each category tests
- **Comparative baselines** against GuardAgent, LlamaFirewall, and ALRPHFS
- **Policy recommendations** to address failing categories

### Dashboard Integration

The **ADR Benchmark tab** in the local dashboard (`http://127.0.0.1:8080`) renders the latest benchmark report interactively:

```bash
agentwall dev
```

Then click **ADR Benchmark** in the sidebar to view your security score ring and per-category breakdown.

For the full benchmark reference including all 17 attack categories and scoring methodology, see the [ADR Security Benchmark Guide](adr_benchmark.md).

---

## 8. Environment Variables

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
| `AGENTWALL_STRICT_CREDENTIAL_SCOPE` | Upgrade scope mismatches to hard `403 Forbidden` denials | `false` |
| `AGENTWALL_SIEM_BACKEND` | SIEM backend target (`splunk`, `datadog`, `opensearch`, `local`) | `local` |
| `AGENTWALL_SIEM_ENDPOINT` | External SIEM log ingestion endpoint URL | — |
| `AGENTWALL_SIEM_TOKEN` | Authentication token for external SIEM API | — |
| `AGENTWALL_SHADOW_MODE` | Passive observation mode — log events without blocking calls | `false` |
| `AGENTWALL_DRY_RUN` | Log policy violations without denying tool executions | `false` |
| `AGENTWALL_TLS_CERT` | Path to TLS certificate PEM file (`rustls`) | — |
| `AGENTWALL_TLS_KEY` | Path to TLS private key PEM file (`rustls`) | — |
| `AGENTWALL_HITL_SECRET` | Cryptographic HMAC secret for HITL approval callbacks | — |
| `AGENTWALL_THREAT_INTEL_URL` | Vexa threat intelligence SSE feed URL | — |
| `AGENTWALL_CMK_KEY_FILE` | Path to Customer-Managed Key file for zero-knowledge SIEM encryption | — |

---

## 9. War Plan Strategic Features (v2.0)

### Passive Shadow AI Risk Delta Reports

Run AgentWall in non-blocking observation mode to audit agent traffic before enabling enforcement:

```bash
agentwall start --shadow-mode --log-path audit.log
# Generate Risk Delta report summarizing hypothetical blocks and PII exfiltrations
agentwall report audit.log --risk
```

### Vexa Security Scanning (vexa-scan)

Scan MCP server definitions and security policy schemas before deployment:

```bash
agentwall scan --path agentwall-policy.yaml
```

### WebSocket Egress Tunneling

Bridge cloud agents with local MCP tools over a secure Rust WebSocket tunnel with sub-5ms latency and inline DLP:

```bash
agentwall start --centralized --listen 0.0.0.0:8080
```

### Human-in-the-Loop (HITL) Webhooks

Intercept dangerous commands and require HMAC-signed approval via Slack, Teams, or the Control Hub UI:

```yaml
hitl_escalation:
  enabled: true
  secret_key: "env:AGENTWALL_HITL_SECRET"
  webhook_url: "https://hooks.slack.com/services/..."
```

### Hardened Agent Containers (HAR)

Deploy AgentWall as an entrypoint proxy inside OCI container environments (Kubernetes) using the lightweight image (<100MB):

```bash
docker build -f Dockerfile.har -t agentwall-har:v2.0 .
```

---

## 10. Troubleshooting Common Issues

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
- **Solution:** Check tool parameter inputs. Ensure secrets are referenced via secure environment variables or provider key custody rather than raw text.

---

## 2.5 CLI Tooling Reference (License & Compliance)

### License Key Tooling (`agentwall license`)

AgentWall Team & Enterprise licensing utilizes Ed25519-signed JWT license tokens.

```bash
# 1. Generate an Ed25519 signing keypair for license issuance
agentwall license keygen --output /path/to/license_key

# 2. Generate a signed license JWT token for an organization
agentwall license generate \
  --org "AcmeCorp" \
  --tier "team" \
  --seats 25 \
  --days 365 \
  --signing-key /path/to/license_key.priv \
  --features spend_caps,siem_aggregation
```

### Compliance Report Generator (`agentwall compliance`)

Generate automated compliance mapping reports (SOC2, ISO 27001, NIST SP 800-207, EU AI Act, HIPAA) directly from audit logs:

```bash
# Generate markdown compliance report
agentwall compliance report --log-path ./audit.log --format markdown --output ./compliance_report.md

# Output JSON report to stdout
agentwall compliance report --log-path ./audit.log --format json
```

### Identity JWKS Export (`agentwall identity export-jwks`)

Export public JWKS keys from an OIDC issuer for air-gapped or offline gateway deployments:

```bash
agentwall identity export-jwks --issuer https://auth.yourorg.com --output ./jwks.json
```

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

#### Error 405 `Method Not Allowed` when fetching remote policy
```
{"error":"Dashboard API returned HTTP 405 Method Not Allowed for http://...:8080/api/v1/policy/active: Method Not Allowed","event":"policy_fetch_remote_failed","level":"error"}
```
- **Cause:** `DASHBOARD_API_URL` was pointed to the Gateway proxy ingress port (port `8080`) instead of the Control Plane API port (port `8081`).
- **Solution:** Ensure `DASHBOARD_API_URL` uses port `8081` (e.g. `http://<alb-domain>:8081` or `http://127.0.0.1:8081`), not the gateway proxy port `8080`.

---

### Executable & PATH Troubleshooting

#### Issue: `agentwall: command not found` across terminal restarts

Persist the installation directory in your shell configuration:

- **Linux / WSL (Bash):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc
  ```
- **macOS / Linux (Zsh):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc && source ~/.zshrc
  ```
- **Fish Shell:**
  ```fish
  fish_add_path ~/.local/bin
  ```
- **Windows (PowerShell):**
  ```powershell
  [Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", "User") + ";$env:USERPROFILE\.local\bin", "User")
  ```
- **Windows (CMD):**
  ```cmd
  setx PATH "%PATH%;%USERPROFILE%\.local\bin"
  ```
- **Windows (Git Bash / MSYS2):**
  ```bash
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bash_profile && source ~/.bash_profile
  ```

#### Issue: `✖ Stdio proxy error: No such file or directory (os error 2)`

- **Cause 1 — `npx` not in PATH:** On macOS, Node/nvm/brew/fnm binaries may reside in a non-standard path that `agentwall` cannot resolve automatically.
  - **Solution:** Pass the full path using `$(which npx)`:
    ```bash
    agentwall dev --stdio -- $(which npx) -y @modelcontextprotocol/server-filesystem ~/workspace
    ```

- **Cause 2 — Target directory missing:**
  - **Solution:** Ensure the path exists before running:
    ```bash
    mkdir -p ~/workspace
    agentwall dev --stdio -- npx -y @modelcontextprotocol/server-filesystem ~/workspace
    ```

### Environment Variables Reference

| Environment Variable | Default Value | Description |
|---|---|---|
| `AGENTWALL_TOKEN` | *None* | One-Time Enrollment Token (OTET) for automated workstation onboarding |
| `DASHBOARD_API_URL` | `http://localhost:8400` | Central Control Hub API endpoint |
| `GATEWAY_SECRET` | *None* | Shared gateway bearer token for Control Hub API ingestion |
| `POLICY_READ_SECRET` | *None* | Bearer secret for pulling remote policies from Control Hub |
| `AGENTWALL_HEARTBEAT_INTERVAL` | `60` | Background Sentry daemon health ping interval in seconds |
| `AGENTWALL_LOG_LEVEL` | `info` | Gateway logging verbosity (`trace`, `debug`, `info`, `warn`, `error`) |

---

### Multi-OS Troubleshooting & System Integration

#### Linux DBus SecretService & Headless Fallback
- **Issue:** On headless Linux servers (SSH/CI-CD) without an active X11/DBus session bus, `keyring` may fail to store Ed25519 device keys.
- **Solution:** AgentWall automatically falls back to Machine-ID derived AES-256 encrypted file storage (`/etc/machine-id` or `/var/lib/dbus/machine-id`) at `~/.agentwall/device_identity.key` with restricted POSIX `0600` permissions.

#### macOS Keychain Authorization Prompts
- **Issue:** macOS prompts for keychain access approval when running `agentwall enroll`.
- **Solution:** Click **Always Allow** to permit the `agentwall` binary to read and store the Ed25519 device private key in macOS Keychain Services (`security-framework`).

#### Windows Session 0 Multi-User Profile Resolution
- **Issue:** When running as a Windows Service under `NT AUTHORITY\SYSTEM` in Session 0, `%USERPROFILE%` evaluates to `C:\Windows\System32\config\systemprofile`.
- **Solution:** AgentWall's Windows SCM engine automatically resolves all human user profile directories in `C:\Users\*` via `ProfileList` registry keys (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`), watching and locking IDE configs across all developer accounts on the machine.

#### WSL / WSL2 Path Interop
- **Issue:** Developer uses Cursor or Claude Desktop on Windows host while running agent scripts inside WSL2.
- **Solution:** AgentWall in WSL automatically detects `/proc/sys/kernel/osrelease` containing `microsoft` and resolves Windows host paths (`/mnt/c/Users/<user>/AppData/Roaming/...`) alongside Linux native paths (`~/.config/`).

---

### IDE Wrapping & Watch Daemon Diagnostics

#### Issue: IDE MCP tools not routing through AgentWall after `agentwall wrap`

- **Cause:** IDE processes (Claude Desktop, Cursor, VS Code) read `mcpServers` configuration strictly at application startup.
- **Solution:** Restart the IDE process completely after running `agentwall wrap <target>`.
- **Diagnostic:** Run `agentwall status` to inspect path resolution, file existence, and wrap status across all IDE targets.

---

### Spend Limit & Loop Detection Triggers

#### Error 429 `spend_budget_exhausted` (Authoritative PostgreSQL Ledger)
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
- **Cause:** Pre-dispatch authorization checked active budget windows in PostgreSQL (`reserved + settled + reserve > limit`) and rejected the request to prevent financial overruns. Zero provider tokens were consumed.
- **Solution:** Submit an increase request via the Web Console (`/spend/status`) or ask an administrator to publish an updated budget limit (`/spend/limits`).

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
