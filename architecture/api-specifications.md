# Vexa Agent Control — API & Contract Specifications

**Project:** Vexa Agent Control  
**Document Version:** 2.0 (PRD P0 Baseline Specification)  
**Last Updated:** 2026-10-15  
**Document Status:** Approved Engineering Specification  
**Conforms to:** [vexa-agent-control-requirements.md](file:///c:/agentcontrol/agentcontrol/PRD/pending/vexa-agent-control-requirements.md) (24 P0 FRs, 14 P0 NFRs)  

---

## 1. Self-Hosted Control Hub REST API

**Base URL:** `https://{hub-host}:8080/api/v1`  
**Authentication:** OIDC JWT Bearer Token (Authorization: Bearer <jwt>) or Gateway mTLS Certificate  
**Content-Type:** `application/json` (unless noted)  

---

### 1.1 Gateway Bootstrap & Snapshot State
#### `GET /api/v1/bootstrap`
Returns the complete authoritative state snapshot required for gateway initialization (**FR-017**, **FR-040**).

**Query Parameters:**
| Parameter | Type | Required | Description |
|---|---|---|---|
| `gateway_id` | string | Yes | Unique cryptographic identifier of the requesting gateway |
| `platform_os` | string | Yes | Host OS (`windows`, `linux`, `macos`) |

**Response 200 OK:**
```json
{
  "policies": [
    {
      "id": "7b8f9e2d-3c4b-5a6f-7e8d-9c0b1a2f3e4d",
      "name": "enterprise-standard",
      "version": 42,
      "schema_version": "v2",
      "sha256_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
      "yaml_content": "version: 2\ndefault_action: deny\n..."
    }
  ],
  "credentials": [
    {
      "provider": "openai",
      "credential_id": "c1d2e3f4-a5b6-7c8d-9e0f-1a2b3c4d5e6f",
      "rotation_version": 4
    }
  ],
  "config": {
    "policy_cache_ttl_seconds": 3600,
    "sse_heartbeat_interval_seconds": 15,
    "fail_closed_mode": true
  }
}
```

---

### 1.2 SSE Delta Event Stream
#### `GET /api/v1/events`
Persistent HTTP Server-Sent Events stream delivering real-time delta updates to connected gateways.

**Headers:**
- `Accept: text/event-stream`
- `Last-Event-ID: {event_id}` (Supports reconnection replay)

**Delivered Event Types:**
```
event: policy_update
id: policy-v43-1729000000
data: {"policy_id": "7b8f9e2d-3c4b-5a6f-7e8d-9c0b1a2f3e4d", "name": "enterprise-standard", "version": 43, "sha256_hash": "b2c3..."}

event: credential_rotation
id: cred-openai-v5
data: {"provider": "openai", "rotation_version": 5, "credential_id": "c1d2e3f4-a5b6-7c8d-9e0f-1a2b3c4d5e6f"}

event: emergency_revocation
id: revoke-agent-88
data: {"target_type": "session", "target_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", "reason": "Compromised prompt detected"}

: ping
```
*Keepalive ping sent every 15 seconds. Gateways treat 30s of silence as a transport disconnect and trigger reconnection backoff.*

---

### 1.3 Declarative Policy Management
#### `GET /api/v1/policies/:id`
Retrieves the raw declarative YAML content for an active or historical policy.

**Response 200 OK:**
```json
{
  "id": "7b8f9e2d-3c4b-5a6f-7e8d-9c0b1a2f3e4d",
  "name": "enterprise-standard",
  "version": 42,
  "schema_version": "v2",
  "sha256_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
  "yaml_content": "version: 2\ndefault_action: deny\ntools:\n  ...",
  "created_at": "2026-10-15T10:00:00Z",
  "created_by": "secops-admin@corp.com"
}
```

#### `POST /api/v1/policies`
Creates a new policy or registers a new immutable version of an existing policy (**FR-017**).

**Request Body:**
```json
{
  "name": "enterprise-standard",
  "yaml_content": "version: 2\ndefault_action: deny\ntools:\n  - name: read_file\n    action: allow\n    parameters:\n      path:\n        regex: \"^/workspace/.*\"\n",
  "schema_version": "v2"
}
```

**Response 201 Created:**
```json
{
  "id": "7b8f9e2d-3c4b-5a6f-7e8d-9c0b1a2f3e4d",
  "name": "enterprise-standard",
  "version": 43,
  "sha256_hash": "b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef01",
  "is_active": true
}
```
*Validation: The Hub strictly lints the YAML against the v2 schema (disallowing unknown fields) and compiles all regular expressions before committing. Returns HTTP 422 on validation failure.*

---

### 1.4 Encrypted Provider Credential Distribution
#### `GET /api/v1/credentials/:provider`
Fetches the AES-256-GCM encrypted provider secret (**FR-011**).

**Response 200 OK:**
```json
{
  "provider": "openai",
  "credential_id": "c1d2e3f4-a5b6-7c8d-9e0f-1a2b3c4d5e6f",
  "key_ciphertext": "V2hhdCBnb2VzIGhlcmUgaXMgZW5jcnlwdGVk...",
  "key_nonce": "MTIzNDU2Nzg5MDEy",
  "key_tag": "YWJjZGVmZ2hpamtsbW5vcA==",
  "rotation_version": 4
}
```

---

### 1.5 Decoupled Telemetry Ingest
#### `POST /api/v1/telemetry`
Batch ingestion endpoint for audit records dispatched by gateway outbox workers (**FR-014**, **FR-015**).

**Request Body:**
```json
{
  "gateway_id": "gw-lon-01",
  "batch_seq": 8842,
  "events": [
    {
      "ts": "2026-10-15T12:00:00.123456Z",
      "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
      "event": "tool_allow",
      "tool_name": "read_file",
      "params_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "decision": "ALLOW",
      "reason_code": "RULE_MATCH_ALLOW",
      "policy_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
      "entry_index": 1042,
      "hmac": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"
    }
  ]
}
```
**Response 202 Accepted:** Telemetry queued for asynchronous PostgreSQL insertion.

---

### 1.6 Fleet Posture & Emergency Stop
#### `POST /api/v1/emergency-stop`
Initiates an immediate cryptographic kill-switch across target agents, sessions, or tools (**FR-016**).

**Request Body:**
```json
{
  "target_type": "session",
  "target_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "scope": "immediate_containment",
  "reason": "Hostile prompt injection exfiltration attempt detected"
}
```
**Response 200 OK:**
```json
{
  "status": "REVOKED",
  "unacknowledged_gateways": []
}
```

---

## 2. Gateway Local Management & IPC API

Provides low-latency administrative management over OS-native IPC (Windows Named Pipe / POSIX UDS `~/.agentcontrol/agentcontrol.sock`) and loopback HTTP (`http://127.0.0.1:18080`).

### 2.1 Posture & Readiness Probe (FR-001, FR-021)
#### `GET http://127.0.0.1:18080/health`
Distinguishes process liveness from actual enforcement readiness:

**Response 200 OK:**
```json
{
  "status": "HEALTHY",
  "liveness": true,
  "enforcement_ready": true,
  "active_mode": "ENFORCED",
  "policy": {
    "version": 42,
    "sha256": "a1b2c3d4...",
    "staleness_seconds": 120
  },
  "audit_writer": {
    "status": "DURABLE_SYNC_OK",
    "queue_depth": 0,
    "last_fsync_ms": 1.12
  },
  "storage": {
    "disk_free_bytes": 48293021696,
    "wal_size_bytes": 1048576
  }
}
```

#### `GET http://127.0.0.1:18080/posture`
Returns the machine-readable capability manifest and protection status per configured client (**FR-001**):

**Response 200 OK:**
```json
{
  "gateway_id": "gw-workstation-wasim",
  "clients": [
    {
      "name": "cursor",
      "transport": "http_proxy",
      "posture": "ENFORCED",
      "last_verified_at": "2026-10-15T11:45:00Z",
      "blind_spots": ["Direct native terminal bash execution ungoverned"]
    },
    {
      "name": "claude_desktop",
      "transport": "stdio_proxy",
      "posture": "ENFORCED",
      "last_verified_at": "2026-10-15T11:45:00Z",
      "blind_spots": ["Completions route out-of-band directly to Anthropic Cloud"]
    }
  ]
}
```

---

### 2.2 Exact-Action HITL Resolution (FR-009)
#### `GET http://127.0.0.1:18080/api/v1/approvals`
Lists currently pending human approval tickets.

#### `POST http://127.0.0.1:18080/api/v1/approvals/:id/resolve`
Resolves a pending ticket using single-use CAS verification:

**Request Body:**
```json
{
  "action": "APPROVE",
  "expected_action_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "justification": "Approved for project build"
}
```
**Response 200 OK:**
```json
{
  "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "RESERVED",
  "auth_token": "cas_auth_single_use_99a8b7"
}
```

---

### 2.3 Gateway CLI Canonical Reference
The `agentcontrol` CLI provides 12 canonical commands for local workstation operations:

| Command Line Syntax | Operational Purpose | Key Flags & Parameters |
|---|---|---|
| `agentcontrol start --standalone` | Starts local gateway daemon in 100% offline standalone mode | `--port 18080`, `--policy <path>`, `--include-params` |
| `agentcontrol clients` | Inspects installed coding assistants and detection status | `--json` |
| `agentcontrol connect <client>` | Wraps target assistant with non-destructive journal backup | `cursor`, `claude`, `claude-code`, `antigravity`, `codex` |
| `agentcontrol disconnect <client>`| Atomically restores original assistant configuration | `--force` |
| `agentcontrol status` | Displays live posture, listener health, and active rule count | `--watch`, `--detailed` |
| `agentcontrol verify-log` | Verifies HMAC-SHA256 audit chain from local key offline | `--log-file <path>`, `--key-file <path>` |
| `agentcontrol kill` | Executes emergency stop on agent session or active tool | `--session <uuid>`, `--tool <name>`, `--all` |
| `agentcontrol doctor` | Validates loopback listeners, file ACLs, and OS permissions | `--fix` |
| `agentcontrol support-bundle` | Exports sanitized diagnostic bundle (redacted secrets) | `--output <path>` |
| `agentcontrol repair` | Heals drifted configuration files back to pristine baseline | `--client <name>` |
| `agentcontrol rotate-local-token`| Generates new local IPC bearer token and updates ACLs | `--silent` |
| `agentcontrol reset-local-state` | Safely clears local traces while preserving audit ledger | `--confirm` |

---

## 3. Declarative Policy Specification Schema (YAML v2)

```yaml
# Vexa Agent Control Policy Specification v2 (FR-017, FR-040)
version: 2
default_action: deny

metadata:
  name: "engineering-standard-policy"
  version: 42
  description: "Standard developer workstation policy for coding agents"

# 1. Identity & Role Mappings (FR-012)
identity_binding:
  oidc_discovery_url: "https://idp.corp.com/.well-known/openid-configuration"
  allowed_audiences: ["vexa-gateway"]
  group_claim: "groups"

policy_bindings:
  - group: "platform-engineers"
    policy: "elevated-debug"
  - sub: "dev-local-user"
    policy: "developer-standard"

# 2. Tool-Level Pre-Execution Authorization Rules (FR-002, FR-007, FR-008)
tools:
  - name: "read_file"
    action: allow
    risk: low
    schema_drift:
      action: block # FR-007: Block if tool schema changes
      expected_digest: "sha256:7c2e4b8a910f1d2e3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d"
    parameters:
      path:
        type: string
        regex: "^(/Users/[a-z]+/workspace/.*|C:\\\\Users\\\\[a-z]+\\\\workspace\\\\.*)"
        deny_patterns: ["\\.ssh", "\\.aws", "\\.gnupg", "\\.env", "id_rsa"]
        structural_validators:
          - type: "path_traversal"
          - type: "no_sensitive_paths"

  - name: "execute_bash"
    action: require_approval # FR-009: Triggers exact-action HITL CAS
    risk: high
    parameters:
      command:
        type: string
        deny_patterns: ["rm\\s+-rf\\s+/", "chmod\\s+777", "mkfs", "dd\\s+if="]

# 3. Inline DLP & Secret Hygiene (FR-010, NFR-006)
dlp:
  scannable_tools: ["read_file", "execute_bash", "fetch_url"]
  safe_tools: ["list_directory"]
  patterns:
    - name: "aws_access_key"
      regex: "AKIA[0-9A-Z]{16}"
      action: block
    - name: "private_key"
      regex: "-----BEGIN [A-Z ]*PRIVATE KEY-----"
      action: block
    - name: "credit_card"
      regex: "\\b\\d{4}[- ]?\\d{4}[- ]?\\d{4}[- ]?\\d{4}\\b"
      action: redact # Replaces with [REDACTED:credit_card]
    - name: "high_entropy_secret"
      min_entropy: 4.5
      min_length: 20
      action: block

# 4. Bounded Autonomy & Loop Controls (FR-034)
autonomy:
  max_run_duration_seconds: 1800 # Max 30 minutes
  max_tool_calls_per_run: 50
  sliding_window_rate_limit:
    max_calls: 10
    window_seconds: 1
  loop_detection:
    identical_call_threshold: 3
    action: PivotError # Injects structured guidance to agent

# 5. Model Egress & Spend Ceilings (FR-034)
spend:
  allowed_models:
    - "openai/gpt-4o"
    - "openai/gpt-4o-mini"
    - "anthropic/claude-3-7-sonnet"
    - "gemini/gemini-2.0-flash"
  max_spend_microcents_per_session: 500000000 # $5.00 limit
  max_concurrent_sessions: 5

# 6. Audit & Outbox Pipeline (FR-014, FR-015, NFR-007)
audit:
  log_file: "~/.agentcontrol/audit.jsonl"
  fsync_mode: "synchronous_pre_dispatch" # High-impact actions wait for fsync
  fail_closed_on_audit_error: true
  siem_export:
    type: "splunk_hec"
    endpoint: "https://splunk.corp.com:8088/services/collector"
    token: "${SPLUNK_HEC_TOKEN}"
    queue_capacity: 5000
```

---

## 4. Capability Manifest Schema (FR-001, NFR-012)

Published per release to formally declare the supported enforcement boundaries and uncovered blind spots for each client:

```json
{
  "$schema": "https://vexasec.io/schemas/capability-manifest-v2.json",
  "manifest_version": "2.0.0",
  "client_target": "claude_desktop",
  "enforcement_adapter": "stdio_proxy",
  "capabilities": {
    "mcp_tools_call": {
      "supported": true,
      "modes": ["ALLOW", "DENY", "REQUIRE_APPROVAL", "WARN"],
      "inspected_fields": ["tool_name", "parameters"],
      "schema_drift_detection": true
    },
    "mcp_resources_read": {
      "supported": true,
      "modes": ["ALLOW", "DENY"],
      "inspected_fields": ["uri"]
    },
    "llm_completions": {
      "supported": false,
      "posture": "UNCOVERED",
      "reason": "Completions route out-of-band directly to Anthropic Cloud"
    },
    "os_native_shell": {
      "supported": false,
      "posture": "UNCOVERED",
      "reason": "Native terminal execution is outside stdio proxy mediation"
    }
  },
  "failure_semantics": {
    "on_evaluator_error": "DENY",
    "on_timeout": "DENY",
    "on_audit_failure": "DENY"
  }
}
```

---

## 5. Standardized Error Response & Stable Reason Codes (NFR-011, NFR-012)

All API and JSON-RPC errors use a consistent schema providing clear explanation, policy rule traceability, and safe remediation steps without leaking sensitive data:

```json
{
  "error": {
    "code": "ERR_PATH_TRAVERSAL",
    "message": "Tool 'read_file' was blocked: path '../etc/shadow' traverses outside allowed workspace root",
    "request_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "rule_name": "read_file_parameters_path",
    "policy_version": 42,
    "safe_remediation": "Ensure target paths reside strictly inside the project root directory."
  }
}
```

### Stable Reason Codes Reference:
| Error Code | HTTP Status | JSON-RPC Code | Description & Trigger Condition |
|---|---|---|---|
| `ERR_POLICY_VIOLATION` | 403 Forbidden | -32001 | Tool or action explicitly forbidden by declarative policy. |
| `ERR_PATH_TRAVERSAL` | 403 Forbidden | -32001 | File parameter contains relative path traversal or points to sensitive directory. |
| `ERR_TOOL_SCHEMA_DRIFT` | 403 Forbidden | -32001 | Active tool schema digest diverged from pinned digest in policy. |
| `ERR_DLP_BLOCKED` | 403 Forbidden | -32001 | Tool parameter or output matched high-risk DLP pattern (API key, private key). |
| `ERR_APPROVAL_REQUIRED` | 403 Forbidden | -32001 | Action halted; requires human-in-the-loop authorization. |
| `ERR_APPROVAL_EXPIRED` | 408 Timeout | -32000 | Human authorization ticket timed out without approval. |
| `ERR_APPROVAL_TAMPERED`| 400 Bad Request | -32602 | Action arguments mutated between request and human approval. |
| `ERR_FRAME_EXCEEDED` | 413 Payload Too Large | -32600 | Inbound message frame exceeded 16 MiB boundary. |
| `ERR_DEPTH_EXCEEDED` | 400 Bad Request | -32600 | Inbound JSON nesting depth exceeded 32 levels. |
| `ERR_SPEND_CAP_EXCEEDED`| 429 Too Many Requests | -32000 | Microcent budget ceiling reached for session or virtual key. |
| `ERR_LOOP_DETECTED` | 429 Too Many Requests | -32000 | Recursive identical failed tool-call pattern identified. |
| `ERR_AUDIT_FSYNC_FAILED`| 503 Service Unavailable | -32000 | Gateway could not guarantee durable fsync before high-impact dispatch. |
| `ERR_EMERGENCY_REVOKED`| 403 Forbidden | -32001 | Session, agent, or tool was terminated by emergency kill-switch. |
