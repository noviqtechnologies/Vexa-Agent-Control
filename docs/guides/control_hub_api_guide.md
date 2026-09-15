# Control Hub v2 API Reference & Integration Guide

The VEXA Control Hub v2 provides centralized governance, cryptographic policy signing, telemetry ingestion, and LLM broker routing for enterprise agent fleets.

## 1. Authentication & Trust Boundary Architecture

### Zero Private Key Ingestion
The Control Hub operates under a strict Zero Private Key Ingestion security model. Workstations and developer endpoints generate Ed25519 keypairs locally within OS secure storage (Keychain, DPAPI, or TPM). Only raw public key bytes are transmitted to the Control Hub during registration.

### Device Assertion Tokens (`X-Device-Authorization`)
Every request dispatched from an enrolled workstation is authenticated via an Ed25519-signed JWT assertion:

```http
POST /api/v3/broker/llm-requests HTTP/1.1
Host: console.vexasec.io
Content-Type: application/json
X-Request-ID: req_0198d5b4-7b4c
X-Device-Authorization: Bearer <jwt_assertion>
```

#### Assertion JWT Claims
- `sub`: The unique, stable device identifier (e.g. `dev-workstation-8f2a1b`).
- `tenant_id`: The organization UUID.
- `workspace_id`: Workspace partition identifier (default: `default`).
- `user_id`: Authenticated developer subject.
- `jti`: Random UUID v4 nonce.
- `iat`: Timestamp of assertion issuance.
- `exp`: Expiration timestamp (maximum lifetime: **300 seconds**).
- `agent_version`: Installed CLI/daemon version.

The Hub validates the Ed25519 signature against the active public key registered in `device_keys`, verifies that `exp - iat <= 300s`, and checks the `jti` against a sliding 5-minute cache to reject replay attacks.

---

## 2. Device Governance & Key Management Endpoints

### 2.1 Enroll Workstation
Registers a workstation's Ed25519 public key and creates or activates its fleet record.

- **Method**: `POST`
- **Path**: `/api/v2/devices/enroll`
- **Headers**: `Authorization: Bearer <oauth_token>` or open under bootstrap policy.

#### Request Body
```json
{
  "device_id": "dev-macbook-pro-3a1b8c",
  "display_name": "Alice MacBook Pro",
  "platform": "macos",
  "agent_version": "1.0.82",
  "public_key_bytes": "6d3A...<32_byte_base64_ed25519_pubkey>..."
}
```

#### Response (`200 OK`)
```json
{
  "device_id": "dev-macbook-pro-3a1b8c",
  "organization_id": "00000000-0000-0000-0000-000000000001",
  "status": "COMPLIANT",
  "active_key_id": "key_0198d5b4-9c1a",
  "enrolled_at": "2026-09-14T11:45:00Z"
}
```

---

### 2.2 Rotate Device Key
Rotates a device's public key with atomic invalidation of prior keys.

- **Method**: `POST`
- **Path**: `/api/v2/devices/{id}/rotate-key`
- **Headers**: `X-Device-Authorization: Bearer <jwt_signed_by_current_key>`

#### Request Body
```json
{
  "new_public_key_bytes": "9e1F...<new_base64_pubkey>...",
  "algorithm": "Ed25519"
}
```

#### Response (`200 OK`)
```json
{
  "device_id": "dev-macbook-pro-3a1b8c",
  "status": "ROTATED",
  "active_key_id": "key_0198d5c2-1a4e",
  "public_key_bytes": "9e1F...",
  "rotated_at": "2026-09-14T11:46:00Z"
}
```

---

### 2.3 List Enrolled Devices (v2 Multi-State)
Returns the live inventory of workstations with capability vectors and freshness tiers.

- **Method**: `GET`
- **Path**: `/api/v2/devices`
- **Headers**: `Authorization: Bearer <dashboard_jwt>`

#### Response (`200 OK`)
```json
{
  "devices": [
    {
      "device_id": "dev-macbook-pro-3a1b8c",
      "stable_device_id": "dev-macbook-pro-3a1b8c",
      "display_name": "Alice MacBook Pro",
      "os_family": "macos",
      "architecture": "aarch64",
      "status": "ACTIVE",
      "capability_vector": [
        "CONFIGURED",
        "MCP_WRAPPED",
        "TRAFFIC_VERIFIED"
      ],
      "last_freshness": "ACTIVE_FRESH",
      "public_key": "6d3A...",
      "last_seen_at": "2026-09-14T11:44:30Z",
      "first_enrolled_at": "2026-09-14T08:00:00Z"
    }
  ],
  "total_count": 1
}
```

---

### 2.4 Revoke Device
Permanently revokes device credentials and marks registered public keys as `REVOKED`.

- **Method**: `DELETE`
- **Path**: `/api/v2/devices/{id}`
- **Headers**: `Authorization: Bearer <admin_jwt>`

#### Response (`200 OK`)
```json
{
  "device_id": "dev-macbook-pro-3a1b8c",
  "status": "REVOKED",
  "revoked_at": "2026-09-14T11:47:00Z"
}
```

---

## 3. Cryptographically Signed Effective Policy

### 3.1 Get Signed Effective Policy Manifest
Returns the canonical JSON manifest synthesised across all 5 policy layers, signed with the Control Hub's Ed25519 authority key.

- **Method**: `GET`
- **Path**: `/api/v2/policy/effective`
- **Headers**: `X-Device-Authorization` or `Authorization: Bearer <token>`

#### Response (`200 OK`)
```json
{
  "policy_version": 1,
  "policy_hash": "sha256:8f2a1b9c3e...",
  "tenant_id": "00000000-0000-0000-0000-000000000001",
  "issued_at": 1789377600,
  "expires_at": 1789464000,
  "allowed_models": [
    "gpt-4o",
    "claude-3-5-sonnet",
    "claude-3-7-sonnet",
    "o3-mini",
    "gemini-2.0-flash"
  ],
  "blocked_models": [
    "gpt-4-base",
    "claude-3-opus"
  ],
  "dlp_rules": {
    "block_private_keys": true,
    "redact_api_tokens": true,
    "redact_pII": true
  },
  "rate_limits": {
    "max_rpm": 60,
    "max_tpm": 100000
  },
  "signature": "ed25519:base64_encoded_signature_bytes..."
}
```

---

## 4. Telemetry Ingestion & Audit Ledger Checkpoints

### 4.1 Telemetry Event Ingestion
Accepts cryptographically sequenced telemetry batches from workstation agents.

- **Method**: `POST`
- **Path**: `/api/v2/telemetry/ingest`
- **Headers**: `X-Device-Authorization: Bearer <jwt>`

#### Request Body
```json
{
  "events": [
    {
      "event_id": "evt-0198d5b4-7b4c",
      "device_id": "dev-macbook-pro-3a1b8c",
      "agent_name": "agentcontrol-daemon",
      "session_id": "sess-default",
      "event_type": "mcp_tool_call",
      "payload": {
        "tool": "filesystem_read",
        "file": "package.json",
        "decision": "allowed"
      },
      "timestamp_ms": 1789377650000
    }
  ]
}
```

#### Response (`200 OK`)
```json
{
  "status": "ingested",
  "accepted_count": 1,
  "last_sequence": 1042,
  "latest_hash": "sha256:d41d8cd98f00b204e9800998ecf8427e..."
}
```

---

### 4.2 Audit Ledger Checkpoints
Exposes verifiable cryptographic checkpoints sealing sequential ranges of the tamper-evident audit ledger.

- **Method**: `GET`
- **Path**: `/api/v2/audit/checkpoints`
- **Headers**: `Authorization: Bearer <token>`

#### Response (`200 OK`)
```json
{
  "checkpoints": [
    {
      "checkpoint_id": "chk-a1b2c3d4",
      "tenant_id": "00000000-0000-0000-0000-000000000001",
      "workspace_id": "default",
      "sequence_start": 1,
      "sequence_end": 1000,
      "checkpoint_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "signature": "base64_ed25519_signature...",
      "algorithm": "Ed25519",
      "created_at": "2026-09-14T11:45:00Z"
    }
  ],
  "total_count": 1
}
```
