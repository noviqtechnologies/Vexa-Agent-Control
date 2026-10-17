# Vexa Agent Control — Data Architecture Specification

**Project:** Vexa Agent Control  
**Document Version:** 2.0 (PRD P0 Baseline Specification)  
**Last Updated:** 2026-10-15  
**Document Status:** Approved Engineering Specification  
**Conforms to:** [vexa-agent-control-requirements.md](file:///c:/agentcontrol/agentcontrol/PRD/pending/vexa-agent-control-requirements.md) (24 P0 FRs, 14 P0 NFRs)  

---

## 1. Storage Taxonomy & Data Boundary Overview

Vexa Agent Control strictly maintains the **Sovereign Self-Hosted Invariant (NFR-026)**: all operational data, cryptographic logs, policies, credentials, and telemetry reside inside customer-managed storage tiers.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        DATA PERSISTENCE & SOVEREIGNTY TAXONOMY                         │
├────────────────────────────────┬───────────────────────────────┬───────────────────────┤
│ Tier 1: Developer Workstation  │ Tier 2: Self-Hosted Control   │ Tier 3: Customer      │
│         (Local Profile — P0)   │         Plane (Team / Ent)    │         Enterprise    │
├────────────────────────────────┼───────────────────────────────┼───────────────────────┤
│ • audit.jsonl (HMAC chain)     │ • PostgreSQL 15+ (Relational) │ • Corporate IdP       │
│ • audit.key (OS-protected ACL) │ • Valkey / Redis (Preflight)  │ • Splunk / Datadog    │
│ • traces.db (SQLite)           │ • pg_notify (SSE event bus)   │ • S3 / WORM Storage   │
│ • spend_ledger.db (SQLite)     │ • AES-256-GCM Key Vault       │ • Artifact Registries │
│ • manifests/ (.baseline.bak)   │                               │                       │
└────────────────────────────────┴───────────────────────────────┴───────────────────────┘
```

### Data Storage Matrix:
| Store Identifier | Storage Technology | Location | Data Class & Sensitivity | Deployment Profile |
|---|---|---|---|---|
| **Local Audit Ledger** | JSONL (Append-Only) | Local disk (`~/.agentcontrol/audit.jsonl`) | Cryptographic HMAC audit records (Metadata-first) | Local Workstation (P0) |
| **Local Audit Key** | 32-Byte CSPRNG File | Local disk (`~/.agentcontrol/audit.key`) | Root HMAC verification secret (OS-secured permissions) | Local Workstation (P0) |
| **Local Trace Graph** | SQLite 3 | Local disk (`~/.agentcontrol/traces.db`) | Analytical session traces, tool duration, parent/child IDs | Local Workstation (P0) |
| **Local Spend Ledger** | SQLite 3 | Local disk (`~/.agentcontrol/spend_ledger.db`) | Token usage counters and integer microcent balances | Local Workstation (P0) |
| **Client Manifests** | JSON Files | Local disk (`~/.agentcontrol/manifests/`) | Configuration journals and `.baseline.bak` files | Local Workstation (P0) |
| **Central Policies** | PostgreSQL 15+ | Customer VPC / Server | Declarative YAML policies, version history, lint status | Team Hub (P1) |
| **Central Credentials** | PostgreSQL 15+ | Customer VPC / Server | AES-256-GCM encrypted provider API keys & rotation version | Team Hub (P1) |
| **Virtual Keys** | PostgreSQL 15+ | Customer VPC / Server | Scoped virtual developer tokens, spend caps, CIDR rules | Team Hub (P1) |
| **Central Audit Log** | PostgreSQL 15+ | Customer VPC / Server | Aggregated audit telemetry partitioned monthly by event time | Team Hub (P1) |
| **Gateway Registry** | PostgreSQL 15+ | Customer VPC / Server | Connected gateway health, version, policy ACK status | Team Hub (P1) |
| **Preflight State** | Valkey 7+ / Redis | Customer VPC (Optional) | Sub-millisecond distributed token buckets & spend holds | Team Hub (P1) |

---

## 2. Local Workstation Data Schemas (P0 Core)

### 2.1 Cryptographic Audit Log Schema (`audit.jsonl`)
Every line in `audit.jsonl` is a strictly formatted, single-line JSON record bound to the previous line via HMAC-SHA256 (**FR-014**, **NFR-007**):

```json
{
  "ts": "2026-10-15T12:00:00.123456Z",
  "session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "event": "tool_allow",
  "tool_name": "read_file",
  "params_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "decision": "ALLOW",
  "reason": "Path within declared project workspace",
  "policy_version": 2,
  "policy_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
  "latency_ms": 0.42,
  "identity_sub": "local-developer",
  "client_name": "cursor",
  "entry_index": 1042,
  "prev_hmac": "7c2e4b8a910f1d2e3c4b5a6f7e8d9c0b1a2f3e4d5c6b7a8f9e0d1c2b3a4f5e6d",
  "hmac": "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"
}
```

#### HMAC Computation & Verification Rule:
$$\text{EntryHMAC} = \text{hex}(\text{HMAC-SHA256}(K_{\text{audit}}, \text{CanonicalJSON}(\text{EntryWithoutHMAC}) \parallel \text{prev\_hmac}))$$
- **First Entry Initialization:** Uses the 64-character zero sentinel:
  $$\text{prev\_hmac}_0 = \text{"0000000000000000000000000000000000000000000000000000000000000000"}$$
- **Canonical JSON:** Keys sorted lexicographically; no extraneous whitespace; UTF-8 encoded.
- **Privacy Default (NFR-006):** `params_hash` is mandatory; raw `params` is omitted unless `--include-params` is explicitly passed and authorized.

---

### 2.2 Local Analytical Trace Store (`traces.db`)
Implemented in local SQLite to provide structured session analysis, graph queries, and loop detection without modifying the append-only cryptographic audit chain (ADR-009).

```sql
-- SQLite Schema: traces.db
CREATE TABLE IF NOT EXISTS sessions (
    session_id      TEXT PRIMARY KEY,
    trace_id        TEXT NOT NULL,
    client_name     TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    ended_at        TEXT,
    total_calls     INTEGER NOT NULL DEFAULT 0,
    total_tokens    INTEGER NOT NULL DEFAULT 0,
    total_spend_uc  INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL CHECK (status IN ('ACTIVE', 'COMPLETED', 'REVOKED', 'TIMED_OUT'))
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL REFERENCES sessions(session_id),
    tool_name       TEXT NOT NULL,
    params_hash     TEXT NOT NULL,
    decision        TEXT NOT NULL,
    reason_code     TEXT,
    action_hash     TEXT,
    schema_digest   TEXT NOT NULL,
    execution_time_ms REAL NOT NULL,
    executed_at     TEXT NOT NULL DEFAULT (datetime('now', 'subsec')),
    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tool_session ON tool_executions(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_hash ON tool_executions(tool_name, params_hash);
```

---

### 2.3 Local Spend & Token Ledger (`spend_ledger.db`)
Tracks token allocations and enforces microcent budget caps locally (**FR-034**):

```sql
-- SQLite Schema: spend_ledger.db
CREATE TABLE IF NOT EXISTS spend_ledger (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id          TEXT NOT NULL,
    provider            TEXT NOT NULL,
    model               TEXT NOT NULL,
    prompt_tokens       INTEGER NOT NULL DEFAULT 0,
    completion_tokens   INTEGER NOT NULL DEFAULT 0,
    total_tokens        INTEGER NOT NULL DEFAULT 0,
    spend_microcents    INTEGER NOT NULL DEFAULT 0,
    is_settled          BOOLEAN NOT NULL DEFAULT 1,
    recorded_at         TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE TABLE IF NOT EXISTS spend_reservations (
    reservation_id      TEXT PRIMARY KEY,
    session_id          TEXT NOT NULL,
    estimated_microcents INTEGER NOT NULL,
    status              TEXT NOT NULL CHECK (status IN ('RESERVED', 'SETTLED', 'RELEASED')),
    created_at          TEXT NOT NULL DEFAULT (datetime('now', 'subsec'))
);

CREATE INDEX IF NOT EXISTS idx_spend_session ON spend_ledger(session_id);
```

---

## 3. Centralized PostgreSQL Schema (Self-Hosted Control Hub — P1)

### 3.1 Policies Table (`policies`)
Stores versioned declarative policies with immutable historical tracking (**FR-017**):

```sql
CREATE TABLE policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    name            VARCHAR(64) NOT NULL,
    version         INTEGER NOT NULL,
    schema_version  VARCHAR(16) NOT NULL CHECK (schema_version IN ('v1', 'v2')),
    yaml_content    TEXT NOT NULL,
    sha256_hash     CHAR(64) NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT false,
    created_by      VARCHAR(128) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (tenant_id, name, version)
);

CREATE UNIQUE INDEX idx_policies_active 
    ON policies (tenant_id, name) 
    WHERE is_active = true;
```

---

### 3.2 Provider Credentials Vault (`provider_credentials`)
Stores encrypted upstream API keys. Raw credentials are never exposed to agents or stored in plaintext (**FR-011**):

```sql
CREATE TABLE provider_credentials (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    provider            VARCHAR(32) NOT NULL,
    key_ciphertext      BYTEA NOT NULL,
    key_nonce           BYTEA NOT NULL,
    key_tag             BYTEA NOT NULL,
    rotation_version    INTEGER NOT NULL DEFAULT 1,
    is_active           BOOLEAN NOT NULL DEFAULT true,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    rotated_at          TIMESTAMPTZ
);

CREATE UNIQUE INDEX idx_cred_provider_active 
    ON provider_credentials (tenant_id, provider) 
    WHERE is_active = true;
```

---

### 3.3 Scoped Virtual Keys (`virtual_keys`)
Issues revocable, bounded credentials to developers without sharing raw provider secrets (**FR-011**, **FR-034**):

```sql
CREATE TABLE virtual_keys (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    key_prefix          VARCHAR(16) NOT NULL, -- e.g. "vx-live-"
    key_hash            CHAR(64) NOT NULL UNIQUE, -- SHA-256(secret_token)
    user_identity       VARCHAR(128) NOT NULL,
    model_allowlist     TEXT[] NOT NULL,
    spend_ceiling_uc    BIGINT NOT NULL, -- Integer microcents ($1 = 100,000,000 uc)
    current_spend_uc    BIGINT NOT NULL DEFAULT 0,
    cidr_whitelist      CIDR[],
    expires_at          TIMESTAMPTZ,
    is_revoked          BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX idx_vkeys_hash ON virtual_keys(key_hash) WHERE is_revoked = false;
```

---

### 3.4 Aggregated Audit Events (`audit_events`)
Stores central telemetry uploaded asynchronously from gateway outboxes (**FR-014**, **FR-015**). Partitioned monthly for high-volume ingest:

```sql
CREATE TABLE audit_events (
    id                  BIGSERIAL,
    tenant_id           UUID NOT NULL,
    gateway_id          VARCHAR(64) NOT NULL,
    event_time          TIMESTAMPTZ NOT NULL,
    session_id          UUID NOT NULL,
    trace_id            VARCHAR(64) NOT NULL,
    event_type          VARCHAR(32) NOT NULL,
    tool_name           VARCHAR(64),
    params_hash         CHAR(64),
    decision            VARCHAR(16) NOT NULL,
    reason_code         VARCHAR(32),
    policy_hash         CHAR(64) NOT NULL,
    latency_ms          REAL,
    identity_sub        VARCHAR(128),
    hmac_chain_hash     CHAR(64) NOT NULL,
    payload_metadata    JSONB,
    ingested_at         TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (id, event_time)
) PARTITION BY RANGE (event_time);

CREATE INDEX idx_audit_lookup ON audit_events (tenant_id, event_time DESC, gateway_id);
CREATE INDEX idx_audit_trace ON audit_events (trace_id);
```

---

### 3.5 Human-in-the-Loop Tickets (`hitl_tickets`)
Manages the server-side atomic CAS state machine for exact-action approvals (**FR-009**):

```sql
CREATE TABLE hitl_tickets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL,
    session_id          UUID NOT NULL,
    action_hash         CHAR(64) NOT NULL,
    tool_name           VARCHAR(64) NOT NULL,
    canonical_params    JSONB NOT NULL,
    status              VARCHAR(16) NOT NULL CHECK (
                            status IN ('PENDING', 'RESERVED', 'EXECUTING', 'EXECUTED', 'REJECTED', 'OUTCOME_UNKNOWN', 'TIMED_OUT')
                        ),
    requested_by        VARCHAR(128) NOT NULL,
    resolved_by         VARCHAR(128),
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    resolved_at         TIMESTAMPTZ
);

CREATE INDEX idx_hitl_pending ON hitl_tickets(tenant_id, status) WHERE status = 'PENDING';
```

---

## 4. Privacy, Retention & Payload Access Controls (FR-023, NFR-006)

To prevent the governance plane from becoming a secondary data-exfiltration risk, Vexa enforces a strict **Metadata-First Access Hierarchy**:

```
                       ┌──────────────────────────────┐
                       │     Mediated Action Event    │
                       └──────────────┬───────────────┘
                                      │
              Extract Metadata & Compute Canonical SHA-256
                                      │
               ┌──────────────────────┴──────────────────────┐
               ▼                                             ▼
┌──────────────────────────────┐              ┌──────────────────────────────┐
│  Tier 1: Metadata Event Log  │              │  Tier 2: Scoped Raw Payload  │
│  (Default - Minimal Privacy) │              │  (Strict Opt-In & Segregated)│
├──────────────────────────────┤              ├──────────────────────────────┤
│ • Timestamp, Session, Trace  │              │ • Raw Prompts & Completions  │
│ • Tool Name, Model Version   │              │ • Full Tool Parameters       │
│ • SHA-256 Parameter Hash     │              │ • Full Output Text           │
│ • Policy Decision & Reason   │              │ • AES-256-GCM Encrypted      │
│ • HMAC Cryptographic Chain   │              │ • Strict Role-Gated Access   │
└──────────────────────────────┘              └──────────────────────────────┘
```

### 4.1 Segregated Raw Payload Access Audit
1. **Access Gating:** Viewing unredacted raw tool parameters or prompts requires the `SensitiveTraceAuditor` RBAC role (**FR-012**).
2. **Read Access Logging:** Every read access to Tier 2 raw payload emits a dedicated audit event:
   ```json
   {
     "event": "audit.raw_payload_access",
     "actor": "security-officer@corp.com",
     "target_session_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
     "target_request_id": "550e8400-e29b-41d4-a716-446655440000",
     "justification": "Incident IR-2026-10-88 investigation",
     "ts": "2026-10-15T12:30:00Z"
   }
   ```
   *The access event explicitly excludes the sensitive payload itself.*

### 4.2 Retention, Deletion & Purge Lifecycles (FR-023)
- **Local Workstation Sentry:** Automatic daily log rotation of `audit.jsonl` when exceeding 100 MB. Retains 30 days locally before archiving. CLI provides `agentcontrol purge-audit --older-than 30d`.
- **Central PostgreSQL Tables:** Monthly range partitions are automatically created ahead of time and detached/dropped via scheduled cron jobs based on the tenant's retention policy (e.g., 90 days).
- **GDPR / Right-to-Erasure Purge:** Purging a user identity cascades through `traces.db`, removing session links while maintaining HMAC chain hash continuity via cryptographic pseudorandom masking.

---

## 5. Read & Write Paths Performance Profile (NFR-014)

| Data Operation | Source Component | Target Store | Sync / Async | Latency Profile (p50 / p99) |
|---|---|---|---|---|
| **Policy Evaluation** | Ingress Pipeline | `ArcSwap<CompiledPolicy>` (RAM) | Synchronous | $0.05\text{ ms} / 0.15\text{ ms}$ |
| **DLP RegexSet Match** | Parameter Filter | Pre-compiled regex engine (RAM) | Synchronous | $0.10\text{ ms} / 0.45\text{ ms}$ |
| **Audit Fsync** | Logger Thread | `audit.jsonl` via `sync_all()` | Synchronous (Blocking) | $0.80\text{ ms} / 2.50\text{ ms}$ |
| **Trace Graph Commit** | Local Worker | SQLite `traces.db` (WAL mode) | Asynchronous | $0.20\text{ ms} / 1.10\text{ ms}$ |
| **Spend Preflight Hold** | Broker Handler | Valkey / SQLite ledger | Synchronous | $0.35\text{ ms} / 1.20\text{ ms}$ |
| **SIEM Outbox Export** | Outbox Worker | Splunk HEC / Datadog API | Asynchronous (Decoupled) | Background Queue |
| **Policy Delta Broadcast** | Hub API | SSE Subscriber Gateways | Asynchronous (< 100 ms) | $15\text{ ms} / 45\text{ ms}$ |
