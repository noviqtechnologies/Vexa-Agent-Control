# Vexa Agent Control System Architecture (Phases 1 & 2 Baseline)

**Target Domain:** `vexasec.io` (Hosted Gateway & Cloud Hub)  
**Architecture Spec:** PRD-VEXA-CORE-2026.5 / PLAN-VEXA-SMB-ENTERPRISE-2026.5  
**Contract Version:** 4.0  

---

## 1. Four-Plane Architecture & System Topology

The system decouples responsibilities across four distinct architectural planes:
1. **Edge Execution Plane (Workstation):** Ultra-lightweight local daemon proxy (`127.0.0.1:18080`), isolated MCP `stdio-proxy` child wrappers, and CLI administrative tooling.
2. **Gateway Broker Plane (Cloud Edge):** Horizontally scalable, stateless LLM proxy terminating upstream connections and custodying provider keys.
3. **Control & Governance Plane (Cloud Core):** Tenant management, IAM federation, PKCE OAuth, device enrollment, and Key Vault.
4. **Audit & Analytics Plane (Cloud Ingestion):** Cryptographic ledger, FinOps budgeting, and SIEM event streaming.

```mermaid
graph TB
    subgraph EdgePlane["1. Edge Execution Plane (Developer Workstation)"]
        CLI["agentcontrol CLI\n(12 Canonical Commands)"]
        DAEMON["agentcontrol daemon\n(127.0.0.1:18080 - Per-User)"]
        STDIO["agentcontrol stdio-proxy\n(&lt; 64MB Memory Ceiling, 60s Timeout)"]
        IDE_A["IDE Mode A: Cloud-Direct\n(e.g., VS Code Continue)"]
        IDE_B["IDE Mode B: Local-Agent\n(e.g., Codex CLI / Cursor)"]
        MCP_SRV["MCP Server Process\n(Isolated Execution)"]

        CLI -->|OS Authenticated IPC| DAEMON
        IDE_B -->|Bearer local_token| DAEMON
        IDE_B -->|stdio pipes| STDIO --> MCP_SRV
    end

    subgraph BrokerPlane["2. Gateway Broker Plane (Cloud Edge - Multi-Region)"]
        GW_EDGE["gateway.vexa.ai\n(TLS 1.3 Termination)"]
        BROKER["Hosted LLM Broker\n(Key Quarantine & Transformation)"]
        GW_EDGE --> BROKER
    end

    subgraph ControlPlane["3. Control & Governance Plane (Cloud Core)"]
        AUTH_SVC["PKCE OAuth & Device Enrollment\n(app.vexasec.io)"]
        DEV_STORE["Device Key Registry\n(Ed25519 Public Keys Only)"]
        VIRTUAL_KEYS["Virtual Credential Service\n(Scoped vx-live / sk-vex keys)"]
        SQL[(Cloud SQL PostgreSQL)]
    end

    subgraph AuditPlane["4. Audit & Analytics Plane (Cloud Ingestion)"]
        VALKEY[("Valkey Distributed State\n(Sub-ms Token Buckets & Spend Hold)")]
        FINOPS["FinOps Spend Engine\n(Integer Microcent Ledger)"]
        OUTBOX["Durable Outbox & SIEM Export\n(Splunk / Datadog / OpenSearch)"]
    end

    subgraph UpstreamProviders["Upstream Frontier LLMs & External Services"]
        OAI["OpenAI / Azure OpenAI"]
        ANTH["Anthropic Claude"]
        GEMINI["Google Gemini"]
        GROQ["Groq LPU"]
        BEDROCK["AWS Bedrock"]
    end

    IDE_A -->|HTTPS + Scoped Virtual Key| GW_EDGE
    DAEMON -->|Short-Lived Ed25519 Assertion JWT| GW_EDGE
    CLI -->|Browser PKCE Login| AUTH_SVC
    AUTH_SVC --> DEV_STORE
    DEV_STORE --> SQL
    VIRTUAL_KEYS --> SQL

    BROKER --> VALKEY
    BROKER --> FINOPS --> SQL
    BROKER --> OUTBOX
    BROKER --> OAI
    BROKER --> ANTH
    BROKER --> GEMINI
    BROKER --> GROQ
    BROKER --> BEDROCK
```

### Dual-Mode Operation

* **Mode A: Cloud-Direct Mode (Completions-Only):**
  - Designed for lightweight coding extensions (such as VS Code Continue) that only require LLM completions without local MCP tool sandboxing.
  - Authenticated directly to `https://gateway.vexa.ai/v1` via workspace-scoped, revocable virtual keys (`vx-live-...` / `sk-vex-direct-...`).
* **Mode B: Local-Agent Mode (Codex & MCP Targets - Default):**
  - Intercepts local LLM completion requests via loopback proxy at `http://127.0.0.1:18080/v1`.
  - Terminates local bearer token, attaches short-lived Ed25519 device assertion JWTs (5-minute TTL), and dispatches to the hosted gateway broker.
  - Spawns dedicated child `agentcontrol stdio-proxy` processes to govern Model Context Protocol (MCP) tool executions.

---

## 2. Process Isolation & Workstation Security Architecture

To guarantee workstation stability, prevent daemon bloat, and isolate failures:
1. **`agentcontrol` (CLI):** Interactive administrative binary with 12 canonical commands (`login`, `connect`, `disconnect`, `status`, `doctor`, `support-bundle`, `repair`, `rotate-local-token`, `service`, `start`, `logout`, `reset-local-state`). Communicates with daemon over OS-native authenticated IPC (Windows: Named Pipe with User SID DACL; POSIX: Unix domain socket `~/.agentcontrol/agentcontrol.sock` with `0600` permissions).
2. **`agentcontrol daemon` (Background Service):** Long-running per-user daemon listening strictly on `127.0.0.1:18080`. Enforces socket-level loopback assertions, RFC 3986 authority parsing, proxy header stripping, and local token validation. Zero elevation required.
3. **`agentcontrol stdio-proxy` (Child Process):** Dedicated process spawned per configured MCP server. Enforces frame quotas (< 16MB), memory limits (< 64MB RSS ceiling), and 60-second timeouts. A failure in an MCP child process cannot terminate the daemon or affect other tools.
4. **`OwnershipManifest` & Non-Destructive Reversal:** Configuration mutations are tracked in `~/.agentcontrol/manifests/<target>.manifest.json`. Pristine files are preserved in `<config>.baseline.bak`. Running `agentcontrol disconnect <target>` restores original configuration keys without erasing custom user settings.
5. **Zero Silent Root CA:** Workstation trust stores are never modified. No Root CA certificates are installed or generated.
6. **Zero Plaintext Provider Keys:** Workstations never receive or store upstream provider API keys. Keys reside in encrypted cloud vaults (AES-256-GCM / KMS).

---

## 3. Cryptographic Core: Two-Key Enrollment

| Key Type | Algorithm | Storage | Purpose |
|---|---|---|---|
| **Identity Proof Key** | `Ed25519` | OS Secure Store (CNG/Keychain/0600) | Signs canonical transcript challenge during bootstrap and renewal proofs. |
| **mTLS Client Key** | `ECDSA P-256` | OS Secure Store | Embedded in PKCS#10 CSR to obtain GCP ALB-compatible mTLS client certificate. |

### Canonical Transcript Format:
```text
transaction_id|challenge_id|enroll.vexasec.io|tenant_id|ed25519_fingerprint|csr_sha256|2.0
```

---

## 4. Threat Model & Invariant Protections

* **Zero Fleet Secrets (NFR-SMB-003)**: Eliminates static plaintext shared keys in production by requiring mTLS and KMS-backed secret references.
* **Atomic OTET Consumption (FR-SMB-001)**: Single-use guarantee enforced with PostgreSQL `SELECT ... FOR UPDATE`.
* **Immediate Revocation Containment (FR-SMB-009)**: Cloud SQL gate denies all device-facing routes on the next request.
* **Deterministic Fail-Closed Gateway (NFR-SMB-007)**: When policy is expired, invalid, or spend preflight fails in enforce mode, sensitive egress calls fail closed.

---

## 5. Centralized LLM Key Custody & Brokered Egress

* **Encryption at Rest:** Provider API keys (OpenAI, Anthropic, Groq, Together, Mistral) are encrypted in the Hub database with AES-256-GCM using a 32-byte secret (`PROVIDER_KEY_ENCRYPTION_SECRET`).
* **Decryption Boundary:** Stored credentials are only decrypted in-memory inside the broker handler (`/api/v2/broker/llm-requests`) immediately before outbound provider dispatch.
* **Plaintext Isolation:** Raw keys are never distributed to endpoints, returned in UI payloads, or exposed in audit logs.

---

## 6. Spend Ledger Governance & Streaming Accounting

* **Integer Microcent Precision:** All currency calculations use exact integer microcents ($1.00 = 100,000,000 microcents) to eliminate floating-point drift.
* **Preflight Reservations:** The gateway reserves estimated input + maximum output tokens before contacting the model provider (`reserved + settled + new <= limit`).
* **SSE Stream Framing Parser:** Streaming responses (`stream: true`) are framed incrementally to capture real-time provider token counts (`usage` objects) or fall back to character estimation (`len / 4`), ensuring non-zero settlement upon stream completion.

---

## 7. Enterprise Identity Provider (IdP) Integration

* **Console SSO (Local Auth, Google Workspace, Microsoft Entra ID):**
  - **Local Auth:** In-database bcrypt password hashing and session tokens for air-gapped / standalone deployments.
  - **Google Workspace:** Standard OIDC discovery via `https://accounts.google.com/.well-known/openid-configuration` with optional hosted domain (`hd`) restrictions.
  - **Microsoft Entra ID:** OpenID Connect authorization code flow via `https://login.microsoftonline.com/{tenant}/v2.0` with optional group claim GUID mapping.
* **Workstation & Agent JWT Binding:**
  - Gateways validate incoming `Authorization: Bearer <JWT>` against cached IdP JWKS.
  - Resolved `identity_sub`, `identity_email`, and group memberships bind directly to spend reservations and audit events.

---

## 8. Phase-Oriented Execution Pipeline

All incoming agent requests (MCP tool calls, LLM chat completions, embeddings) execute through a strict, deterministic 9-stage pipeline:

```text
Ingress -> Identity Binding -> Snapshot Acquisition -> Security Inspection (DLP/Inj/SafeMode) -> Preflight Reservation -> Route Planning -> Upstream Execution -> Stream Sanitization -> Settlement & Outbox
```

1. **Immutable Snapshot Swaps:** Policies, deployment routes, and price tables are held in atomic `ConfigSnapshotStore` wrappers, guaranteeing zero lock contention on hot paths.
2. **Operation Classification & Replay Taxonomy:** Operations are partitioned into `ReadOnly` (LLM completions, embeddings) and `SideEffecting` (MCP file writes, shell execution, database mutations). Side-effecting operations are **never** blindly replayed.

---

## 9. Bidirectional Provider Transformation Engine

Standardizes incoming OpenAI-formatted chat requests across heterogeneous upstream model providers:
* **OpenAI:** Native `/v1/chat/completions` pass-through with header sanitization.
* **Azure OpenAI:** Dynamic deployment name URL rewriting and `api-key` header adaptation.
* **Groq:** Ultra-low latency LPU routing via `https://api.groq.com/openai/v1/chat/completions`.
* **Anthropic:** Transforms OpenAI messages and tool calls into Anthropic `/v1/messages` format, extracting top-level system prompts and translating streaming delta chunks.
* **Google Gemini:** Adapts requests to Gemini OpenAI-compatible endpoints with API key headers.
* **AWS Bedrock:** Formats requests for Bedrock `Converse` APIs with SigV4 authentication.

---

## 10. Valkey Distributed State Layer

* **Open-Source BSD Engine:** Uses Valkey (wire-compatible with RESP2/RESP3) for sub-millisecond Virtual Key caching, distributed token buckets (RPM/TPM), and atomic microcent spend reservations.
* **Zero-Lock Database Architecture:** PostgreSQL row-level locking is replaced by Valkey-backed atomic `ReserveSpend` with asynchronous background batch settlements every 5 seconds.
* **Serverless Cost Optimization:** Containerized Valkey runs alongside the Control Plane on AWS (ECS Fargate Spot), Azure (Container Apps), and GCP (Cloud Run) with minimal resource footprint ($0 to <$15/mo).

---

## 11. Decoupled Durable Event Outbox

* **Tamper-Evident Durability:** The local HMAC-SHA256 audit logger commits each entry to local disk via `sync_all()` before confirming the request.
* **Non-Blocking Asynchronous Fan-Out:** Network SIEM exports (Splunk, Datadog, OpenSearch) and Control Hub telemetry are dispatched via `DurableOutbox` worker tasks, preventing remote network latencies from stalling the gateway.

---

## 12. Pluggable Routing Engine & Data Residency (AR-2)

The gateway features a pluggable routing layer supporting diverse multi-model selection strategies per model group:
* **`PriorityStrategy`:** Primary/secondary fallback sequence honoring explicit deployment priority ordinals.
* **`LowestLatencyStrategy`:** Evaluates exponential moving average (EMA) response latency metrics reported by `StatsProvider` to route to the fastest available deployment.
* **`WeightedRandomStrategy`:** Proportional distribution based on deployment traffic weights for canary and load distribution scenarios.
* **`RegionAffinityStrategy`:** Strict data residency compliance. Evaluates authoritative typed deployment `region` metadata (with delimiter-bounded fallback) and deterministically fails closed with HTTP 503 `routing_policy_violation` if no eligible compliant deployment exists.

---

## 13. Extensible Pipeline Hook Lifecycle Framework (AR-1)

A unified hook system provides lifecycle interception across three distinct stages:
* **`PreRoute`:** Intercepts raw HTTP requests before routing decisions or payload parsing. Supports header injection and raw byte mutations (`ModifyBytes`).
* **`PreExecute`:** Intercepts structured MCP tool calls (`serde_json::Value`), executing content sanitizers, inline DLP redactions (`ModifyJson`), and security blocks (`Block`).
* **`PostExecute`:** Intercepts outbound downstream responses and streaming token chunks (`ModifyBytes`).
* **Unified `SharedScanners` Construction:** Detectors (SafeMode, DLP, Prompt Injection, Schema Drift) are compiled once at gateway startup inside a centralized `SharedScanners` suite and shared cleanly across proxy handlers, avoiding redundant multi-block regex compilations.

---

## 14. Decomposed Control Plane & Asynchronous Batch Durability (AR-3, AR-4, AR-5)

The Go Control Plane separates monolithic spend database operations into specialized, high-throughput components:
* **`runs.Store`:** Decoupled execution history and forensic run dossiers (`ListRuns`, `GetRunDossier`), preventing analytical queries from interfering with transaction hot paths.
* **`SpendEventWriter`:** Asynchronous bounded queue with batch ingestion via `pgx.Batch`, exponential backoff retry on transient DB errors, in-memory replay buffer, and graceful shutdown draining. Production-wired to transactional `Store.Authorize`, `Store.Settle`, and `Store.Release` commit flows.
* **Centralized `Scheduler`:** Deterministic background daemon managing periodic tasks (e.g. `SweepJob` for expired reservation holds, `AssignmentStaleSweepJob`) with graceful cancellation and loopback/admin-authenticated live introspection at `/internal/jobs`.




