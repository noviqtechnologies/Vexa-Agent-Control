# Scoped Virtual Keys Architecture Specification

## 1. Overview & Trust Boundaries

Vexa Agent Control provides fine-grained, policy-governed access to upstream LLM providers via **Scoped Virtual Keys**. 

Virtual keys act as revocable execution handles attached to human users or machine workloads, decoupling user authentication from runtime API authorization.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ TRUST BOUNDARY & DUAL ENFORCEMENT ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  [ Developer Workstation / Client ]                                         │
│       │                                                                     │
│       │ (TCP / HTTP with Bearer sk-vex-...)                                 │
│       ▼                                                                     │
│  [ Rust Edge Proxy / Gateway (local_key_cache.rs) ]                         │
│       ├── Real TCP Socket IP / CIDR Validation                              │
│       ├── In-Memory Dynamic Expiration & Status Checks                      │
│       ├── Sliding-Window Rate Limiting (RPM / TPM)                          │
│       └── Local Sub-millisecond Prompt & Token Caching                      │
│            │                                                                │
│            │ (Authenticated internal dispatch / MTLS)                       │
│            ▼                                                                │
│  [ Go Control Plane Broker (broker_v3.go) ]                                 │
│       ├── Dynamic Key Expiration & Revocation Verification                  │
│       ├── Model Allowlist Filtering                                         │
│       ├── Atomic CTE Preflight Spend Reservation (Fail-Closed)              │
│       ├── Hardware/Central KMS Decryption of Provider Secrets               │
│       └── Upstream LLM Dispatch (OpenAI, Anthropic, Azure, etc.)            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Invalidation & Synchronization Architecture

Key lifecycle transitions (rotation and revocation) are broadcast to all connected edge gateways via a **Zero-Redis SSE Stream** backed by periodic polling:

1. **Real-Time Push (SSE Broadcaster)**: When a virtual key is updated, rotated, or revoked, the control plane immediately publishes an `InvalidationEvent` on `GET /api/v1/internal/invalidation-stream`. Connected edge proxies evict their in-memory cache in `< 50ms`.
2. **Periodic Reconciliation (60s Pull Window)**: If network interruptions temporarily disconnect an edge proxy from the SSE stream, a background reconciler polls the control plane every 60 seconds to ensure eventually-consistent eviction.

---

## 3. Atomic Spend Accounting & Concurrency Control

To prevent race conditions during concurrent request bursts, spend reservations use atomic Compare-And-Swap (CAS) execution in PostgreSQL via Common Table Expressions (CTE):

```sql
WITH key_info AS (
    SELECT id, spent_microcents, monthly_budget_microcents, status
    FROM virtual_keys
    WHERE id = $1::uuid AND organization_id = $2::uuid
),
updated AS (
    UPDATE virtual_keys
    SET spent_microcents = spent_microcents + $3
    WHERE id = $1::uuid AND organization_id = $2::uuid
      AND status = 'active'
      AND (monthly_budget_microcents = 0 OR (spent_microcents + $3) <= monthly_budget_microcents)
    RETURNING spent_microcents
)
SELECT 
    (SELECT count(*) FROM key_info) AS key_exists,
    COALESCE((SELECT status FROM key_info), '') AS key_status,
    (SELECT spent_microcents FROM updated) AS new_spent;
```

### Error Disambiguation:
- **`ErrVirtualKeyNotFound`**: Returned if the key does not exist, belongs to another tenant, or has been revoked.
- **`ErrVirtualKeyBudgetExceeded`**: Returned if the key exists and is active, but the requested spend increment would exceed the monthly budget cap.

---

## 4. Standardized Machine-Readable Error Envelopes

All broker endpoints emit standardized JSON error envelopes with `Content-Type: application/json`:

```json
{
  "error": {
    "code": "budget_exceeded",
    "message": "Monthly spend budget exceeded for this virtual key"
  }
}
```

| HTTP Status | Error Code (`code`) | Description |
|---|---|---|
| `401 Unauthorized` | `invalid_virtual_key` | Key hash not found, expired, or revoked. |
| `401 Unauthorized` | `auth_required` | Missing `Authorization: Bearer sk-vex-...` or `X-Virtual-Key` header. |
| `403 Forbidden` | `model_not_allowed` | Requested model is not permitted under the key's `allowed_models` policy. |
| `402 Payment Required` | `budget_exceeded` | Monthly spend cap has been reached. |
| `429 Too Many Requests` | `rate_limit_exceeded` | RPM or TPM sliding-window limit exceeded. |
| `503 Service Unavailable` | `spend_service_unavailable` | Spend reservation infrastructure failure (fails closed). |
| `502 Bad Gateway` | `upstream_error` | Upstream provider connection failure. |
