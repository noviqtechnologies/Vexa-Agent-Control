# Vexa Canonical Event Envelope Specification v1.0

## Status: APPROVED
## Date: 31 August 2026

---

## 1. Overview & Purpose

The **Canonical Event Envelope** defines the cross-plane contract for telemetry events, security violations, spend ledger entries, and broker LLM runs across Vexa Agent Control.

To uphold the core principle of **"Truth Before Surface"**, every event and API response payload must explicitly declare its data provenance, confidence tier, and measurement source.

---

## 2. The Provenance Block

Every analytical API endpoint response must include a top-level `provenance` block conforming to this schema:

```json
{
  "provenance": {
    "data_freshness": "2026-08-31T15:04:05Z",
    "evidence_source": "postgresql_spend_reservations",
    "confidence": "observed"
  }
}
```

### 2.1 Confidence Tiers

| Tier | UI Badge | Definition | Usage Guidelines |
|---|---|---|---|
| `observed` | 🟢 Green | Directly measured, authoritative, cryptographically verified or transactionally committed. | PostgreSQL committed rows, verified mTLS certs, HMAC-signed audit lines. |
| `enforced` | 🔵 Blue | Deterministically applied by policy engine rules. | Hard-deny spend blocks, tool call parameter schema rejections. |
| `inferred` | 🟡 Amber | Estimated or matched heuristically (e.g. without explicit correlation ID). | Preflight token cost estimates, time-window proximity matching. |
| `not_configured` | ⚪ Gray | No policy or rule defined at this hierarchy level. | Clean default fallback to parent organization tier. |
| `stale` | 🟠 Orange | Telemetry older than maximum acceptable latency threshold (> 5m for sentry heartbeats). | Edge heartbeat timeouts, offline endpoints. |
| `unknown` | 🔴 Red | Data missing, unrecorded, or telemetry unavailable. | **NEVER** render as green or healthy. Always highlight for investigation. |

---

## 3. Canonical Event Ingest Schema

Ingested edge events (`POST /api/v1/ingest/events`) must conform to:

```json
{
  "event_id": "01917f8a-...",
  "timestamp_ms": 1725120000000,
  "session_id": "sess-workstation-1",
  "agent_id": "claude-desktop",
  "tool_name": "bash",
  "decision": "allowed",
  "request_id": "req-trace-uuid",
  "dlp_findings": [
    {
      "category": "api_key",
      "pattern_name": "AWS Access Key",
      "count": 1
    }
  ],
  "injection_findings": [],
  "semantic_findings": []
}
```

---

## 4. Run Explorer Dossier Contract

```json
{
  "run_id": "res-01917f8a-...",
  "request_id": "req-trace-uuid",
  "identity": {
    "device_id": "win-endpoint-01",
    "device_hostname": "workstation-alpha",
    "device_compliance": "COMPLIANT",
    "project_id": "default"
  },
  "policy": {
    "snapshot": {
      "limit_microcents": 10000000000,
      "period_type": "monthly",
      "action": "hard_deny"
    },
    "price_book_version_id": "price-book-v1"
  },
  "dispatch": {
    "provider": "openai",
    "model": "gpt-4o"
  },
  "economics": {
    "reserved_microcents": 112500000,
    "settled_microcents": 76250000,
    "released_microcents": 36250000,
    "currency": "USD",
    "events": []
  },
  "outcome": {
    "state": "SETTLED",
    "started_at": "2026-08-31T15:00:00Z",
    "settled_at": "2026-08-31T15:00:02Z",
    "duration_ms": 2100
  },
  "provenance": {
    "data_freshness": "2026-08-31T15:00:02Z",
    "evidence_source": "postgresql_spend_reservations",
    "confidence": "observed"
  }
}
```
