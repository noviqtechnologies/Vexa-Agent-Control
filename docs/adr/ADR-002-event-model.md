# ADR-002: Canonical Event Envelope Schema and Decoupled Data Model

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md)

---

## 1. Context & Problem Statement

Historically, Agent Control attempted to store all telemetry, policy decisions, and audit events within the append-only HMAC `AuditEntry` record. This created a dual failure mode:
1. Adding new trace/span metadata broke historical HMAC verification.
2. The audit chain became bloated with transient span timing, token counts, and intermediate LLM chunks that do not require cryptographic non-repudiation.

A clear architectural separation of concerns is needed between the **Tamper-Evident Audit Chain** (forensic proof of security verdicts and state changes) and the **Trace & Event Store** (rich analytical spans, performance profiling, and replay fixtures).

---

## 2. Decision: Decoupled Canonical Event Envelope

We establish a canonical, typed event envelope for all telemetry events. The trace envelope references the audit chain via correlation keys `(session_id, audit_entry_index)` without mutating the audit schema.

### 2.1 The Canonical Trace Envelope Schema

```json
{
  "$schema": "https://vexasec.io/schemas/v1/event-envelope.json",
  "envelope_version": "1.0.0",
  "event_id": "01925b3a-8f12-7000-8000-000000000001",
  "timestamp": "2026-10-04T12:00:00.123456Z",
  "correlation": {
    "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
    "run_id": "b1b9e837-1234-4567-89ab-cdef01234567",
    "span_id": "00f067aa0ba902b7",
    "parent_span_id": null,
    "session_id": "sess-workstation-local-1",
    "request_id": "req-987654",
    "audit_entry_index": 42
  },
  "provenance": {
    "data_freshness": "2026-10-04T12:00:00.123456Z",
    "evidence_source": "workstation_proxy_pipeline",
    "confidence": "observed"
  },
  "event_type": "tool_execution | llm_generation | policy_verdict | hitl_decision | dlp_finding | spend_reservation",
  "payload": { ... }
}
```

### 2.2 Strongly-Typed Payload Variants

1. **`llm_generation`**:
   - `model`: e.g. `"claude-3-5-sonnet-20241022"`
   - `provider`: `"anthropic"`
   - `prompt_tokens`: `142`
   - `completion_tokens`: `85`
   - `latency_ms`: `482.5`
   - `ttft_ms`: `120.0` (time-to-first-token)
   - `finish_reason`: `"tool_use"`
2. **`tool_execution`**:
   - `tool_server`: `"mcp-filesystem"`
   - `tool_name`: `"write_file"`
   - `arguments_digest`: `"sha256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"`
   - `execution_status`: `"success" | "failure" | "blocked" | "outcome_unknown"`
   - `idempotency_key`: `"idem-write-f92a-001"`
3. **`policy_verdict`**:
   - `verdict`: `"ALLOW" | "DENY" | "ESCALATE_HITL" | "REDACT"`
   - `rule_id`: `"RULE-FS-003"`
   - `risk_category`: `"path_traversal"`
   - `evidence_snippet`: `"Attempted write outside workspace: ../../../etc/passwd"`
   - `remediation`: `"Restrict file writing paths to within project root."`
4. **`hitl_decision`**:
   - `approval_id`: `"appr-01925b3a-8f12"`
   - `state`: `"PENDING" | "RESERVED" | "EXECUTING" | "EXECUTED" | "FAILED" | "EXPIRED" | "REVOKED"`
   - `actor`: `"local_user"`
5. **`dlp_finding`**:
   - `detector`: `"regex_aws_secret_key"`
   - `masked_count`: `1`
   - `redaction_mode`: `"wire_mask"`

---

## 3. Consequences & Relationship to Audit Chain

- **Separation of Concerns**: Audit chain remains pure cryptographic append-only proof of security boundaries (`AuditEntryV1Legacy` / `AuditEntryV2`). Traces store rich, queryable analytical graphs.
- **Storage Strategy**: Traces are stored in a dedicated local SQLite database (`traces.db`) or exported as JSONL files. Corrupted traces never invalidate the cryptographic audit log.
