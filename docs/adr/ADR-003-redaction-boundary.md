# ADR-003: Multi-Stage Redaction Boundary and DLP Pipeline Extension

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md)

---

## 1. Context & Problem Statement

Agent Control incorporates a 20+ pattern DLP scanner ([`policy/dlp.rs`](file:///c:/AgentWall/agentwall/src/policy/dlp.rs)) detecting credentials, private keys, API tokens, and PII. However, previous designs lacked clear boundary definitions for *where* redaction occurs in the processing lifecycle:
- If redaction occurs before the LLM prompt egresses, does the trace explorer see raw or redacted text?
- If tool parameters contain secrets, how can forensic review occur without creating an unencrypted plaintext secret database?

---

## 2. Decision: Three-Stage Redaction Boundary

We define three distinct, non-overlapping redaction stages:

```
[Agent Output / Ingress]
         │
         ▼
┌─────────────────────────────────┐
│ Stage 1: Wire Redaction (Egress)│ ──► Replaces raw secrets with `[REDACTED:<pattern>]`
└────────┬────────────────────────┘     before payload reaches upstream LLM or tool.
         │
         ▼
┌─────────────────────────────────┐
│ Stage 2: Storage Redaction      │ ──► Default: Stores only redacted strings and
└────────┬────────────────────────┘     SHA-256 digests in `traces.db` and `audit.jsonl`.
         │                              Optional: If `--capture-raw` enabled, raw payload
         │                              is encrypted with dedicated local key.
         ▼
┌─────────────────────────────────┐
│ Stage 3: Presentation Masking   │ ──► Local UI and REST API serve redacted views by default.
└─────────────────────────────────┘     Raw unmasking requires `Scope::RawPayloadRead`.
```

### Stage 1: Wire Redaction (Inline Pre-Egress)
- Executes in the synchronous request path before outgoing HTTP requests or MCP tool dispatches.
- Replaces matches with structured placeholders: `[REDACTED:<detector_name>:<partial_hash>]`.
- Guarantees zero sensitive secrets leave the host machine toward upstream cloud providers or untrusted tools.

### Stage 2: Storage Boundary (At-Rest Isolation)
- By default, `AuditEntry` records carry only `params_hash` (SHA-256 of canonical JSON). The raw parameter string is never written to disk unless explicitly configured with `--include-params`.
- In `traces.db`, payloads store the post-Stage-1 redacted payload.
- When full raw payload retention is enabled for team auditing, payloads are encrypted at rest using an AES-256-GCM data key wrapped by the workspace owner's public key.

### Stage 3: Presentation & API Authorization
- The local REST API (`/api/v1/traces/{id}`) serves redacted representations.
- Viewing unredacted payloads via `GET /api/v1/traces/{id}/raw` requires an explicit, elevated OAuth/token scope: `Scope::RawPayloadRead`.
- Every invocation of `Scope::RawPayloadRead` emits an immutable audit event (`event = "sensitive_payload_revealed"`) to the audit chain.

---

## 3. Consequences & Compliance

- **Privacy Invariant**: Upstream LLMs and unprivileged developers cannot observe raw credentials.
- **Forensic Auditability**: Security teams can verify *that* an exfiltration attempt occurred and inspect the redacted pattern identity without storing plaintext credentials in unencrypted log files.
