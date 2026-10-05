# Architecture Decision Records (ADRs)

This directory contains the frozen architectural specifications established in **Phase 0a** of the Vexa Agent Control implementation plan, governed by [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md).

| ADR | Title | Status | Scope |
|---|---|---|---|
| [ADR-001](ADR-001-run-semantics.md) | Run Semantics and Transport Correlation Hierarchy | APPROVED | 7-tier correlation ID hierarchy (`trace_id` down to `event_id`) across HTTP, SSE, MCP stdio, MCP HTTP, and CLI. |
| [ADR-002](ADR-002-event-model.md) | Canonical Event Envelope Schema and Decoupled Data Model | APPROVED | Canonical trace envelope schema, strongly-typed payloads, and decoupling from cryptographic audit chain. |
| [ADR-003](ADR-003-redaction-boundary.md) | Multi-Stage Redaction Boundary and DLP Pipeline Extension | APPROVED | 3-stage redaction model: wire redaction, storage redaction, and scoped presentation unmasking. |
| [ADR-004](ADR-004-replay-side-effects.md) | Replay Engine and Side-Effect Sandboxing | APPROVED | Absolute prohibition on external I/O and mutations during trace replay and CI evaluation. |
| [ADR-005](ADR-005-storage-retention.md) | Local Storage, Retention, Indexing, and Compaction | APPROVED | SQLite `traces.db` schema, 500MB size caps, rolling FIFO eviction, and `audit.jsonl` rotation. |
| [ADR-006](ADR-006-otlp-strategy.md) | Observability, Export Strategy, and OTLP Ingestion Deferral | APPROVED | Native JSON/JSONL export priority, Phase 3 OTLP export, and formal kill directive for OTLP ingestion. |
| [ADR-007](ADR-007-ui-packaging.md) | UI Packaging, Local REST API, and Frontend Deferral | APPROVED | Versioned local REST/SSE API (`/api/v1/*`), embedded single-file HTML console, React console deferred to Phase 3. |
| [ADR-008](ADR-008-policy-compatibility.md) | Policy Compatibility, Versioning, Signing, and Rollback | APPROVED | Backward compatibility with existing YAML, Ed25519 bundle signing, atomic hot-reload, and rollback. |
| [ADR-009](ADR-009-audit-chain-migration.md) | Audit Chain Migration, Immutable Legacy Verifier, and Chain Bridge Protocol | APPROVED | Frozen `AuditEntryV1Legacy` type, verifier schema dispatch, RFC 8785 canonical bytes for V2, and chain bridges. |
| [ADR-010](ADR-010-hitl-and-local-api-security.md) | Human-in-the-Loop (HITL) State Machine, Idempotent Crash Recovery, and Local API Threat Boundaries | APPROVED | Formal 6-state machine, idempotency keys, opaque references, capability scopes, and local OS threat boundary. |
