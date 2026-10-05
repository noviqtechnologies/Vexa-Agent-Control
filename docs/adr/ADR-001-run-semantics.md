# ADR-001: Run Semantics and Transport Correlation Hierarchy

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md)

---

## 1. Context & Problem Statement

Vexa Agent Control intercepts traffic across disparate protocols:
- HTTP / SSE streaming (OpenAI / Anthropic REST APIs)
- Model Context Protocol (MCP) over standard I/O (`stdio` JSON-RPC)
- MCP over HTTP / SSE
- Direct CLI commands (`agentwall scan`, `agentwall proxy`)

Previously, correlation identifiers were overloaded: `session_id` was conflated with individual LLM completion requests, and audit entries lacked parent-child causal relationships. To support structured distributed tracing, forensic investigation, and deterministic replay without breaking existing audit logs, a rigorous correlation ID hierarchy is required.

---

## 2. Decision: The 7-Tier Correlation Hierarchy

We establish a strict, 7-tier correlation hierarchy for all agent operations:

```
[trace_id] (End-to-End User Task / Workflow, W3C TraceContext)
   │
   └── [run_id] (Discrete Agent Autonomous Iteration / Task Loop)
          │
          ├── [session_id] (Long-Lived Gateway / Transport Session)
          │      │
          │      └── [process_id] (OS Process Hosting Agent / MCP Server)
          │
          └── [span_id] (Discrete Unit of Work / LLM Call / Tool Exec)
                 │
                 ├── [request_id] (Wire-Level Wire Protocol Request / Roundtrip)
                 │
                 └── [event_id] (Point-in-Time Discrete Audit / Security Event)
```

### Definitions & Lifecycle:

1. **`trace_id`** (UUIDv4 or W3C `trace_id` 32-hex):
   - Scope: Represents the end-to-end user goal or conversation (e.g. "Refactor auth module").
   - Origin: Ingested from incoming W3C `traceparent` header if present; otherwise generated at gateway ingress upon the first request of a task.
2. **`run_id`** (UUIDv4):
   - Scope: Represents a single execution attempt or plan execution cycle of an agent. A user task may involve multiple runs if retried or resumed.
   - Origin: Gateway generated or supplied by orchestrator SDK.
3. **`session_id`** (UUIDv4 or client-assigned string, e.g. `sess-workstation-1`):
   - Scope: The transport/gateway connection lifecycle. Corresponds directly to the existing `session_id` in [`AuditEntry`](file:///c:/AgentWall/agentwall/src/audit/logger.rs#L58).
   - Invariant: **Must remain backward-compatible** with existing audit chains.
4. **`span_id`** (16-hex characters / W3C `parent_id`):
   - Scope: A timed execution segment (e.g. LLM inference, tool execution, policy evaluation).
   - Hierarchy: Can be nested via `parent_span_id`.
5. **`process_id`** (String: `{hostname}:{pid}`):
   - Scope: Tracks the OS process ID and host where the agent or MCP child process runs.
6. **`request_id`** (UUIDv4 or wire string, e.g. `req-1234`):
   - Scope: The single wire-level HTTP request/response exchange or MCP JSON-RPC message ID.
7. **`event_id`** (UUIDv7 - time-sortable):
   - Scope: A point-in-time security finding, policy verdict, or audit entry within a span.

---

## 3. Transport-Specific Extraction & Mapping

| Transport | Ingress Correlation Mapping | Egress Header Propagation |
|---|---|---|
| **HTTP / SSE** | Reads `traceparent`, `X-Request-ID`, `X-Run-ID`. Generates `span_id` for proxy evaluation. | Injects `traceparent` (with gateway's `span_id`), `X-Request-ID`. |
| **MCP stdio** | Inspects JSON-RPC `_meta` object: `_meta.traceparent`, `_meta.run_id`. Uses JSON-RPC `id` as `request_id`. | Forwards modified JSON-RPC with sanitized parameters. |
| **MCP HTTP / SSE** | Reads HTTP headers on SSE stream connect; maps JSON-RPC message ID to `request_id`. | Propagates `traceparent` to upstream MCP server. |
| **CLI / SDK** | CLI assigns `run_id` per invocation; SDK propagates explicit run context struct. | Output captures all IDs in structured JSON. |

---

## 4. Consequences & Compatibility

- **Positive**: Clean distributed tracing across multi-agent pipelines; full alignment with OpenTelemetry conventions without early OTLP export dependency.
- **Negative**: Adds 24–48 bytes of envelope metadata per event.
- **Compatibility Guarantee**: The audit chain continues to use `session_id` and `entry_index` exactly as defined in `AuditEntryV1Legacy`. The expanded hierarchy is carried in the **Trace Store**, joined to audit records via `(session_id, entry_index)`.
