# ADR-006: Observability, Export Strategy, and OTLP Ingestion Deferral

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md)

---

## 1. Context & Problem Statement

Initial plans proposed building both OpenTelemetry (OTLP) export and OTLP ingestion in early phases. However, the Feedback v4 Assessment identified this as a critical distraction:
- Supporting OTLP trace ingestion turns Vexa into a generic APM collector (competing with Datadog/Jaeger), diluting its core mission as a zero-trust agent security gateway.
- Implementing OTLP export before establishing a stable, native JSON/JSONL schema complicates local debugging and CLI workflows.

---

## 2. Decision: Phased Export Roadmap & Product Kill List

We establish a strictly sequenced observability roadmap:

```
[Phase 1] ──► Native JSON & JSONL File Streaming (`agentwall export-traces`)
    │
    ▼
[Phase 3] ──► Native OpenTelemetry (OTLP) Exporter (Push to Jaeger/Datadog over gRPC/HTTP)
    │
    ▼
[PERMANENT KILL LIST] ──► OTLP Ingestion (Barred from Vexa Core)
```

### 2.1 Directives:
1. **Phase 1 Priority (Native JSON/JSONL)**:
   - Command: `agentwall export-traces --format jsonl --output ./traces.jsonl`.
   - Streaming endpoint: `GET /api/v1/traces/stream` (SSE emitting NDJSON lines).
   - Enables immediate interoperability with `jq`, Python analysis scripts, and internal SIEM parsers.
2. **Phase 3 OTLP Exporter**:
   - Implements OpenTelemetry Trace and Log specifications (v1.0.0+).
   - Maps `trace_id`, `span_id`, and attributes (`gen_ai.system`, `gen_ai.request.model`, `mcp.tool.name`) following OpenTelemetry GenAI semantic conventions.
   - Verified in CI against a real, live Jaeger/OTEL Collector container instance.
3. **Formal Kill Directive: OTLP Ingestion**:
   - Vexa will **NOT** accept inbound OTLP traces from external services. Vexa generates trace spans exclusively for payloads traversing its local proxy or wrapped MCP transports.

---

## 3. Consequences

- **Focus**: Keeps the gateway binary small, dependencies minimal (no bulky generic telemetry ingestion frameworks), and startup times sub-millisecond.
- **Interoperability**: Enterprise teams can route Vexa's exported traces into existing telemetry backends in Phase 3 without forcing OTLP complexities onto local developers in Phase 1.
