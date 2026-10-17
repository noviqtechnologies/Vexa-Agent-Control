# Vexa Agent Control — Architecture Documentation Suite

**Project:** Vexa Agent Control  
**Document Set Version:** 2.0 (PRD P0 Baseline Specification)  
**Last Updated:** 2026-10-15  
**Governing PRD:** [vexa-agent-control-requirements.md](file:///c:/agentcontrol/agentcontrol/PRD/pending/vexa-agent-control-requirements.md)  
**Compliance Scope:** 24 P0 Functional Requirements (FR) + 14 P0 Non-Functional Requirements (NFR)  

---

## 🧭 Navigation & Document Overview

This directory contains the authoritative, production-grade system architecture specifications for Vexa Agent Control, modeling the system strictly on the **Sovereign Self-Hosted Invariant (NFR-026)** and structured using the templates in `design/architecture/`.

```
architecture/
├── README.md                  # This Index & Architecture Guide
├── system-architecture.md     # Primary System Architecture & Component Blueprint
├── system-diagram.mmd         # End-to-End Mermaid System Architecture Diagram
├── data-flows.md              # Detailed Sequence Diagrams & Operational Data Flows
├── data-architecture.md       # Data Stores, PostgreSQL/SQLite Schemas, & Privacy Controls
└── api-specifications.md      # REST APIs, Local IPC, Policy YAML v2, & Error Contracts
```

---

## 📑 Document Catalog

### 1. [System Architecture Specification](file:///c:/agentcontrol/agentcontrol/architecture/system-architecture.md)
The primary system blueprint detailing:
- **Architectural Ambition & Sovereign Self-Hosted Invariant (NFR-026):** 100% customer-controlled infrastructure; zero Vexa cloud or SaaS dependencies.
- **Three Staged Deployment Profiles:** Local Workstation Sentry (P0 Core), Self-Hosted Team Hub & Proxy (P1 / P0 Shared Core), and Enterprise Hub (Kubernetes / Helm / On-Prem).
- **Component Deep Dive:**
  - High-throughput Rust Gateway Engine (raw `hyper 1.x`, `arc_swap` lock-free policy reloads).
  - Pre-execution tool authorization and versioned decision state machine (`ALLOW`, `DENY`, `REQUIRE_APPROVAL`, `WARN/OBSERVE`, `ERROR/INDETERMINATE`).
  - Zero-Trust MCP tool firewall (stdio/HTTP quotas, nesting depth, 64MB RSS limits).
  - Canonical schema digest pinning (`sha256(canonical_schema)`) and drift detection (**FR-007**).
  - Deep parameter, path traversal, and SSRF egress constraints (**FR-008**).
  - Inline DLP secret redaction (RegexSet, Shannon entropy, Luhn, BIP-39) (**FR-010**).
  - Exact-action Human-in-the-Loop (HITL) atomic 6-state CAS machine (**FR-009**).
  - Run correlation, W3C `traceparent`, and bounded autonomy budgets (**FR-013**, **FR-034**).
  - Cryptographic HMAC-SHA256 chained audit outbox with pre-dispatch `sync_all()` fsync (**FR-014**, **FR-015**, **NFR-007**).
  - Non-destructive client wrapping, journaling, and `.baseline.bak` atomic rollback (**FR-019**, **NFR-010**).
- **Requirements Traceability Matrix:** Direct mapping of all 24 P0 FRs and 14 P0 NFRs.
- **Architectural Decision Records (ADRs):** Summaries for ADR-001 through ADR-010.

### 2. [System Diagram (Mermaid)](file:///c:/agentcontrol/agentcontrol/architecture/system-diagram.mmd)
Visual system topology rendered in Mermaid syntax:
- Boundaries between Developer Workstation (P0), Self-Hosted Control Plane (P1), Customer Infrastructure (IdP, SIEM, Registries), and Upstream Model Endpoints.
- Component-level interactions between CLI, Gateway pipeline, SQLite/JSONL persistence, Go Control Hub, and PostgreSQL.

### 3. [Data Flows & Sequence Specifications](file:///c:/agentcontrol/agentcontrol/architecture/data-flows.md)
Eight end-to-end operational sequence diagrams:
1. **MCP Interception Flow:** stdio and Streamable HTTP with pre-auth, schema drift, path checks, and synchronous fsync.
2. **Universal LLM Streaming Proxy:** W3C tracing, model authorization, preflight spend reservation, and SSE settlement.
3. **HITL Exact-Action Approval:** Single-use ActionHash nonces and the 6-state CAS machine.
4. **Observe / Shadow Mode:** Live audit-only evaluation with `OBSERVED_ALLOW` and explicit would-deny audit records.
5. **Policy Hot-Reload:** PostgreSQL `pg_notify` to Go SSE broker to gateway ArcSwap swap.
6. **Local Sentry Lifecycle:** Connect, `.baseline.bak` journaling, and byte-for-byte rollback.
7. **Emergency Stop & Revocation:** Instant session termination preserving audit evidence.
8. **Audit Durability & SIEM Backpressure:** Local `sync_all()` blocking write decoupled from async SIEM export.

### 4. [Data Architecture Specification](file:///c:/agentcontrol/agentcontrol/architecture/data-architecture.md)
Comprehensive data architecture detailing:
- **Local Workstation Data Tier (P0):** `audit.jsonl` (HMAC chaining algorithm and zero-hash sentinel), `audit.key`, SQLite `traces.db` (analytical session graph), SQLite `spend_ledger.db` (integer microcent economics), and client manifests.
- **Self-Hosted Control Hub Data Tier (P1):** PostgreSQL 15+ schemas for `policies`, `provider_credentials` (AES-256-GCM), `virtual_keys`, `audit_events` (monthly partitions), and `hitl_tickets`.
- **Privacy & Segregated Access Controls (FR-023, NFR-006):** Metadata-first default; strict role-gated raw payload access with dedicated audit trail.
- **Performance & Latency Profiles (NFR-014):** Sub-millisecond hot paths vs. decoupled background queues.

### 5. [API & Contract Specifications](file:///c:/agentcontrol/agentcontrol/architecture/api-specifications.md)
Standardized, versioned interfaces across the system:
- **Control Hub REST API:** Bootstrap, SSE delta stream, policy CRUD, encrypted credentials, telemetry ingest, and emergency stop.
- **Gateway Local IPC & HTTP API:** Health and readiness probes, capability manifest and posture endpoints, HITL approval resolution, and the 12 canonical CLI commands.
- **Declarative Policy Specification (YAML v2):** Complete schema including tools, DLP, autonomy, spend, and audit rules.
- **Capability Manifest Schema:** Machine-readable declaration of enforcement coverage and blind spots per client.
- **Error Response Contract & Reason Codes:** Standardized JSON error envelope and stable reason code catalog.

---

## 🎯 P0 Requirements Coverage Summary

| Priority Set | Total Requirements | Addressed in Architecture | Conformance Status |
|---|:---:|:---:|:---:|
| **P0 Functional Requirements (FR)** | 24 | 24 | ✅ 100% Specified |
| **P0 Non-Functional Requirements (NFR)** | 14 | 14 | ✅ 100% Specified |
| **Total Core P0 Scope** | **38** | **38** | ✅ **Complete Baseline** |
