# ADR-007: UI Packaging, Local REST API, and Frontend Deferral

**Status:** APPROVED (Phase 0a Baseline)  
**Date:** 2026-10-04  
**Author:** Architecture Team  
**Governing Standard:** [Plan Review Feedback v4](file:///C:/Users/wasim/.gemini/antigravity-ide/brain/9469605e-81c2-40a5-9567-198d8ebbf4c0/plan_review_feedback_v4.md)

---

## 1. Context & Problem Statement

Initial proposals suggested building a modern React + Vite single-page application (SPA) for the local developer dashboard in Phase 1. 

However, building an external React web app before the local daemon's REST/SSE API is stable creates high risk:
- Requires multi-process coordination (Node.js dev server or multi-asset bundling).
- Diverts engineering focus away from security enforcement, proxy latency, and crash recovery.
- Threatens binary self-containment if the UI cannot be statically linked into the single Rust binary.

---

## 2. Decision: API-First Architecture & Embedded Lightweight UI

We adopt an **API-First design**. The core product contract is the **versioned local REST and SSE API (`/api/v1/*`)**.

```
┌────────────────────────────────────────────────────────────┐
│              RUST DAEMON (Static Binary)                   │
│                                                            │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Versioned HTTP / SSE Engine (`/api/v1/*`)           │  │
│  │  • `/api/v1/traces`          • `/api/v1/hitl/respond`│  │
│  │  • `/api/v1/policy/status`   • `/api/v1/stats`       │  │
│  └──────────────────────────┬───────────────────────────┘  │
│                             │ Serves JSON & SSE            │
│  ┌──────────────────────────┴───────────────────────────┐  │
│  │  Embedded Diagnostic Console (Vanilla HTML/CSS/JS)   │  │
│  │  • Single statically-compiled asset                  │  │
│  │  • Zero npm/Node.js runtime dependency               │  │
│  │  • Served at `http://127.0.0.1:18080/dashboard`      │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

### 2.1 Directives:
1. **API Contract Priority**:
   - All diagnostic, telemetry, trace querying, and HITL approval capabilities are exposed through versioned HTTP endpoints under `/api/v1/`.
   - The CLI (`agentwall status`, `agentwall traces`) consumes these exact endpoints.
2. **Phase 1 UI (Embedded Lightweight Dashboard)**:
   - Modern, responsive, single-file HTML/CSS/JS embedded directly into the Rust binary using `include_str!()` (expanding [`local_dashboard.html`](file:///c:/AgentWall/agentwall/src/local_dashboard/local_dashboard.html)).
   - Pure Vanilla CSS/JS; zero runtime npm dependencies; zero external CDN dependencies (works 100% offline in air-gapped workstations).
3. **Phase 3 Deferral (React Team Console)**:
   - A full-featured React / TypeScript web console is explicitly deferred to **Phase 3 (Team Collaboration Hub)**, where it connects to the centralized Docker Compose / Kubernetes management plane.

---

## 3. Consequences

- **Self-Contained Distribution**: The workstation sentry remains a single, statically-linked executable (~15MB) with zero external runtime requirements.
- **Stable API Surface**: External IDE extensions (VS Code, Cursor, JetBrains plugins) can integrate directly with the documented `/api/v1/*` REST API.
