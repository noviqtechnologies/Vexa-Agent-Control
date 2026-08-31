# Run Explorer & Forensic Dossiers User Guide

## Overview

The **Run Explorer** gives security and platform teams deep, deterministic visibility into every LLM request routed through Vexa Agent Control. It correlates preflight spend authorization locks, upstream token economics, policy snapshots, and immutable financial ledger transactions.

---

## Accessing the Run Explorer

1. Navigate to the Vexa SOC Console (`http://localhost:5173` or your production domain).
2. In the sidebar, expand **Observability & Runs** $\rightarrow$ **Run Explorer** (or visit `/runs`).
3. Cross-platform compatibility: accessible in any modern web browser on Windows, macOS, Linux, and mobile browsers.

---

## Run Table Columns

| Column | Description |
|---|---|
| **Run ID** | Unique reservation identifier. Click anywhere on the row to slide open the forensic dossier drawer. |
| **Started** | Timestamp when the preflight spend reservation was granted. |
| **Device / Origin** | Gateway device ID originating the request. |
| **Provider & Model** | Upstream provider (`OPENAI`, `ANTHROPIC`, `GROQ`) and model selector (e.g. `gpt-4o`). |
| **State** | Lifecycle status badge (`AUTHORIZED`, `SETTLED`, `RELEASED`, `DENIED`). |
| **Reserved** | Budget reserved before dispatch (microcents converted to USD). |
| **Settled** | Authoritative post-dispatch actual cost. |
| **Duration** | Roundtrip latency in milliseconds. |

---

## The Forensic Dossier Drawer

Clicking any row opens the slide-out dossier drawer with 5 dedicated tabs:

### 1. Economics Tab
Displays the complete monetary flow:
- **Reserved Amount**: Estimated upper-bound lock.
- **Settled Amount**: Actual consumption based on token usage.
- **Released Amount**: Budget returned to the pool (`Reserved - Settled`).
- **Duration & Latency**: Timestamp milestones.

### 2. Identity Tab
Shows the origin workstation, device compliance status, project scope, and cryptographic correlation request ID.

### 3. Policy Tab
Displays the exact JSONB `policy_snapshot` and price book version that governed the request at execution time.

### 4. Events Tab
Lists the immutable, append-only financial ledger events (`AUTHORIZED`, `SETTLED`, `RELEASED`).

### 5. Dispatch Tab
Details upstream provider endpoints, model selectors, and transport metrics.

---

## Fast Navigation: "View Effective Policy"

In the header of the Dossier Drawer, click **"⚖️ View Effective Policy"** to jump directly to the **Effective Policy Explorer** pre-populated with the exact Device, Project, Provider, and Model parameters from the run.

---

## API Reference

### List Runs
```http
GET /api/v1/runs?hours=24&limit=50&provider=openai&state=SETTLED
Authorization: Bearer <token>
```

### Get Single Dossier
```http
GET /api/v1/runs/{run_id}
Authorization: Bearer <token>
```
