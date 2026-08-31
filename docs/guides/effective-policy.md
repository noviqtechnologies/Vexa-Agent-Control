# Effective Policy Explorer User Guide

## Overview

The **Effective Policy Explorer** enables operators to determine exactly which policies, limits, and rules apply to a given combination of Device, Agent, Virtual Key, Project, Provider, Model, and Route at any point in time.

---

## 5-Level Hierarchical Provenance Ladder

Policy resolution follows a strict 5-level hierarchy:

```
Level 1: Organization   ──► Base Tenant Policy & Default Modes
Level 2: Group          ──► Agent Group Policy Overrides
Level 3: Spend          ──► Authoritative Microcent Budget Caps & Actions
Level 4: Virtual Key    ──► Scoped API Key Restrictions (Allowed Models/Routes)
Level 5: Device         ──► Sentry Hardware Compliance & Enrollment
```

### Confidence Indicators

| Badge | Meaning |
|---|---|
| 🟢 `observed` | Authoritatively configured and active. |
| ⚪ `not_configured` | No override at this level; inherits parent defaults. |
| 🔴 `unknown` | Target entity not found; requires investigation. |

---

## How to Debug Denied Requests

1. Identify the denied run in **Run Explorer**.
2. Click **"⚖️ View Effective Policy"** in the dossier drawer.
3. Inspect the synthesized **Effective Policy Bound** panel.
4. If `ACTION: HARD_DENY` is displayed, scroll through the **5-Level Provenance Ladder** to pinpoint which tier (e.g. Level 3: Spend) enforced the budget exhaustion.

---

## Historical Policy Resolution

To inspect which rules governed a request in the past:
1. Enter an ISO-8601 UTC timestamp in the **Historical Timestamp** field (e.g., `2026-08-01T12:00:00Z`).
2. Click **"🔍 Resolve Effective Policy"**.
3. The engine evaluates active published policy versions as of that exact moment.

---

## API Reference

```http
GET /api/v1/policy/effective-explorer?device_id=win-1&provider=openai&model=gpt-4o&at=2026-08-31T15:00:00Z
Authorization: Bearer <token>
```
