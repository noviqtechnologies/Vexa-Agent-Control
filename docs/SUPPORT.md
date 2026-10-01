# Vexa Agent Control — Support, Commercial & Compatibility SLA

> **Document Version:** 1.0 (SMB Production Standard)  
> **Applicable Releases:** `1.0.x` and later  
> **Last Updated:** October 2026

---

## 1. Commercial Editions & Pricing Structure

Vexa Agent Control is engineered for engineering teams of all sizes with transparent pricing and zero forced lock-in:

| Dimension | Community (Local Developer) | Small-Team (Self-Hosted Hub) | Cloud SaaS / Enterprise |
|---|---|---|---|
| **Target Audience** | Individual engineers & open-source contributors | Engineering teams (5–50 developers) | Mid-market & enterprise organizations (50+ devs) |
| **Deployment Model** | Local binary proxy (`agentcontrol start`) | Single VM / Server Compose (`docker-compose.team.secure.yml`) | Managed cloud VPC or multi-region cluster |
| **Pricing** | **$0 / Free & Open Source** | **$19 / seat / month** (billed annually) | Custom contract / Volume licensing |
| **Control Plane** | Embedded SQLite & local web view | Self-hosted Go API + PostgreSQL | High-Availability Managed Control Plane |
| **Supported Clients** | Cursor, Claude Code, Codex, Antigravity, Claude Desktop | All supported clients + team policy sync | All supported clients + enterprise SSO & SCIM |
| **Policy Engine** | DLP Regex, Heuristic Screening, Spend Tracking | Centralized DLP, Spend Budgets, Org Policies | Custom ML Scanners, SIEM Streaming, SSO/RBAC |
| **Telemetry** | **Zero Telemetry (100% Offline)** | Telemetry stays within your private PostgreSQL | Optional encrypted audit forwarding |
| **Support Channel** | GitHub Issues & Community Discussions | Priority Email & Dedicated Slack Connect | 24/7 Phone, Slack, Dedicated Tam & Custom SLA |

---

## 2. Support Response SLAs

Vexa provides defined response times and escalation paths based on incident severity:

| Severity Level | Definition | Community | Small-Team | Cloud / Enterprise |
|---|---|---|---|---|
| **P1 — Critical Blocker** | Gateway daemon panic preventing all AI proxy traffic across team; active security vulnerability in release build | Best Effort (GitHub) | **$\le 4$ Business Hours** | **$\le 1$ Hour (24/7/365)** |
| **P2 — Major Impact** | Significant feature impairment (e.g. spend budget evaluation failure, UI dashboard unreachable) with workaround available | Best Effort | **$\le 8$ Business Hours** | **$\le 4$ Hours (24/7)** |
| **P3 — Minor Impact** | Non-critical UI glitch, documentation error, or non-blocking client wrapping edge case | Community triage | **$\le 1$ Business Day** | **$\le 8$ Business Hours** |
| **P4 — General Inquiry** | Architecture guidance, feature requests, migration questions | GitHub Discussions | **$\le 2$ Business Days** | **$\le 1$ Business Day** |

---

## 3. Data Processing Agreement (DPA) & Privacy Boundaries

### 3.1 Zero Prompt Retention Guarantee
- **Local Proxy Mode (`agentcontrol start`):** Prompt payloads flow strictly in-memory between the local IDE client and the upstream LLM provider over TLS. Prompts are **never written to disk, telemetry logs, or remote servers**.
- **Audit Outbox Redaction:** When audit logging is enabled, prompt text is hashed and tokenized locally before any event is saved to the SQLite spool or forwarded to the Control Hub. Only metadata (token counts, spend estimation, model name, policy verdicts, client fingerprint) is retained.

### 3.2 Cryptographic Key Custody Boundary
- **Local Workstation Model:** Provider API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.) remain exclusively in your local workstation environment variables and are never transmitted to the Control Hub.
- **Hub-Managed Vault Model:** If the organization chooses to centralize API keys, keys are encrypted in flight via HTTPS and immediately encrypted at rest using AES-256-GCM envelope encryption before entering PostgreSQL.

### 3.3 Telemetry & Network Isolation
- **No Phone-Home:** The core gateway binary contains zero telemetry beacons, Google Analytics, or third-party phone-home SDKs.
- **Air-Gapped & Offline Ready:** The standalone proxy runs 100% offline without requiring internet access (other than direct connectivity to your configured LLM provider endpoint).

---

## 4. Responsibility Assignment (RACI) Matrix

| Operational Area | Community (Local) | Self-Hosted Team Hub | Managed Cloud Hub |
|---|---|---|---|
| **Host VM & OS Hardening** | User | Customer IT / DevOps | Vexa Cloud Operations |
| **Docker & Network Firewall** | User | Customer IT / DevOps | Vexa Cloud Operations |
| **PostgreSQL Backup & Restores** | N/A (Local SQLite) | Customer IT / DevOps | Vexa Cloud Operations |
| **CSPRNG Secret Generation** | Automated (`agentcontrol`) | Customer Script (`bootstrap-team.sh`) | Automated Vault |
| **Gateway Binary Updates** | User (`agentcontrol upgrade`) | Customer DevOps | Automatic Canary Rollout |
| **LLM Provider API Accounts** | User | Customer Account | Customer Account (BYOK) |
| **Security Patch Monitoring** | User (GitHub Releases) | Customer DevOps | Vexa Cloud Operations |

---

## 5. Upgrade, Migration & Rollback Guarantees

### 5.1 Two-Way Schema Migrations
All database migrations in [`control-plane/db/migrations/`](file:///c:/AgentWall/agentwall/control-plane/db/migrations) are strictly paired:
- Every `.up.sql` migration is accompanied by a tested, deterministic `.down.sql` reversal.
- Automated CI migration tests verify that migrating `Up -> Down -> Up` leaves the database schema in a clean, identical state with zero data corruption.

### 5.2 Binary Rollback Guarantee
If an upgraded gateway binary or control plane container experiences an issue:
1. Stop the active process or container: `docker compose down` or `agentcontrol stop`.
2. Pin the previous binary version from [GitHub Releases](https://github.com/noviqtechnologies/Vexa-Agent-Control/releases).
3. The local client configuration files (`.manifest.json`) support seamless, byte-for-byte reversal via `agentcontrol unprotect` or `agentcontrol rollback`.

---

## 6. Contact & Escalation

- **Support Portal:** [https://support.vexasec.io](https://support.vexasec.io)
- **Security Vulnerability Reporting:** [SECURITY.md](file:///c:/AgentWall/agentwall/SECURITY.md) or [`contact@vexasec.io`](mailto:contact@vexasec.io)
- **Sales & Custom SLAs:** [`sales@vexasec.io`](mailto:sales@vexasec.io)
