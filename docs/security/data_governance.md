# Vexa Agent Control — Data Governance, Retention, & Key Management Standard

**Document Version:** 1.0.0  
**Status:** Approved Security Standard  
**Applies to:** Vexa Agent Control `v1.0.x` – `v1.2.x`  
**Classification:** Public Security Specification  

---

## 1. Executive Data Policy

Vexa Agent Control acts as a local and upstream security control boundary for AI agents and LLM tool invocations. A foundational security principle of the platform is **Zero Plaintext Prompt Persistence by Default**.

This specification outlines concrete, contractual commitments regarding:
1. **Data Retention & Automated Pruning**
2. **Tenancy Boundaries & Cryptographic Isolation**
3. **Key Custody, KMS Hierarchy, & Secret Scrubbing**
4. **Incident Response (IR) & Breach Notification Commitments**

---

## 2. Data Retention & Pruning Architecture

| Storage Tier | Data Captured | Encryption at Rest | Default Retention | Pruning Enforcement |
|---|---|---|---|---|
| **Local Spool (`audit.log` / SQLite)** | Anonymized tool calls, token usage, policy verdicts, HMAC hashes | AES-256 / OS DPAPI / File ACL | **30 Days** (configurable 7–365d) | FIFO rotation with HMAC tombstone markers |
| **In-Memory Cache (Semantic / Prompt)** | Embeddings, hashed token fingerprints | Ephemeral RAM only (non-swappable) | Max 1 hour TTL | Evicted on process stop or LRU limit |
| **Control Hub (PostgreSQL / WAL)** | Aggregate telemetry, spend attribution, compliance event records | AES-256-GCM envelope encryption | **90 Days** (Enterprise contract variable) | Deterministic nightly cron with vacuuming |
| **Raw Prompt Payloads** | **NOT RETAINED** (Redacted in-flight by DLP scanner) | N/A | **0 Seconds** | Inline RegexSet masking before disk writes |

### Automated Pruning Command:
Operators can verify and force immutable audit pruning using:
```bash
agentcontrol audit prune --older-than 30d --verify-chain
```
Pruning preserves cryptographic chain integrity by recording an append-only `tombstone` entry signed with HMAC-SHA256 summarizing pruned entry counts and boundary hashes.

---

## 3. Tenancy & Workload Isolation Model

```
┌────────────────────────────────────────────────────────────────────────┐
│                        TENANCY ISOLATION BOUNDARY                      │
│                                                                        │
│   Workstation A (User 1)              Workstation B (User 2)           │
│   ┌───────────────────────────┐       ┌───────────────────────────┐    │
│   │ Local SQLite / IPC Socket │       │ Local SQLite / IPC Socket │    │
│   │ Bound to UID / User SID   │       │ Bound to UID / User SID   │    │
│   └─────────────┬─────────────┘       └─────────────┬─────────────┘    │
│                 │ mTLS / OIDC JWT                   │ mTLS / OIDC JWT  │
│                 ▼                                   ▼                  │
│   ┌───────────────────────────────────────────────────────────────┐    │
│   │             CONTROL HUB MULTI-TENANT ISOLATION LAYER          │    │
│   │                                                               │    │
│   │   Tenant Alpha (Org A)            Tenant Beta (Org B)         │    │
│   │   • Isolated PostgreSQL Schema    • Isolated PostgreSQL Schema│    │
│   │   • Distinct KMS Customer Key     • Distinct KMS Customer Key │    │
│   │   • Scoped Policy Trees           • Scoped Policy Trees       │    │
│   └───────────────────────────────────────────────────────────────┘    │
└────────────────────────────────────────────────────────────────────────┘
```

1. **Workstation Level:** Single-tenant local daemon process running strictly under the invoking OS user context (`%LOCALAPPDATA%` on Windows, `~/.local/share` on Linux/macOS). Cross-user socket access is prevented by file permission masks (`0600`) and Windows discretionary access control lists (DACLs).
2. **Team / Hub Level:** Logical schema separation in PostgreSQL per organization tenant. Queries require parameterized `tenant_id` validation enforced at the middleware repository boundary.
3. **Cross-Tenant Leakage Defense:** No telemetry or audit records are queryable or aggregatable across organizational tenant boundaries.

---

## 4. Key Management & Cryptographic Hierarchy

```
[ Cloud KMS / HSM / Hardware Security Module ]
                   │
                   ▼  Master Key Encryption Key (KEK)
[ Tenant Data Encryption Key (DEK) - AES-256-GCM ]
                   │
                   ├──▶ Secrets at Rest (Upstream API Tokens in Vault)
                   ├──▶ HMAC-SHA256 Audit Log Chaining Secret
                   └──▶ Session Ephemeral Token Key (CSPRNG Ed25519)
```

1. **Key Custody Models:**
   * **Local / Air-Gapped Mode:** Workstation keys are derived using OS-native key stores (Windows DPAPI, macOS Keychain, Linux secret-service) or ephemeral CSPRNG seeds.
   * **Enterprise Central Vault:** Customer-Managed Keys (BYOK via AWS KMS, Azure Key Vault, or HashiCorp Vault).
2. **Secret Scrubbing (DLP Engine):**
   * Pre-execution 21-pattern `RegexSet` scanner redacts AWS, GitHub, OpenAI, SSH, PII, and high-entropy API tokens before any log writing or remote event export.
   * Redaction is non-reversible (one-way `[REDACTED:API_KEY]`).

---

## 5. Incident Response & Breach Notification SLAs

Vexa commits to the following contractual incident response timelines:

| Milestone | Severity P1 (Critical) | Severity P2 (High) | Severity P3 (Medium) |
|---|---|---|---|
| **Initial Acknowledgment** | $\le 1$ Hour (24/7) | $\le 4$ Business Hours | $\le 1$ Business Day |
| **Triage & Threat Containment** | $\le 4$ Hours | $\le 24$ Hours | $\le 5$ Business Days |
| **Customer Breach Notification** | $\le 24$ Hours | $\le 72$ Hours | Within regular release notes |
| **Hotfix & CVE Publication** | $\le 48$ Hours | $\le 7$ Business Days | Scheduled minor release |

### Coordinated Disclosure & Reporting:
* **Security Contact:** [`contact@vexasec.io`](mailto:contact@vexasec.io)
* **Advisory Portal:** [GitHub Security Advisories](https://github.com/noviqtechnologies/Vexa-Agent-Control/security/advisories)
