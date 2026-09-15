# GitOps Policy Precedence & Central Ceiling Guide

Vexa Agent Control operates a dual-layer policy governance model designed specifically for enterprises, agencies, and AI engineering teams.

This guide outlines the merge semantics, security invariants, client attribution hierarchy, and privacy guarantees enforced across all environments.

---

## 1. The Central Policy Ceiling Principle

In enterprise security, local projects must move fast without compromising corporate governance. 

Agent Control enforces a **hard ceiling**:
> **Central Corporate Policy sets the security ceiling. Repository-local `.agentcontrol.yaml` policies can only tighten controls, never loosen or bypass Central restrictions.**

```
       ┌────────────────────────────────────────────────────────┐
       │             Central Corporate Policy                   │
       │  (Enforced from Control Hub or explicit --policy flag) │
       └────────────────────────────────────────────────────────┘
                                   │
                                   ▼  [CEILING INVARIANT]
       ┌────────────────────────────────────────────────────────┐
       │             Repository .agentcontrol.yaml              │
       │  • Can DENY tools permitted by Central                 │
       │  • Can ADD stricter parameter validation               │
       │  • Can RESTRICT to a subset of Central LLM models      │
       │  • Can LOWER spend caps or concurrency                 │
       │  ✖ CANNOT allow tools denied by Central                │
       │  ✖ CANNOT route to unapproved external LLM models       │
       │  ✖ CANNOT elevate spend or concurrency limits          │
       │  ✖ CANNOT escape Central Tenant Boundary Locks         │
       └────────────────────────────────────────────────────────┘
```

---

## 2. Rule Merge Semantics

When `agentcontrol` resolves active policy, it merges the Central Policy with the nearest discovered repository `.agentcontrol.yaml` using the following deterministic rules:

### A. MCP Tools & Actions
- **Explicit Deny Invariant:** If Central policy denies a tool (e.g. `bash`, `execute_command`), no repository policy can allow it. Attempting to allow an unapproved tool results in an immediate startup error:
  `GitOps policy violation: repository policy attempts to allow tool 'X' which is explicitly DENIED by Central Policy`
- **Allowlist Restriction:** If Central enforces an explicit tool allowlist, repository policies cannot introduce tools outside that allowlist.
- **Local Tightening:** If Central allows a tool, repository policies can explicitly deny it or attach tighter parameter constraints (e.g., additional regex validators, path traversal checks).

### B. LLM Models
- **Strict Intersection:** The effective allowed models list is the mathematical intersection of `central.llm.allowed_models` and `repo.llm.allowed_models`.
- **Zero-Tolerance Bypass:** If a repository specifies only models not permitted by Central (empty intersection), the gateway halts startup with a fatal violation error.

### C. Rate Limits & Spend Caps
- **Minimum Enforced:** The effective rate limit is `min(central.max_calls_per_second, repo.max_calls_per_second)`.
- **Token Caps & Concurrency:** Session token limits and concurrency ceilings take the lower of Central and Repo values.

### D. Central Tenant Boundary Lock
- If Central policy specifies an organization attribution `client_id` (e.g. `acme_corp`), the repository policy is locked to that tenant boundary.
- Any attempt in local GitOps YAML or request headers to attribute costs to a different tenant is rejected with a boundary violation error.

---

## 3. 4-Tier Client Attribution Hierarchy

For agencies, multi-client service firms, and multi-tenant engineering platforms, Agent Control tracks every token and microcent against client and project spend ledgers.

Attribution tags (`client_id`, `project_id`, `cost_center`) are resolved using strict 4-tier precedence:

| Tier | Source | Example | Use Case |
|---|---|---|---|
| **1 (Highest)** | HTTP Request Headers | `X-AgentControl-Client-ID: client_acme`<br/>`X-AgentControl-Project-ID: proj_checkout`<br/>`X-AgentControl-Cost-Center: cc_frontend` | Per-request dynamic attribution by agent runtimes |
| **2** | Environment Variables | `AGENTCONTROL_CLIENT_ID=client_acme`<br/>`AGENTCONTROL_PROJECT_ID=proj_checkout`<br/>`AGENTCONTROL_COST_CENTER=cc_frontend` | CI/CD container and developer environment defaults |
| **3** | GitOps Policy YAML Metadata | `metadata:`<br/>`  attribution:`<br/>`    client_id: "client_acme"` | Repository-wide attribution committed to git |
| **4 (Fallback)** | System Fallback | `"default"` | Unattributed legacy traffic |

### Slug Sanitization & CSV Injection Defense
All attribution values are sanitized against the character set `^[a-zA-Z0-9_\-\.]{1,64}$`. Commas, double quotes, newlines, and control characters are converted to underscores (`_`), eliminating CSV formula injection (`=cmd|...`) when exporting to financial billing platforms.

---

## 4. Zero-Payload Privacy by Default

By default, Agent Control **never logs raw prompt or completion text** to persistent SQLite databases.

- **Default Privacy Mode:** The SQLite `egress_events` table persists only cryptographic SHA-256 hashes (`request_body_hash` and `response_body_hash`) along with token counts, latency, and policy verdicts.
- **Opt-In Debug Mode:** To inspect full prompt/response payloads during local development or troubleshooting, use the `--record-payloads` flag or set `AGENTCONTROL_RECORD_PAYLOADS=true`:
  ```bash
  # Enable raw payload recording for debugging
  agentcontrol dev --record-payloads
  agentcontrol protect --record-payloads
  agentcontrol start --record-payloads
  ```

---

## 5. Spend Management & Invoicing CLI

Agent Control includes a zero-telemetry local SQLite spend ledger for immediate financial visibility and invoicing exports:

```bash
# Check current spend and budget caps
agentcontrol spend status --agent-id agent-local

# Export invoice-ready token usage records to CSV
agentcontrol spend export --format=csv --client=acme_corp --output=./invoices/acme_march.csv

# Export records to formatted JSON
agentcontrol spend export --format=json --client=acme_corp

# Configure local budget caps (daily, weekly, monthly)
agentcontrol spend set-cap --agent-id agent-local --cap-cents 1000 --period daily
```

### Export Schema (CSV / JSON)
- `timestamp`: RFC-3339 execution timestamp
- `request_id`: Unique request UUID
- `client_id`: Sanitized client attribution tag
- `project_id`: Sanitized project attribution tag
- `cost_center`: Financial cost center code
- `agent_id`: Authenticated identity or session ID
- `provider`: Upstream provider (`openai`, `anthropic`, etc.)
- `model`: Target model ID (`gpt-4o`, `claude-3-5-sonnet`)
- `input_tokens`: Prompt token count
- `output_tokens`: Completion token count
- `total_tokens`: Total token consumption
- `cost_cents`: Exact financial cost in USD cents
- `cost_usd`: Exact financial cost in USD dollars
- `is_estimated`: `false` if verified provider usage; `true` if character estimate

---

## 6. Cryptographic Compliance & Evidence Verification

Agent Control provides honest, non-inflated compliance reports with real HMAC cryptographic chain verification:

```bash
# Generate Markdown evidence report
agentcontrol compliance report --log-path ~/.agentcontrol/audit.jsonl

# Generate JSON report for CI/CD or SIEM ingestion
agentcontrol compliance report --log-path ~/.agentcontrol/audit.jsonl --format json --output report.json
```

Reports cryptographically verify the append-only HMAC chain via `agentcontrol::audit::verifier`. If a single byte or entry is altered or missing, the status immediately reports:
- **`TAMPERING_DETECTED`** for Logical Access Controls (SOC 2 CC6.1).
- **`EVIDENCE_COLLECTED`** or **`CONTROLS_ACTIVE`** for active boundary defense, DLP, and AI input/output verification.
