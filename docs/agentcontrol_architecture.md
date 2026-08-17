# Agent Control Architecture & Core Concepts

Agent Control is a specialized security gateway, shadow proxy, and identity governance platform designed for AI agents operating over the Model Context Protocol (MCP), HTTP/HTTPS, and WebSockets.

---

## 🏗️ Architecture Diagram

Below is the architectural representation of Agent Control. Inspired by enterprise platforms, it sits between AI Agents/Clients and the external services/tools they consume, serving as a policy enforcement point.

![Agent Control Architecture](file:///c:/Agent Control/agentcontrol/docs/agentcontrol_architecture_diagram.png)

---

## 🔑 Key Concepts

### 🔐 1. Zero-Trust Authentication Flow
Agent Control operates under a Zero-Trust posture, binding every agent tool execution to a cryptographically validated identity:
* **Bearer Token Extraction:** The agent client passes an OIDC JSON Web Token (JWT) in the `Authorization: Bearer <token>` HTTP header.
* **OIDC Discovery & JWKS Caching:** Upon receiving a token, Agent Control queries the Identity Provider's (IdP) OIDC configuration endpoint (`{issuer}/.well-known/openid-configuration`) to retrieve the JSON Web Key Set (`jwks_uri`). These public RSA/EC verification keys are cached in RAM with a configurable TTL rotation to prevent latency overhead.
* **Claims Validation & Policy Mapping:** Agent Control validates the token's signature, expiration (`exp`), audience (`aud`), and issuer (`iss`). It extracts the subject claim (`sub`, representing the user or specific agent system) and group memberships (e.g., via `groups`). These groups are matched against `policy_bindings` inside `agentcontrol-policy.yaml` to enforce fine-grained, role-based tool restrictions.

---

### 💾 2. Data Persistence & Authoritative Spend Governance Strategy
Agent Control stores activity metrics, token usage, and audit records with strict tiered authority:
* **Local Workstation Telemetry:** Local tool call history and observational metrics are recorded to a lightweight SQLite database for developer dashboards and debugging.
* **Authoritative PostgreSQL Spend Ledger (`control-plane/spend`):** In Team and Enterprise deployments, PostgreSQL is the **sole authority for hard financial budgets**. All preflight bounded reservations (`POST /api/v2/spend/authorize`), settlements, releases, and immutable transaction logs (`spend_events`) are processed in serializable transactions with integer microcents arithmetic ($1 = 100,000,000 µ¢).
* **SIEM Telemetry Streaming:** For corporate compliance, the gateway streams audit events directly to enterprise SIEM platforms (Splunk, Datadog, OpenSearch) in real time over HTTP/HTTPS, eliminating long-term log storage overhead on the gateway nodes themselves.

---

### 🛡️ 3. Encryption & Cryptographic Integrity
Agent Control employs rigorous mathematical controls to guarantee confidentiality, authenticity, and tamper-resistance:
* **In-Transit Encryption (TLS):** All public endpoints (gateway API, dashboard, and upstream integrations) are forced through HTTP/2 over TLS secured by memory-safe rustls.
* **Tamper-Evident HMAC Log Chaining:** The gateway records audit entries to disk in a cryptographic hash chain. Each log entry $n$ includes an HMAC signature computed from the current payload concatenated with the signature of the preceding entry:
  $$\text{HMAC}_n = \text{HMAC-SHA256}(K, \text{Payload}_n \parallel \text{HMAC}_{n-1})$$
  *If an attacker modifies, deletes, or inserts any historical log line, the hash chain breaks instantly, causing verification tools (`agentcontrol verify-log`) to flag the tamper point.*
* **Scoped Credential Governance:** Agent Control acts as a credential issuer, replacing long-lived API keys with short-lived scoped tokens (e.g. TTL of 1 hour) bound to specific allowed tools, preventing secret exposure.

---

### ⚙️ 4. Core Operational Modes & Security Engines
* **Observation & Routing (Local Shadow Proxy):** Intercepts traffic transparently to observe patterns and generate YAML policies.
* **Enforcement Gateway:** Actively enforces safety policies with hot-reloading support.
* **Safe Mode (FR-303a):** 15 built-in, config-free rules covering dangerous commands, path traversal, and SSRF (metadata endpoints).
* **Stateful Sequence Rules (ADR Framework):** Detects multi-turn attack patterns using a sliding-window `SessionTracker` to catch complex exfiltration steps.
* **ADR Security Benchmark:** Stress-tests configuration with 303 tasks across 17 threat categories, generating a grade report.
