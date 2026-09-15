# Vexa Agent Control Architecture & Core Concepts

**Vexa Agent Control** is an enterprise-grade AI safety layer, zero-trust MCP governance firewall, and FinOps LLM gateway designed for autonomous AI agents and coding assistants operating over the Model Context Protocol (MCP), HTTP/HTTPS, and WebSockets.

---

## 🏗️ Architecture Topology

Vexa Agent Control sits between AI Agents/Clients (Codex, Claude Desktop, Cursor, VS Code Continue) and external services/tools, decoupling responsibilities across four distinct architectural planes:

```text
┌──────────────────────────────────────────────────────────────────────────────┐
│                    1. Edge Execution Plane (Workstation)                     │
│                                                                              │
│   agentcontrol CLI (12 Canonical Commands: login, connect, doctor...)        │
│          │                                                                   │
│          ▼ (OS-Native Authenticated IPC: Named Pipe / Unix Socket 0600)      │
│   agentcontrol daemon (Per-User Background Service on 127.0.0.1:18080)       │
│          ├── Mode A: Cloud-Direct (VS Code Continue) ──HTTPS (Virtual Key)──┐│
│          │                                                                  ││
│          ├── Mode B: Local Proxy (Codex / Cursor) ──HTTP (Bearer Token)──┐  ││
│          │                                                               │  ││
│          └── MCP Governance: agentcontrol stdio-proxy (Child Process)   │  ││
│                 (< 64MB Memory Ceiling, 60s Timeout, Frame < 16MB)       │  ││
└──────────────────────────────────────────────────────────────────────────┼──┼┘
                                                                           │  │
                                    Short-Lived Ed25519 Device Assertion   │  │
                                                                           ▼  ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                  2. Gateway Broker Plane (Cloud Edge / SaaS)                 │
│                                                                              │
│   • TLS 1.3 Termination (gateway.vexa.ai)                                    │
│   • Central Provider Key Vault (AES-256-GCM / KMS - Keys Quarantined)        │
│   • Heterogeneous Provider Transformation (OpenAI, Anthropic, Bedrock, etc.) │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                    ┌──────────────────┴──────────────────┐
                    ▼                                     ▼
┌──────────────────────────────────────┐┌──────────────────────────────────────┐
│ 3. Control & Governance Plane (Core) ││ 4. Audit & Analytics Plane (FinOps)  │
│                                      ││                                      │
│ • PKCE OAuth & Device Enrollment     ││ • Valkey Distributed State Layer     │
│ • Ed25519 Public Key Registry        ││ • Integer Microcent Spend Ledger     │
│ • Scoped Virtual Key Minting         ││ • Durable Outbox & SIEM Streaming    │
│ • PostgreSQL Multi-Tenant RLS        ││   (Splunk, Datadog, OpenSearch)      │
└──────────────────────────────────────┘└──────────────────────────────────────┘
```

---

## 🔑 Key Concepts & Architectural Invariants

### 🔐 1. Zero-Elevation & Zero Trust Authentication
* **Zero Elevation Required:** Standard developer commands (`login`, `connect`, `disconnect`, `status`, `doctor`, `support-bundle`, `repair`) require no administrative privileges or UAC elevation.
* **PKCE OAuth Login:** Workstation enrollment (`agentcontrol login`) authenticates developers via standard browser OAuth 2.0 PKCE.
* **Cryptographic Device Binding:** The client generates a local Ed25519 keypair. The private key never leaves the workstation's secure store (OS Keyring or `0600` token file); only the public key is registered with the Control Plane.
* **Short-Lived Device Assertions:** Outbound requests to the hosted gateway present an Ed25519-signed JWT assertion with a strict 5-minute TTL, eliminating static fleet API secrets.

---

### 🛡️ 2. MCP Stdio-Proxy Process & Fault Isolation
Autonomous agents interacting with Model Context Protocol (MCP) servers run through isolated child processes:
* **Dedicated Child Process:** Each configured MCP server is spawned under `agentcontrol stdio-proxy -- <command>`.
* **Resource Ceiling:** Enforces an explicit `< 64MB RSS` memory ceiling and a 60-second execution timeout per tool call.
* **Frame Validation:** Protocol frames exceeding 16MB or JSON nesting exceeding 32 levels are rejected immediately with JSON-RPC `-32600`.
* **Crash Isolation:** A crash or timeout in an MCP server never cascades to terminate the daemon or affect other running tools.
* **Parameter DLP:** Real-time regex inspection and inline redaction of API keys, private credentials, and sensitive connection strings before dispatch.

---

### 🌐 3. Loopback Proxy Hardening (Mode B)
For agents routing LLM completions locally (`http://127.0.0.1:18080/v1`):
* **Socket-Level Verification:** Validates that incoming connections strictly originate from local loopback interfaces (`127.0.0.0/8`, `::1`). External network connections are dropped at the TCP socket layer.
* **RFC 3986 Authority Parsing:** Rejects duplicate `Host` headers and unapproved domain authorities with HTTP 400/403.
* **Proxy Header Stripping:** Inbound `X-Forwarded-For` and `Forwarded` headers are stripped to prevent identity spoofing.
* **Anti-DNS Rebinding:** External browser `Origin` and `Sec-Fetch-*` headers are blocked to prevent ambient port scanning from malicious websites.
* **Non-Relay Invariant:** The proxy strictly communicates with authoritative Vexa Cloud Gateways, failing closed if prompted to relay to internal RFC 1918 subnets.

---

### 💰 4. FinOps Microcent Spend Governance & Valkey State
* **Integer Microcent Precision:** Spend budgets, reservations, and settlements use integer microcents ($1.00 = 100,000,000 µ¢) to eliminate floating-point drift.
* **Concurrency-Safe Preflight:** Authoritative reservations lock estimated tokens before upstream dispatch (`reserved + settled + new <= limit`), guaranteeing zero double-spend.
* **Valkey State Layer:** Sub-millisecond virtual key lookups, distributed token buckets (RPM/TPM), and lock-free reservations powered by Valkey.
* **Premature Disconnect Accounting:** Downstream client stream disconnects trigger immediate upstream stream cancellation (< 500ms) and settle exact tokens consumed.

---

### 📦 5. Ownership Manifests & Non-Destructive Reversal
* **Ownership Manifests:** Every target configuration modified by `agentcontrol connect` is recorded in `~/.agentcontrol/manifests/<target>.manifest.json` with pre-mutation and post-mutation SHA-256 hashes, managed keys, and injected values.
* **Baseline Preservation:** Pristine configuration files are backed up to `<config>.baseline.bak` and never overwritten on reconnect.
* **Clean Disconnection:** Running `agentcontrol disconnect <target>` restores original configuration keys while preserving custom developer comments, environment variables, and user-defined settings.

---

### 🔒 6. Zero Provider Keys & Zero Root CA
* **Quarantined Credentials:** Master LLM provider keys (OpenAI, Anthropic, Gemini, Groq, Bedrock) remain strictly quarantined inside the Cloud Vault (AES-256-GCM / KMS envelope encryption). Workstations never hold or log provider credentials.
* **Zero Trust Store Mutation:** Workstation trust stores (Windows CryptoAPI, macOS Keychain, Linux ca-certificates) are never modified, and no synthetic Root CA certificates are generated or installed.
