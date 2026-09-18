# Vexa Agent Control — Master User Guide

> **Enterprise-Grade AI Security Gateway & Firewall for MCP, HTTP, HTTPS, and WebSockets**  
> Complete operational manual for Endpoint Users, Software Developers, DevOps Engineers, and Security Administrators.

---

## Table of Contents

1. [Overview & Security Boundary](#1-overview--security-boundary)
2. [Operating Profile Selection](#2-operating-profile-selection)
3. [Master Capabilities Matrix](#3-master-capabilities-matrix)
4. [Workstation Quickstart (Standalone Developer)](#4-workstation-quickstart-standalone-developer)
5. [Multi-IDE Integration & File-Lock Management](#5-multi-ide-integration--file-lock-management)
6. [Hardware PKI Enrollment & OS Sentry Service](#6-hardware-pki-enrollment--os-sentry-service)
7. [Policy Configuration & Automated Rule Synthesis](#7-policy-configuration--automated-rule-synthesis)
8. [Data Loss Prevention (DLP) & Prompt Injection Defense](#8-data-loss-prevention-dlp--prompt-injection-defense)
9. [Authoritative LLM Spend Governance](#9-authoritative-llm-spend-governance)
10. [Human-in-the-Loop (HITL) Action Escalation](#10-human-in-the-loop-hitl-action-escalation)
11. [Tamper-Evident Audit Logging & Compliance Reporting](#11-tamper-evident-audit-logging--compliance-reporting)
12. [Master CLI Command Reference](#12-master-cli-command-reference)
13. [Specialist Documentation Links](#13-specialist-documentation-links)
14. [Run Explorer & Forensic Dossiers](#14-run-explorer--forensic-dossiers)
15. [Effective Policy Explorer](#15-effective-policy-explorer-5-level-hierarchical-resolution)
16. [Spend Analytics & Ledger Observatory](#16-spend-analytics--ledger-observatory)
17. [Desired-State Routing & Verification Architecture](#17-desired-state-routing--verification-architecture)

---

## 1. Overview & Security Boundary

Autonomous AI agents possess powerful capabilities — reading files, running terminal commands, and interacting with external services over Model Context Protocol (MCP). Without deterministic runtime controls, agents are susceptible to prompt injection, credential exfiltration, infinite loops, and data leaks.

**Vexa Agent Control** provides an out-of-process, default-deny security boundary around AI agent execution. Rather than relying on soft system prompts or probabilistic LLM guardrails, Agent Control intercepts, sandboxes, audits, and enforces cryptographic policy rules on all tool calls and LLM egress traffic.

### The 6-Pass Security Pipeline

Every agent tool call and LLM egress payload traversing Agent Control passes sequentially through a 6-pass deterministic pipeline before reaching upstream servers:

```
  [ Operating Surfaces & IDEs ] ──► (Claude Desktop / Cursor / VS Code / Antigravity / CLI)
             │
             ▼
 ┌───────────────────────────┐
 │ 1. Session & Identity     │ ◄── OIDC JWT Claims & Multi-Tenant Project / Task Policy Sharding
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 2. MCP Scoring & Schema   │ ◄── Vexa Security Score (0-100) & Parameter JSON Schema Validation
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 3. Safe Mode & Injection  │ ◄── 15 Out-of-the-Box Safe Mode Rules & 9 Prompt Injection Detectors
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 4. Dual-Pass DLP Engine   │ ◄── Inline PII & Secret Redaction / Dynamic Threat Intel Feed
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 5. Spend & Loop Control   │ ◄── Repeat Failure Loop Intercept (PivotError) & Token Budget Ledger
 └─────────────┬─────────────┘
               ▼
 ┌───────────────────────────┐
 │ 6. HITL & Action Ladder   │ ◄── Default-Deny Evaluation & HMAC Webhook / Browser Escalation
 └─────────────┬─────────────┘
               │
    [ Upstream MCP / LLM ]  ───►  Control Hub Telemetry & Zero-Knowledge Encrypted SIEM Export
```

> [!NOTE]
> **Boundary of Protection:** Agent Control governs all tool calls and network egress routed through its local proxy and wrapped IDE configurations. It is designed to work in synergy with host EDR and OS security policies.

---

## 2. Operating Profile Selection

Agent Control adapts to your infrastructure across three operational deployment profiles:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Agent Control Operating Profiles                                      │
├──────────────────────────┬───────────────────────────────┬───────────────────────────────┬──────────────┤
│ 1. Workstation Sidecar   │ 2. Docker Local / PoC         │ 3. Team Control Hub           │ 4. Enterprise│
│    • Individual Devs     │    • Zero Host Installation   │    • Engineering Teams        │    • K8s / HA│
│    • Statically Linked   │    • Standalone or Full Stack │    • Central Docker Compose   │    • HAR OCI │
│    • Embedded SQLite     │    • Instant Evaluation       │    • PostgreSQL Ledger        │    • CMK     │
│    → [Workstation Guide] │    → [Docker Guide]           │    → [Team Hub Guide]         │    → [Enterp]│
└──────────────────────────┴───────────────────────────────┴───────────────────────────────┴──────────────┘
```

1. **[Workstation Sidecar](workstation_guide.md)** — Statically-linked binary for individual developers. Provides zero-touch authentication and target connection (`agentcontrol login` and `agentcontrol connect`), 15 out-of-the-box safe mode rules, inline DLP, and a local background proxy on `http://127.0.0.1:18080`.
2. **[Docker Local / PoC Deployment](guides/docker-deployment.md)** — Containerized gateway or all-in-one full stack (PostgreSQL + Control Plane API + React Console + Gateway) for fast zero-install development, testing, and PoC evaluation.
3. **[Team Control Hub](team_hub_guide.md)** — Self-hosted centralized management plane deployed via Docker Compose (Go REST API on `:8081`, React Management Console on `:3000`, PostgreSQL database). Coordinates distributed gateways with real-time SSE policy push, OIDC identity binding, centralized provider key custody, and authoritative spend ledgers.
4. **[Enterprise Fleet](enterprise_guide.md)** — High-availability Kubernetes Helm deployment (`./chart`) featuring the Hardened Agent Container Runtime (HAR) sidecar image (`Dockerfile.har`), hardened WebSocket egress tunneling, offline Ed25519 licensing, pure-Rust TLS (`rustls`), and zero-knowledge customer-managed key (CMK) SIEM export.

---

## 3. Master Capabilities Matrix

| Capability | Workstation Sidecar | Team Control Hub | Enterprise Fleet | Primary Command / Interface |
|---|:---:|:---:|:---:|---|
| **Default-Deny Policy Engine** | ✓ | ✓ | ✓ | `agentcontrol start` / `agentcontrol protect` |
| **Policy Marketplace (One-Click Templates)** | ✓ | ✓ | ✓ | Web Console `/policy/marketplace` |
| **15 Out-of-the-Box Safe Rules** | ✓ | ✓ | ✓ | Active by default (no YAML needed) |
| **9 Prompt Injection Scanners** | ✓ | ✓ | ✓ | Built-in 6-pass normalizer |
| **Dual-Pass DLP Secret Redaction** | ✓ | ✓ | ✓ | 21 built-in regex detectors |
| **Shadow AI Discovery & Risk Delta** | ✓ | ✓ | ✓ | `agentcontrol dev` / `agentcontrol report --risk` |
| **MCP Security Scoring (0–100)** | ✓ | ✓ | ✓ | `agentcontrol scan` |
| **Multi-IDE Auto-Wrapping (9 IDEs)** | ✓ | ✓ | ✓ | `agentcontrol protect` / `agentcontrol wrap` |
| **Event-Driven Config Watcher Daemon** | ✓ | ✓ | ✓ | `agentcontrol watch --all` |
| **Hardware PKI Device Enrollment** | ✓ | ✓ | ✓ | `agentcontrol login` (interactive) / `agentcontrol enroll` (headless) |
| **Persistent OS Sentry Service** | ✓ | ✓ | ✓ | Auto-registered by `agentcontrol login`; `agentcontrol service install` (advanced) |
| **ADR Security Benchmark (303 Tasks)** | ✓ | ✓ | ✓ | `agentcontrol bench --full` |
| **Automated Compliance Reports** | ✓ | ✓ | ✓ | `agentcontrol compliance report` |
| **Zero Master Key Custody** | — | ✓ | ✓ | Centralized Vault / Hub Injection |
| **Authoritative Spend Ledger** | — | ✓ | ✓ | Web Console `/spend/status` |
| **Centralized SSE Policy Push** | — | ✓ | ✓ | SSE stream `/api/v1/policy/subscribe` |
| **OIDC Identity & Group Claims** | — | ✓ | ✓ | `identity_binding` YAML block |
| **Multi-Tenant Policy Sharding** | — | ✓ | ✓ | `agent_project_id` header routing |
| **Async HITL Webhook Queue** | — | ✓ | ✓ | Slack / Teams HMAC callbacks |
| **Hardened Agent Container (HAR)** | — | — | ✓ | `Dockerfile.har` OCI sidecar |
| **Hardened WebSocket Tunneling** | — | — | ✓ | Bi-directional `<5ms` proxy |
| **Real-Time Threat Intel Feed** | — | — | ✓ | SSE malware signature stream |
| **Zero-Knowledge CMK Encryption** | — | — | ✓ | AES-256-GCM client-side export |
| **Pure-Rust TLS Termination** | — | — | ✓ | `rustls` native HTTPS listener |
| **Pluggable Model Routing (4 Strategies)** | ✓ | ✓ | ✓ | `model_groups` policy config (AR-2) |
| **Extensible Pipeline Hook Framework** | ✓ | ✓ | ✓ | PreRoute, PreExecute, PostExecute hooks (AR-1) |
| **Asynchronous Spend Batch Writer** | — | ✓ | ✓ | Bounded buffer with backpressure protection (AR-3) |
| **Centralized Daemon Job Scheduler** | — | — | ✓ | Introspection endpoint `/internal/jobs` (AR-4) |

---

## 4. Workstation Quickstart (Standalone Developer)

This quickstart is designed for individual software developers evaluating Vexa Agent Control on their local workstation. **Zero Docker, zero external databases, and zero Control Hub required** — the entire security gateway, DLP engine, prompt injection shield, and developer dashboard run locally from a single standalone binary.

### Step 1: Install the Agent Control Binary

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
  export PATH="$HOME/.local/bin:$PATH"
  agentcontrol --version
  ```

* **Windows (PowerShell):**
  ```powershell
  irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex
  agentcontrol.exe --version
  ```

* **Windows (Command Prompt - CMD):**
  ```cmd
  curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 -o "%TEMP%\install.ps1" && powershell.exe -ExecutionPolicy Bypass -File "%TEMP%\install.ps1" && del "%TEMP%\install.ps1"
  set PATH=%USERPROFILE%\.local\bin;%PATH%
  agentcontrol.exe --version
  ```

### Step 2: Start the Local Security Gateway (`agentcontrol start`)

Launch the local security gateway and proxy daemon on your workstation:

```bash
agentcontrol start
```

**What occurs automatically:**
1. 🔒 **Local Bearer Token:** Automatically generates a persistent, high-entropy bearer token at `~/.agentcontrol/local.token` (restricted with `0600` / Windows User ACL).
2. 🚀 **Loopback Socket:** Listens on `127.0.0.1:18080` (with dynamic fallback range `18080..=18090`).
3. 💾 **Local Audit Store:** Commits all telemetry to `~/.agentcontrol/events.db` (SQLite WAL mode).
4. 🌐 **Local Web Console:** Serves the embedded **Local Developer Dashboard** at `http://127.0.0.1:18080`.

*(To connect this workstation to a Control Hub and register a persistent background daemon, run `agentcontrol login --hub <url>`. This handles PKCE authentication, device enrollment, and service installation in one step.)*

### Step 3: Connect Your Coding Assistants (`agentcontrol connect <target>`)

In a new terminal window, connect your local AI coding assistants:

```bash
# Connect Anthropic Claude Desktop:
agentcontrol connect claude

# Connect Cursor:
agentcontrol connect cursor

# Connect Antigravity IDE:
agentcontrol connect antigravity

# Connect OpenAI Codex CLI:
agentcontrol connect codex
```

**What `agentcontrol connect` performs automatically:**
1. 🔍 **Discovers & Verifies Version:** Checks client version against supported ranges.
2. 🔒 **Creates Baseline Backup:** Backs up original config to `<config>.baseline.bak`.
3. 📝 **Injects Local Governance:** Injects loopback routing (`http://127.0.0.1:18080/v1`) using the local token, or wraps MCP servers with `agentcontrol stdio-proxy -- <command>`.
4. 📜 **Writes Ownership Manifest:** Records pre/post SHA-256 file hashes and injected keys in `~/.agentcontrol/manifests/<target>.manifest.json` for risk-free reversal.
5. ⚡ **Synthesizes Verification Probe:** Sends a synthetic 1-token loopback probe to assert routing.

### Step 4: Experience Live Governance in the Local Developer Dashboard (`http://127.0.0.1:18080`)

Open the embedded **Local Developer Dashboard** in your web browser:

```text
http://127.0.0.1:18080
```

**The Developer Experience in the Local Dashboard:**
1. **Overview & Security Posture:** Check your real-time security score, active connected clients, loopback latency, and system health.
2. **Real-Time Activity Stream:** Send a prompt or tool call from your connected coding assistant (Codex, Claude, Cursor, Continue) and watch the intercepted LLM stream and tool calls populate via live SSE events.
3. **Live Detections & Parameter DLP:** Observe automatic redaction of credentials (`[REDACTED:API_KEY]`, `[REDACTED:CONNECTION_STRING]`) and prompt injection shield triggers.
4. **Token Economics & Semantic Cache:** Monitor real-time token spend, budget burn-down, and cache hits.
5. **Live Policy Wizard:** Interactively customize safe-mode tool permissions and synthesize custom policies.

Inspect verified target capabilities and freshness tiers from your terminal:

```bash
# View multi-state capability status and freshness tiers:
agentcontrol status
```

```text
Target: claude          [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
Target: cursor          [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
Target: antigravity     [CONFIGURED, PROBE_VERIFIED]                   (🟢 ACTIVE_FRESH)
Target: codex           [CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED]  (🟢 ACTIVE_FRESH)
```

### Step 5: Run Diagnostic Health Suite (`agentcontrol doctor`)

Verify system integrity, local auth token, background daemon, and target drift:

```bash
# Run comprehensive diagnostic checks:
agentcontrol doctor
```

```text
✔ Binary Integrity:          Pass (v1.0.87)
✔ Local Token Health:        Pass (~/.agentcontrol/local.token, 0600)
✔ Daemon Reachability:       Pass (127.0.0.1:18080 responsive)
✔ Local Database Health:     Pass (~/.agentcontrol/events.db, WAL active)
✔ Target Configuration:      Pass (codex: verified, claude: verified, cursor: verified)
✔ Security Hygiene:          Pass (Zero plaintext keys detected in env)

Overall Health: HEALTHY (Exit Code 0)
```

### Step 6: Clean Non-Destructive Reversal Anytime (`agentcontrol disconnect <target>`)

To cleanly restore target configurations without erasing custom developer settings:

```bash
# Revert specific connected target:
agentcontrol disconnect claude
agentcontrol disconnect cursor
agentcontrol disconnect antigravity
agentcontrol disconnect codex

# Diagnose and automatically repair configuration drift:
agentcontrol repair
```

---

## 5. Target Governance & Child Process MCP Sandboxing

Agent Control governs autonomous coding agents and Model Context Protocol (MCP) servers:

| Target Client | Connect Command | Governed Surfaces | Isolation Model |
|---|---|---|---|
| **Claude Desktop** | `agentcontrol connect claude` | MCP tool executions | Isolated child `stdio-proxy` per server (< 64MB memory quota) |
| **Cursor** | `agentcontrol connect cursor` | MCP tools & LLM egress | Stdio proxy wrapping & custom proxy endpoint (`127.0.0.1:18080`) |
| **ChatGPT Codex** | `agentcontrol connect codex` | LLM completions & MCP tools | Loopback proxy (`127.0.0.1:18080`) + child `stdio-proxy` |
| **Antigravity IDE** | `agentcontrol connect antigravity` | MCP tool execution | Stdio proxy with inline parameter DLP |
| **VS Code** *(Experimental)* | Manual `stdio-proxy` wrapping | LLM completions | Mode A Cloud-Direct via scoped virtual key |

### Checking Multi-State Capability Status

Run `agentcontrol status` to inspect all connected targets with verified capabilities and freshness tiers:

```bash
agentcontrol status
```

Output:
```text
=== Vexa Agent Control Workstation Status ===
Daemon:    RUNNING (127.0.0.1:18080, PID 14208)
Identity:  local (local.token, ~/.agentcontrol/local.token)
Keyring:   LOCAL_TOKEN (Available)

Target Status:
• codex:        CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED (ACTIVE_FRESH)
• claude:       MCP_WRAPPED, MCP_TRAFFIC_VERIFIED (ACTIVE_RECENT)
• cursor:       CONFIGURED, PROBE_VERIFIED, TRAFFIC_VERIFIED (ACTIVE_FRESH)
```

### Event-Driven Configuration Watcher Daemon

### Stdio Proxy Architecture & Transparent Interception

When wrapping IDE configurations like Claude Desktop, Agent Control substitutes the direct MCP server binary invocation with:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agentcontrol",
      "args": ["stdio-proxy", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "/path/to/workspace"]
    }
  }
}
```

**Interception & Decision Lifecycle:**
1. **Zero-Latency Transparent Stream:** MCP client (IDE) communicates via standard JSON-RPC over stdin/stdout.
2. **Deterministic Pre-Execution Evaluation:** Tool requests (`tools/call`) are evaluated against active policies and regex engines before any byte reaches the upstream process.
3. **Canonical Threat Classification:** Hostile payloads are halted immediately with JSON-RPC error responses, preserving exact threat classifications:
   - **DLP Exfiltration Attempts:** Gated and persisted as `DLP-01-HIGH-ENTROPY` with structured DLP finding metadata.
   - **Prompt Injection & System Overrides:** Gated and persisted as `INJ-04-OVERRIDE` with injection finding metadata.
   - **Safe Permitted Operations:** Forwarded transparently to upstream server and recorded as `tool_allow` / `default_allowlist`.
4. **Cross-Process WAL Persistence:** All policy decisions are atomically committed to `~/.agentcontrol/events.db` (using SQLite Write-Ahead Logging) and badged as **REAL** in the local dashboard (`http://127.0.0.1:18080`).

### Custom IDE Config Paths & Non-Standard Environments

If your IDE is installed in a non-standard location or marked as unverified in `agentcontrol status`, you can protect it manually using either of the following approaches:

1. **Direct CLI Wrapping in Custom Configs:**
   Update your IDE's MCP JSON config manually by prefixing your command with `agentcontrol stdio-proxy --`:
   ```json
   "command": "agentcontrol",
   "args": ["stdio-proxy", "--", "python3", "my_mcp_server.py"]
   ```

2. **Environment Variable Overrides:**
   Point Agent Control to custom config directories using environment variables before running `agentcontrol protect`:
   ```bash
   export CLAUDE_CONFIG_DIR="/custom/path/to/Claude"
   export CURSOR_CONFIG_DIR="/custom/path/to/Cursor"
   agentcontrol protect
   ```

---

## 6. Hardware PKI Enrollment & OS Sentry Service

For team and enterprise environments, workstations are bound to the central Control Hub using cryptographic device enrollment and a persistent OS background service.

### Onboarding Path A — Zero-Touch Browser Login (Recommended for Developers)

This is the **primary onboarding path** for individual developers and team members. A single command opens browser PKCE SSO, generates a local Ed25519 hardware-bound device key, registers the device with the Hub, and automatically installs the background OS sentry service:

```bash
agentcontrol login --hub "http://localhost:8400"
```

**What happens automatically:**
1. Opens browser PKCE SSO against the Control Hub.
2. Generates an **Ed25519 Device Keypair** in OS secure storage (Windows DPAPI / macOS Keychain / Linux Secret Service `0600`).
3. Registers the device's public key with the Hub via `POST /api/v2/devices/enroll` (bearer-authenticated).
4. Saves device credentials and hub URL to `~/.agentcontrol/`.
5. Automatically calls `service install` to register the OS-level background daemon — **no separate step required**.

### Onboarding Path B — Headless / MDM / CI Enrollment (Advanced)

This path is reserved for **automated fleet provisioning** (Intune, SCCM, GPO, CI pipelines) where a browser is unavailable. It requires an admin-issued one-time enrollment token (OTET) from the Control Hub.

> [!IMPORTANT]
> Hub-side OTET generation (admin panel token issuance) is **not yet available in the Hub UI**. This path is reserved for future automated deployment workflows. For current interactive setup, use `agentcontrol login`.

```bash
# Headless enrollment using admin-issued one-time token
agentcontrol enroll --token "TOK-ADMIN-ISSUED-TOKEN" --hub-url "http://localhost:8400"
```

**Cryptographic Enrollment Flow (PKI v4.0):**
1. Generates an **Ed25519 Device Keypair** + **ECDSA P-256 CSR** (dual-key bundle).
2. Posts challenge to `POST /api/v2/enrollment/start` with the OTET.
3. Signs the Hub nonce with the Ed25519 private key.
4. Posts proof to `POST /api/v2/enrollment/complete` — receives a device JWT and mTLS certificate.
5. The one-time token is consumed immediately and never stored in plain text.

### Persistent OS Sentry Background Daemon

`agentcontrol login` registers the daemon automatically. For advanced scenarios or re-registration:

```bash
# Check daemon health (truthful multi-dimensional status)
agentcontrol service status

# Re-register daemon after OS-level supervisor failure (requires prior enrollment)
agentcontrol service install --hub-url "http://localhost:8400"

# Enterprise / system-level install (requires Administrator; no prior enrollment needed)
agentcontrol service install --enterprise --hub-url "http://localhost:8400"

# Uninstall Sentry Daemon
agentcontrol service uninstall
```

**Sentry Protection Mechanics:**
- **Immutable File Locks:** Applies read-only attributes (`chmod 0444`, BSD `chflags uchg`, Windows ACL Write Deny) to prevent unauthorized tampering with MCP configurations.
- **Continuous Tamper Detection:** Any manual tampering triggers `<300ms` auto-rewrapping and sends a real-time `TAMPER_DETECTED` alert to the Control Hub.
- **Windows Session 0 Multi-User Enumeration:** When running as `SYSTEM` on Windows, automatically scans and protects developer profile hives in `C:\Users\*`.

---

## 7. Policy Configuration & Automated Rule Synthesis

Agent Control enforces zero-trust rules defined in `agentcontrol-policy.yaml` (Schema v2).

### Baseline Policy Structure

```yaml
version: 2
default_action: deny

# 1. Identity Provider Binding (Enterprise / Team)
identity:
  provider: "oidc"
  issuer: "https://auth.corp.local/oauth2/default"
  audience: "agentcontrol-gateway-prod"
  group_claim_key: "groups"

# 2. Group Policy Bindings
policy_bindings:
  - group: "secops-team"
    policy: "admin-unrestricted"
  - group: "dev-team"
    policy: "developer-standard"

# 3. Tool Allowlists & Parameter Schemas
tools:
  - name: "read_file"
    action: allow
    credential_scope: ["file:read"]
    parameters:
      - name: "path"
        type: string
        required: true
        max_length: 512
        validators:
          - path_traversal
          - no_sensitive_paths
        deny_patterns: ["\\.ssh", "\\.env", "\\.aws"]

  - name: "execute_command"
    action: allow
    parameters:
      - name: "command"
        type: string
        required: true
        deny_patterns: ["rm\\s+-rf", "mkfs", "dd\\s+if=", "curl.*\\|.*bash"]

# 4. Data Loss Prevention (DLP)
dlp:
  scannable_tools: ["read_file", "execute_command"]
  safe_tools: ["list_directory"]
  patterns:
    - name: "aws_access_key"
      regex: "AKIA[0-9A-Z]{16}"
      action: block
    - name: "generic_api_key"
      regex: "(?i)(api_key|apikey|secret|token)\\s*[:=]\\s*['\"][a-zA-Z0-9_-]{16,}['\"]"
      action: redact

# 5. Stateful Multi-Step Sequence Rules
sequence_rules:
  - name: "block_credential_exfiltration"
    window_size: 5
    antecedent_tools: ["read_file", "view_file"]
    antecedent_param_regex: ".*(\\.env|id_rsa|credentials).*"
    consequent_tools: ["http_post", "fetch_url", "bash", "execute_command"]
    action: block
    message: "Security Refusal: Network egress blocked after reading sensitive credentials."

# 6. Cycle & Loop Detection
firewall:
  enabled: true
  cycle_detection:
    max_attempts: 3
    action: pivot_error
```

### Auto-Synthesizing Policies from Shadow Traffic

You don't need to write policies by hand. Run `agentcontrol dev` or `agentcontrol protect --shadow` during development to observe normal agent behavior, then synthesize a strict, lint-passing policy draft:

```bash
# Synthesize policy from recorded shadow SQLite database
agentcontrol generate-policy --decay-window 30 --output agentcontrol-policy.yaml
```

### Policy Linting, Validation & CI/CD Testing

```bash
# 1. Lint policy YAML for structural errors & security warnings
agentcontrol lint agentcontrol-policy.yaml

# 2. Test a single tool call payload offline against the policy
agentcontrol validate --policy agentcontrol-policy.yaml --tool read_file --payload payload.json

# 3. Validate policy fixtures against a running gateway in CI/CD pipelines
agentcontrol test --policy agentcontrol-policy.yaml --gateway "http://127.0.0.1:18080" fixture.json

# 4. Cryptographically sign policy with Ed25519 key for production promotion
agentcontrol promote --policy agentcontrol-policy.yaml --key ./keys/prod.key
```

---

## 8. Data Loss Prevention (DLP) & Prompt Injection Defense

Agent Control acts as a dual-pass firewall examining both outbound tool arguments and inbound execution responses.

### 21 Built-In Regex DLP Detectors

| Category | Patterns Covered | Action |
|---|---|---|
| **Cloud Provider Keys** | AWS Access Key (`AKIA...`), AWS Secret Key, GCP API Key, Azure Key Vault Secrets | Block / Redact |
| **API & Service Tokens** | GitHub PAT, GitLab Token, Stripe API Keys, Slack Bot Tokens, OpenAI Keys, Anthropic Keys | Block / Redact |
| **Private Keys & Certificates** | RSA Private Keys, OpenSSH Keys, Ed25519 Keys, EC Private Keys, PGP Private Keys | Block |
| **PII & Financial Data** | Credit Card Numbers (Visa, Mastercard, Amex), US Social Security Numbers (SSN), IBAN | Redact |
| **Authentication Secrets** | JWT Bearer Tokens, Database Connection Strings (`postgres://`, `mysql://`), Basic Auth URLs | Redact |

### 6-Pass Normalizer & Prompt Injection Scanners

To prevent evasion through obfuscation, incoming payloads undergo 6 normalization passes before inspection:
1. **NFKC Unicode Normalization** — Resolves homoglyphs and compatibility characters.
2. **Zero-Width Character Stripping** — Removes hidden zero-width spaces (`\u200B`), non-breaking spaces, and directional marks.
3. **Cyrillic & Unicode Homoglyph Mapping** — Canonicalizes spoofed characters to ASCII equivalents.
4. **URL & Percent Decoding** — Recursively resolves URL encodings.
5. **Base64 Payload Decoding** — Automatically inspects embedded Base64 strings.
6. **Leetspeak & Case Normalization** — Maps common character substitutions (`3 -> e`, `1 -> l`, `@ -> a`).

Normalized text is evaluated against 9 active injection scanners blocking:
- **Jailbreak Attempts** (`DAN`, `Ignore previous instructions`, `Developer Mode`)
- **System Prompt Overrides** (`You are now in unrestricted mode`)
- **Context & Memory Poisoning** (Malicious instructions hidden inside retrieved web pages or file reads)
- **Tool-Response Poisoning** (Indirect prompt injections embedded in SQL or API results)

---

## 9. Authoritative LLM Spend & Key Governance

Agent Control provides an authoritative, distributed spend management and key custody engine that prevents budget runaways, eliminates local credential leakage, and guarantees fail-closed budget enforcement.

```
Agent Request (Loopback) ──► [ Local Edge Gateway ] ──► [ Central Broker /api/v3/broker ]
                                                              │
                                                        [ Spend Preflight ] ──► (Sufficient Budget?)
                                                              │                       │
                                                        [ Active Price Book ]   YES ──┴──► Just-in-Time Key Decrypt
                                                        Integer Microcents                    │
                                                                                      ▼
                                                                                Allowlisted Provider (OpenAI / Anthropic / Groq)
                                                                                      │
                                                                                True 4-Tier Streaming SSE Relay
                                                                                      │
                                                                                Central Durable Outbox Settle / Release
```

### LLM Governance Modes (`llm_mode`)

| Mode | Key Custody Location | Preflight Accounting Semantics | Failure Mode |
|---|---|---|---|
| **`local_compat` (Default)** | Workstation environment variables (`OPENAI_API_KEY`, etc.) | Local advisory tracking; direct upstream dispatch | Fails locally |
| **`central_shadow`** | Central Control Plane Key Vault (AES-256-GCM Envelope) | Evaluates active price book; logs `would_deny` audit events; permits egress | Fail-closed (`503`); zero local fallback |
| **`central_enforce`** | Central Control Plane Key Vault (AES-256-GCM Envelope) | Strict serializable row-locked budget reservation; denies on exhaustion | Fail-closed (`429` / `503`); zero local fallback |

### Preflight Budget Invariants & Zero-Trust Key Custody
- **Integer Microcents Math:** All token calculations use integer microcents ($1.00 = 100,000,000 µ¢) to eliminate IEEE-754 floating-point rounding errors.
- **Pinned Active Price Book:** Every reservation queries the active versioned price book, pins the version ID, and fails closed with `price_unknown` on unpriced models in enforce mode.
- **Pre-Dispatch Bounded Reservations:** Before forwarding prompts to an LLM provider, Agent Control calculates maximum potential cost based on model pricing rules and reserves the amount.
- **Fail-Closed Hard Deny:** If `active_reservations + settled_spend > limit`, the gateway rejects the request with HTTP 429 (`spend_budget_exhausted`). Zero upstream provider packets are transmitted.
- **Centralized Envelope Key Custody:** Provider credentials exist exclusively in the Control Plane database encrypted with AES-256-GCM and Authenticated Additional Data (AAD = `tenant_id | provider | key_alias | version`). Workstations never store or load long-lived provider secrets.
- **True 4-Tier SSE Streaming:** Responses are streamed chunk-by-chunk with immediate flushing (`Provider → Central Broker → Local Edge → Client`), maintaining low first-token latency and capturing terminal `stream_options.include_usage`.
- **Central Durable Outbox:** Authoritative settlement and release operations are recorded in the Control Plane database outbox with idempotency keys (`settle-{req_uuid}`), ensuring exact-once accounting even during network partitions or process restarts.

### Provider Key Lifecycle Management
- **Staged Key Rotation:** Add new key versions (`ACTIVE`) while gracefully retiring older versions (`RETIRING`) with overlap windows.
- **Sanitized Validation:** `POST /api/v1/providers/keys/{id}/validate` verifies upstream credential validity with zero error leakage.

### Virtual Keys & Client Configuration (Cross-Platform)

Agent Control provides **Virtual Keys** (`sk-vex-...`) managed through the Web Console (`/virtual-keys`). Rather than distributing sensitive, unrestricted provider API keys (OpenAI, Anthropic, Google) to developer workstations, operators generate scoped Virtual Keys with strict boundaries:

- **Monthly Budget Cap ($ USD):** Hard or soft ceiling converted to integer microcents.
- **Throughput Rate Limits:** Maximum Requests Per Minute (RPM) and Tokens Per Minute (TPM).
- **Concurrency Ceilings:** Limit simultaneous in-flight completions.
- **Model Allowlisting:** Restrict developer usage to approved models (e.g., `o3-mini`, `gpt-4o-mini`).
- **Route & CIDR Restrictions:** Restrict API routes and source IP subnets.

When developers use a Virtual Key, the Agent Control Gateway validates the key, enforces spend reservations, strips the virtual token, and injects the authoritative upstream key from key custody.

#### Cross-Platform Client Configuration Matrix

| AI Tool / IDE | Operating System | Configuration File Location | Configuration Snippet |
|---|---|---|---|
| **ChatGPT Codex** | **Windows** | `%USERPROFILE%\.codex\config.toml` | ```toml<br>openai_base_url = "http://127.0.0.1:18080/v1"<br>model = "gpt-4o"<br><br>[shell_environment_policy.set]<br>OPENAI_BASE_URL = "http://127.0.0.1:18080/v1"<br>OPENAI_API_KEY = "sk-vex-YOUR_VIRTUAL_KEY"<br>OPENAI_MODEL = "gpt-4o"<br>HTTP_PROXY = "http://127.0.0.1:18080"<br>HTTPS_PROXY = "http://127.0.0.1:18080"<br>``` |
| | **macOS / Linux** | `~/.codex/config.toml` | Same top-level routing and `[shell_environment_policy.set]` block |
| **Claude Desktop** | **Windows** | `%APPDATA%\Claude\claude_desktop_config.json` | ```json<br>{<br>  "mcpServers": {<br>    "agent": {<br>      "command": "agentcontrol",<br>      "args": ["stdio-proxy", "--", "node", "runner.js"]<br>    }<br>  }<br>}<br>``` |
| | **macOS** | `~/Library/Application Support/Claude/claude_desktop_config.json` | Same JSON schema |
| | **Linux** | `~/.config/Claude/claude_desktop_config.json` | Same JSON schema |
| **Cursor IDE** | **Windows** | `%APPDATA%\Cursor\User\settings.json` | ```json<br>{<br>  "cursor.openAI.baseUrl": "http://127.0.0.1:18080/v1",<br>  "cursor.openAI.apiKey": "sk-vex-YOUR_VIRTUAL_KEY",<br>  "cursor.openAI.model": "gpt-4o"<br>}<br>``` |
| | **macOS** | `~/Library/Application Support/Cursor/User/settings.json` | Same JSON settings |
| | **Linux** | `~/.config/Cursor/User/settings.json` | Same JSON settings |
| **Terminal / CLI** (Aider, SDKs) | **Windows (PowerShell)** | `$PROFILE` or session env | ```powershell<br>$env:OPENAI_BASE_URL = "http://127.0.0.1:18080/v1"<br>$env:OPENAI_API_KEY  = "sk-vex-YOUR_VIRTUAL_KEY"<br>``` |
| | **macOS / Linux** | `~/.bashrc` or `~/.zshrc` | ```bash<br>export OPENAI_BASE_URL="http://127.0.0.1:18080/v1"<br>export OPENAI_API_KEY="sk-vex-YOUR_VIRTUAL_KEY"<br>``` |

> [!IMPORTANT]
> **Codex Desktop & CLI Routing:** In `~/.codex/config.toml`, always set `openai_base_url = "http://127.0.0.1:18080/v1"` and `model = "gpt-4o"` at the **top level** of the file so the Codex chat engine routes completions to AgentControl. `[shell_environment_policy.set]` configures child tools and subprocesses. Do not place custom keys under sections like `[features]`.

### Native BaseURL & Stdio Proxy Architecture for IDEs & SDKs

Agent Control provides a clean architecture for governing LLM spend and security across all developer environments without OS trust store modifications:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    NATIVE LLM SPEND & GOVERNANCE ARCHITECTURE               │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Native BaseURL Redirection (Cleanest, Fastest, Zero Certs)               │
│   • Targets: Codex, Continue.dev, Cursor OpenAI-mode, Aider, Python/Node SDK│
│   • Configuration: Set `baseURL: http://127.0.0.1:18080/v1`                 │
│   • Path: Handled directly by high-performance proxy (`/v1/chat/completions`)│
├─────────────────────────────────────────────────────────────────────────────┤
│ 2. Isolated MCP Stdio Proxy Child Processes (< 64MB RSS Ceiling)            │
│   • Targets: Claude Desktop, Cursor MCP, Zed, VS Code MCP servers           │
│   • Configuration: Command wrapped as `agentcontrol stdio-proxy -- <bin>`   │
│   • Path: Intercepts JSON-RPC tool calls on stdin/stdout with parameter DLP │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Requesting a Budget Increase
1. Navigate to the **Spend Status** view in the Web Console (`/spend/status`).
2. Review project budget limits, current window consumption, and active reservations.
3. Submit a budget increase request with requested amount and business justification.
4. Once approved by an operator in `/spend/requests`, the new limit takes effect immediately with zero downtime.

### Pluggable Model Groups & Routing Strategies (AR-2)

When defining upstream model providers in `agentcontrol-policy.yaml`, operators can group multiple deployments under a unified alias with dynamic routing strategies:
- **`priority`:** Fallback ladder prioritizing primary deployments and shifting to backup endpoints upon failure.
- **`lowest_latency`:** Dynamically dispatches queries to whichever deployment exhibits the lowest exponential moving average (EMA) response latency.
- **`weighted_random`:** Proportional traffic routing across deployments based on assigned weights.
- **`region_affinity`:** Strict sovereign data residency compliance. Matches against authoritative typed deployment `region` metadata (with delimiter-bounded fallback). If the candidate deployments violate `allowed_regions`, Agent Control deterministically rejects the request with HTTP 503 `routing_policy_violation` to prevent cross-border data leakage.

### High-Throughput Asynchronous Spend Event Writer (AR-3, AR-5)

In high-concurrency enterprise deployments, logging individual token spend events synchronously can bottleneck database transaction pools. Agent Control decouples spend event recording via an asynchronous `SpendEventWriter`:
- **Production Wiring:** Bound directly to `spend.Store` and triggered post-commit upon `Authorize`, `Settle`, and `Release` lifecycle operations.
- **Bounded In-Memory Ring Buffer:** Holds up to 10,000 pending spend events.
- **Multi-Row Batch Flushing:** Batches flushes into PostgreSQL using `pgx.Batch` every 100ms or 256 records.
- **Exponential Backoff Retry & Replay:** Automatically retries failed batch flushes up to 3 times with exponential backoff, storing uncommitted events in a dedicated replay buffer to prevent data loss during transient database outages.
- **Backpressure Shed Protection:** Under extreme database saturation, write attempts wait up to 2 seconds before shedding load with critical audit alerts, shielding request proxies from unbounded latencies.
- **Graceful Shutdown Drain:** Flushes all buffered events to durable storage upon SIGTERM/SIGINT.
- **Decoupled Execution Runs (`runs.Store`):** Analytical run queries (`ListRuns`, `GetRunDossier`) are isolated from transactional ledger updates, preventing dashboard queries from degrading active agent execution.

### Centralized Daemon Job Scheduler (AR-4)

The Go Control Plane manages true background daemons using a centralized, context-aware `Scheduler`:
- **Deterministic Sweeper Registration:** Periodic maintenance jobs (e.g. `SweepJob` for cleaning expired reservation holds, `AssignmentStaleSweepJob` for stale endpoint convergence) register with specific intervals.
- **Authenticated Live Introspection:** Operators can inspect active jobs, execution schedules, and run statistics via `GET /internal/jobs` (restricted to loopback or authenticated admin token).
- **Graceful Cancellation:** All daemon jobs link directly to the application termination context, guaranteeing clean cancellation on service shutdown.

---

## 10. Human-in-the-Loop (HITL) Action Escalation

High-risk actions (e.g., database drops, production deployments, sensitive file access) can be routed for human authorization.

### Real-Time Interactive Browser Modals
When running locally, dangerous tool calls trigger a real-time modal in the Local Dashboard (`http://127.0.0.1:18080`). The execution pauses safely until the user clicks **Approve** or **Deny**.

### Asynchronous Slack / MS Teams / Webhook Queue
For team and enterprise deployments, the gateway dispatches an async webhook payload containing:
- Request ID & Timestamp
- Agent OIDC Identity & Project Context
- Tool Name & Raw Parameters
- Cryptographic HMAC-SHA256 Signature

Approvers submit decisions via HTTP callback:
```bash
curl -X POST http://localhost:18080/api/v1/hitl/respond \
  -H "Content-Type: application/json" \
  -H "X-Agent-Control-Signature: <HMAC_SIGNATURE>" \
  -d '{"request_id": "req-9842", "decision": "approve"}'
```

---

## 11. Tamper-Evident Audit Logging & Compliance Reporting

Every tool call, policy evaluation, DLP finding, and administrative action is recorded in an immutable, cryptographically chained audit log.

### HMAC-SHA256 Hash Chaining

Each record in `~/.agentcontrol/audit.jsonl` contains the SHA-256 hash of the preceding record:
$$\text{Hash}_n = \text{HMAC-SHA256}(\text{Record}_n \parallel \text{Hash}_{n-1}, K_{\text{audit}})$$

If any record is altered or deleted, the hash chain breaks immediately.

### Verifying Log Integrity

```bash
# Verify HMAC integrity across the entire audit log
agentcontrol verify-log ~/.agentcontrol/audit.jsonl

# Verify with custom HMAC key file
agentcontrol verify-log ~/.agentcontrol/audit.jsonl --key-file ./keys/audit.key
```

### Automated Compliance Evidence Generation

Generate audit evidence reports mapped directly to **SOC 2 Type II**, **ISO 27001:2022**, and **NIST AI RMF 1.0**:

```bash
# Generate Markdown compliance report
agentcontrol compliance report --log-path ~/.agentcontrol/audit.jsonl --format markdown --output compliance-report.md

# Output JSON structured report for automated compliance platforms
agentcontrol compliance report --log-path ~/.agentcontrol/audit.jsonl --format json
```

### Compliance Framework Mappings

| Standard | Control ID | Control Title | Agent Control Verification Evidence |
|---|---|---|---|
| **SOC 2 Type II** | CC6.1 | Logical Access & Least Privilege | HMAC-chained audit log & tool parameter allowlists |
| **SOC 2 Type II** | CC6.6 | Boundary Defense for AI Systems | Safe mode rules, injection scanners & cycle detection |
| **ISO 27001:2022** | A.8.12 | Data Leakage Prevention (DLP) | 21 dual-pass regex detectors with secret redaction |
| **NIST AI RMF 1.0** | MEASURE 2.2 | Input & Output Verification | 6-pass normalizer & stateful sequence rules |
| **OWASP ASI 2026** | ASI01–ASI10 | OWASP Agentic Top 10 | Complete matrix alignment (8/10 Full, 1/10 Partial) |

---

## 12. Master CLI Command Reference (12 Canonical Commands)

Vexa Agent Control provides a streamlined set of 12 canonical CLI commands for developer workstation management, target governance, and diagnostics:

| Command | Arguments / Flags | Description |
|---|---|---|
| `agentcontrol login` | `[--no-browser]` | Authenticates workstation via browser OAuth 2.0 PKCE, generates local Ed25519 keypair, registers public key with Control Hub, and installs background service. |
| `agentcontrol connect <target>` | `codex`, `claude`, `vscode-continue` `[--mode local\|cloud-direct]`, `[--force]` | Injects loopback proxy or wraps MCP tool configuration; records ownership manifest and baseline backup. |
| `agentcontrol disconnect <target>` | `codex`, `claude`, `vscode-continue` | Reverts injected configuration keys from ownership manifest while preserving user custom settings. |
| `agentcontrol status` | *(none)* | Displays active daemon state, identity, gateway latency, target capabilities (`CONFIGURED`, `MCP_WRAPPED`), and freshness tiers (`ACTIVE_FRESH`, `ACTIVE_RECENT`, `STALE`). |
| `agentcontrol doctor` | `[--json]` | Runs comprehensive health checks (binary integrity, auth, daemon IPC, gateway RTT, target drift, security invariants). Strict exit codes: 0 (Pass), 1 (Fail), 2 (Degraded). |
| `agentcontrol support-bundle` | `[--output-dir <PATH>]`, `[--yes]` | Generates a privacy-preserving diagnostic archive containing doctor report, system info, service metrics, error tail, and manifest summaries with zero secrets. |
| `agentcontrol repair` | *(none)* | Validates configuration files against manifests; repairs missing user tasks and broken loopback endpoints without modifying custom user edits. |
| `agentcontrol rotate-local-token` | *(none)* | Atomically rotates the 32-byte local session bearer token in `~/.agentcontrol/local.token`, updates connected configs, and notifies the running daemon. |
| `agentcontrol service` | `install`, `uninstall`, `status` `[--hub-url <URL>]` | Manages the per-user background agent daemon (Windows scheduled user task, macOS launchd LaunchAgent, Linux systemd user service). |
| `agentcontrol start` | `[--listen <ADDR>]`, `[--policy <PATH>]` | Runs the local background proxy daemon listening on `127.0.0.1:18080`. |
| `agentcontrol logout` | *(none)* | Flushes local cached tokens from OS keyring and notifies Control Hub to revoke device session. |
| `agentcontrol reset-local-state` | `[--force]` | Interactive recovery command to purge local SQLite event ledger and cache while preserving pristine baseline backups. |
| `agentcontrol stdio-proxy -- <cmd>` | `<command> [args...]` | Dedicated child process wrapper for MCP servers enforcing frame quotas (< 16MB), memory limits (< 64MB RSS), 60s timeouts, and parameter DLP. |

---

## 13. Specialist Documentation Links

For focused operational guides and deep-dive technical references:

- **[Docker Deployment Guide](guides/docker-deployment.md)** — Standalone gateway container & Docker Compose full-stack setup.
- **[10-Minute Quickstart](quickstart.md)** — Step-by-step developer guide with proven rollback paths.
- **[Workstation Sidecar Guide](workstation_guide.md)** — Local shadow discovery, safe rules, and policy synthesis.
- **[Small Team Hub Guide](guides/small-team-hub.md)** — Centralized policy sync, OTET enrollment, and Caddy TLS.
- **[Enterprise Fleet Guide](enterprise_guide.md)** — Kubernetes Helm chart, HAR container sidecars, and CMK encryption.
- **[Custom Agent HTTP Guide](guides/custom-agent-http.md)** — Integrating Python, TypeScript, LangChain, and CrewAI agents.
- **[CLI Reference](reference/cli.md)** — Authoritative reference for all CLI commands, flags, and environment variables.
- **[Configuration Reference](reference/configuration.md)** — Policy Schema v2, detectors, and canonical environment variables.

---

## 14. Run Explorer & Forensic Dossiers

The **Run Explorer** (`/runs`) provides end-to-end auditability and forensic inspection for all LLM broker transactions across the fleet.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           RUN EXPLORER TELEMETRY                            │
├─────────────────────────────────────────────────────────────────────────────┤
│ 1. Run Search & Filters: Filter by 1H/24H/7D/30D, Provider, State, Model.  │
│ 2. Run Dossier Drawer: 5 comprehensive inspection tabs:                     │
│    • Economics: Preflight Reserved ($), Settled ($), and Released ($).      │
│    • Identity: Workstation Device ID, Hostname, and Compliance Posture.     │
│    • Policy Snapshot: Exact JSONB rules and Price Book version evaluated.   │
│    • Ledger Events: Immutable append-only audit events for the run.         │
│    • Dispatch: Upstream endpoint, model selector, and roundtrip latency.    │
│ 3. Deep-Link Navigation: Direct jump to Effective Policy Explorer.          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Inspecting Runs via API
```bash
# List recent runs
curl -H "Authorization: Bearer <TOKEN>" "http://localhost:8400/api/v1/runs?hours=24&limit=50"

# Fetch single forensic dossier
curl -H "Authorization: Bearer <TOKEN>" "http://localhost:8400/api/v1/runs/res-01917f8a-..."
```

---

## 15. Effective Policy Explorer (5-Level Hierarchical Resolution)

The **Effective Policy Explorer** (`/policy/effective-explorer`) determines exact governing bounds across the 5-layer hierarchy:

1. **Level 1: Organization** — Base tenant rules and default enforcement modes.
2. **Level 2: Group** — Scoped group overrides.
3. **Level 3: Spend** — Budget limits, period types, and hard-deny actions.
4. **Level 4: Virtual Key** — Scoped API key route and model restrictions.
5. **Level 5: Device Governance** — Hardware compliance and sentry posture.

### Point-in-Time Historical Resolution
Operators can specify an `at` ISO-8601 UTC timestamp to evaluate the exact policy version active during any historical incident.

---

## 16. Spend Analytics & Ledger Observatory

The **Spend Observatory** (`/spend/visualization`) replaces client-side approximations with PostgreSQL server-side aggregation (`GET /api/v2/spend/analytics`):

- **Zero Client Approximation:** Aggregated in PostgreSQL with `date_trunc('hour', created_at)`.
- **Hourly Spend Velocity:** Real-time visual trend lines for settled spend and active reservations.
- **Dimensional Breakdown:** Instant grouping by `provider`, `device`, `model`, or `project`.
- **Data Freshness & Provenance:** Explicit timestamps and confidence tiers on all telemetry widgets.

---

## 17. Desired-State Routing & Verification Architecture

Vexa Agent Control implements a deterministic **Desired-State Assignment Model** and **Identity Attribution Pipeline** to guarantee that routing configurations and provider keys delivered from the Control Hub are reliably applied, cryptographically acknowledged, and verified against authenticated identities.

### Desired-State Assignment Lifecycle

Assignments replace fire-and-forget push channels with a formal 9-state state machine:

```
  [desired] ──► [eligible] ──► [delivered] ──► [applied] ──► [verified]
      │             │               │              │
      │             ▼               ▼              ▼
      ├────────► [stale] ◄──────── [failed] ◄──────┘
      │
      ▼
  [revoked] ──► [rolled_back]
```

| State | Description |
|---|---|
| `desired` | Initial target state configured in Control Hub policy editor or API. |
| `eligible` | Device identity and posture verified; ready for transmission. |
| `delivered`| Sent to endpoint over SSE push or retrieved via periodic pull poll. |
| `applied`  | Endpoint in-memory proxy state and IDE configuration updated (`apply_centralized_cursor_config`). |
| `verified` | Active end-to-end routing asserted via `agentcontrol verify` probe and authenticated Control Hub correlation. |
| `failed`   | Endpoint was unable to apply or verify assignment within threshold. |
| `stale`    | Superseded by a newer assignment or unacknowledged past timeout (`AssignmentStaleSweepJob`). |
| `revoked`  | Explicitly invalidated by security administrator or key rotation. |
| `rolled_back` | Automatically reverted to the previous known good assignment. |

### Hybrid Push / Pull Convergence Model

1. **Instant SSE Push (Fast Path):** The endpoint subscribes to `GET /api/v2/device/policy/subscribe`. When an assignment update is published, the proxy hot-swaps provider keys and model routing rules in memory, updates local IDE configs, and immediately fires an acknowledgment (`POST /api/v2/device/assignments/:id/ack`).
2. **60-Second Pull Reconciler (Safety Net):** A background task (`start_provider_keys_poll`) polls `GET /api/v2/device/provider-keys/active` every 60 seconds. This catches up after laptop sleep/wake cycles, network interruptions, or missed SSE packets.

### Two-Tier Identity Model (REQ-VER-002)

Every LLM request and verification probe is stamped with an identity tier:

- **Verified Identity (`oidc`):** Bound to an authenticated IdP identity (Okta, Azure AD, Google Workspace) via mTLS client certificates or OIDC Bearer tokens. Stored with `identity_verified = true`.
- **Unverified Identity (`local_os`):** Falling back to local OS username / environment variables when offline or un-enrolled. Stored with `identity_verified = false`.

### Verification Probe (REQ-VER-004)

Operators and automated CI/CD pipelines can run the 5-point verification probe to assert that local IDE routing, DLP filters, injection defenses, and Control Hub correlation are active:

```bash
# Basic local gateway verification
agentcontrol verify --gateway http://127.0.0.1:18080

# Full end-to-end verification with Control Hub correlation (REQ-VER-004)
agentcontrol verify \
  --gateway http://127.0.0.1:18080 \
  --hub https://console.vexasec.io \
  --user-id dev-user-42 \
  --assignment-id asgn-01918a2b-c3d4-7e8f-9a0b-1c2d3e4f5a6b

# Output structured JSON report
agentcontrol verify --gateway http://127.0.0.1:18080 --hub https://console.vexasec.io --json
```

The probe verifies:
1. Gateway health and uptime (`/healthz`).
2. Safe tool execution without false positives (`echo` command pass-through).
3. DLP secret redaction (AWS API key simulation blocked/redacted).
4. Prompt injection detection (delimiter extraction attack blocked).
5. **Control Hub Identity Correlation (`/api/v2/device/verify-probe`):** Validates device identity, user ID, and active assignment hash against Control Hub records.

### Correlated Request Attribution (REQ-VER-008 Guarantee)

At the Control Hub broker layer (`POST /api/v3/gateway-broker/chat/completions`), every incoming LLM request is recorded in PostgreSQL `request_attributions` with:
- `device_id` and `user_id`
- `identity_source` (`oidc` vs `local_os`) and `identity_verified`
- Active `assignment_id`
- `model`, `provider`, prompt/completion token counts, and microcent cost.


