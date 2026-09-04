# Vexa Agent Control — Master User Guide

> **Enterprise-Grade AI Security Gateway & Firewall for MCP, HTTP, HTTPS, and WebSockets**  
> Complete operational manual for Endpoint Users, Software Developers, DevOps Engineers, and Security Administrators.

---

## Table of Contents

1. [Overview & Security Boundary](#1-overview--security-boundary)
2. [Operating Profile Selection](#2-operating-profile-selection)
3. [Master Capabilities Matrix](#3-master-capabilities-matrix)
4. [Workstation Quickstart & Single-Command Protection](#4-workstation-quickstart--single-command-protection)
5. [Multi-IDE Integration & File-Lock Management](#5-multi-ide-integration--file-lock-management)
6. [Hardware PKI Enrollment & OS Sentry Service](#6-hardware-pki-enrollment--os-sentry-service)
7. [Policy Configuration & Automated Rule Synthesis](#7-policy-configuration--automated-rule-synthesis)
8. [Data Loss Prevention (DLP) & Prompt Injection Defense](#8-data-loss-prevention-dlp--prompt-injection-defense)
9. [Authoritative LLM Spend Governance](#9-authoritative-llm-spend-governance)
10. [Human-in-the-Loop (HITL) Action Escalation](#10-human-in-the-loop-hitl-action-escalation)
11. [Tamper-Evident Audit Logging & Compliance Reporting](#11-tamper-evident-audit-logging--compliance-reporting)
12. [Master CLI Command Reference](#12-master-cli-command-reference)
13. [Specialist Documentation Links](#13-specialist-documentation-links)

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

1. **[Workstation Sidecar](workstation_guide.md)** — Statically-linked binary for individual developers. Provides one-command discovery and wrapping of all installed IDEs (`agentcontrol protect`), 15 out-of-the-box safe mode rules, inline DLP, passive shadow discovery, and an embedded browser dashboard on `http://127.0.0.1:8080`.
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
| **Hardware PKI Device Enrollment** | ✓ | ✓ | ✓ | `agentcontrol enroll` |
| **Persistent OS Sentry Service** | ✓ | ✓ | ✓ | `agentcontrol service install` |
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
| **Centralized Daemon Job Scheduler** | — | ✓ | ✓ | Introspection endpoint `/internal/jobs` (AR-4) |

---

## 4. Workstation Quickstart & Single-Command Protection

The fastest path to complete local AI security is **One-Command Protection** via `agentcontrol protect`.

### Step 1: Install the Agent Control Binary

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.sh | bash
  ```

* **Windows (PowerShell):**
  ```powershell
  irm https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 | iex
  ```

* **Windows (Command Prompt):**
  ```cmd
  curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/Vexa-Agent-Control/main/install/install.ps1 -o install.ps1 && powershell -ExecutionPolicy Bypass -File install.ps1
  ```

### Step 2: Run One-Command Protection

Execute `agentcontrol protect` in your terminal:

```bash
# macOS / Linux
agentcontrol protect

# Windows (PowerShell / CMD)
agentcontrol.exe protect
```

**What `agentcontrol protect` performs automatically:**
1. 🛡 **Generates Baseline Policy:** Creates `agentcontrol-policy.yaml` with baseline P0 DLP rules (blocking `.env`, `.ssh/id_rsa`, `~/.aws/credentials`) if no policy file exists.
2. 🔍 **Auto-Discovers Installed IDEs:** Scans for Cursor, Claude Desktop, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity, and Codex.
3. 🔒 **Atomically Wraps Configurations:** Updates MCP configs to route through the gateway while creating timestamped backups before writing.
4. 🚀 **Starts Security Gateway:** Binds the local proxy to `127.0.0.1:8080` and streams structured JSONL logs to `~/.agentcontrol/audit.jsonl`.
5. 🌐 **Launches Local Dashboard:** Automatically opens your default web browser to `http://127.0.0.1:8080`.

```bash
# Useful flags:
agentcontrol protect --dry-run   # Preview all discovery & wrapping actions without modifying files
agentcontrol protect --shadow    # Launch in passive observation mode (no active blocking)
agentcontrol protect --no-browser # Start gateway without opening browser automatically
```

### Step 3: Run Live 3-Point Security Verification

In a second terminal window, run the canonical verification probe to assert active gateway defenses:

```bash
# macOS / Linux / WSL
agentcontrol verify

# Windows (PowerShell)
agentcontrol.exe verify

# JSON Output (CI / Scripting)
agentcontrol verify --json
```

The verifier executes 3 automated assertions against the running gateway:
1. **Safe Tool Execution:** Asserts baseline operations like `read_file` are allowed (`HTTP 200`).
2. **DLP Secret Shield:** Asserts high-entropy secrets and SSNs are blocked (`HTTP 400`, `DLP-01-HIGH-ENTROPY`).
3. **Prompt Injection Shield:** Asserts system prompt overrides and jailbreaks are blocked (`HTTP 400`, `INJ-04-OVERRIDE`).

### Step 4: Verify with Instant Telemetry

If you have not connected an IDE yet, generate simulated tool calls to verify the dashboard:

```bash
# macOS / Linux / WSL
python3 ~/.local/bin/quickstart_agent.py

# Windows (PowerShell)
python "$env:USERPROFILE\.local\bin\quickstart_agent.py"
```

### Step 5: Revert Anytime

To cleanly restore all IDE configurations from their original backups:

```bash
agentcontrol unprotect            # macOS / Linux (verifies backup integrity)
agentcontrol.exe unprotect        # Windows
agentcontrol.exe unprotect --force # Emergency recovery: force restore
```

---

## 5. Multi-IDE Integration & File-Lock Management

Agent Control natively discovers, wraps, and monitors 9 leading AI coding environments:

| IDE / Target | Wrap Command | Config File Location | Interception Behavior |
|---|---|---|---|
| **Claude Desktop** | `agentcontrol wrap claude` | `claude_desktop_config.json` | Replaces stdio commands with Agent Control proxy wrapper |
| **Cursor** | `agentcontrol wrap cursor` | Cursor `User/settings.json` | Intercepts MCP server registrations & tool invocations |
| **VS Code** | `agentcontrol wrap vscode` | `.vscode/mcp.json` / Extension storage | Governs extension-based MCP tool calls |
| **JetBrains** | `agentcontrol wrap jetbrains` | JetBrains AI assistant settings | Wraps external MCP servers with default-deny rules |
| **Zed Editor** | `agentcontrol wrap zed` | `~/.config/zed/settings.json` | Injects security proxy into Zed language model config |
| **Cline Extension** | `agentcontrol wrap cline` | Cline extension settings | Intercepts autonomous tool execution and shell commands |
| **OpenCode** | `agentcontrol wrap opencode` | OpenCode configuration | Secures tool parameter payloads and audits activity |
| **Antigravity IDE** | `agentcontrol wrap antigravity` | Antigravity settings / MCP config | Governs tool calls and surfaces interactive HITL modals |
| **ChatGPT Codex** | `agentcontrol wrap codex` | Codex CLI / API settings | Scopes credentials and blocks prompt injections |

### Checking Wrap Status

Run `agentcontrol status` to inspect all 9 targets:

```bash
agentcontrol status
```

Output:
```text
┌───────────────────────────────────────────────────────────────────────────────────────┐
│ Target        Config File Path                                   Exists?   Wrapped?   │
├───────────────────────────────────────────────────────────────────────────────────────┤
│ Claude        C:\Users\dev\AppData\Roaming\Claude\config.json     YES       YES       │
│ Cursor        C:\Users\dev\AppData\Roaming\Cursor\settings.json   YES       YES       │
│ VS Code       C:\Users\dev\.vscode\mcp.json                       YES       YES       │
│ JetBrains     C:\Users\dev\AppData\Roaming\JetBrains\mcp.json     NO        NO        │
│ Zed           C:\Users\dev\.config\zed\settings.json              NO        NO        │
│ Cline         C:\Users\dev\AppData\Roaming\Code\cline.json        YES       YES       │
│ OpenCode      C:\Users\dev\.config\opencode\config.json           NO        NO        │
│ Antigravity   C:\Users\dev\.gemini\antigravity\config.json        YES       YES       │
│ Codex         C:\Users\dev\.codex\config.json                     NO        NO        │
└───────────────────────────────────────────────────────────────────────────────────────┘
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
4. **Cross-Process WAL Persistence:** All policy decisions are atomically committed to `~/.agentcontrol/events.db` (using SQLite Write-Ahead Logging) and badged as **REAL** in the local dashboard (`http://127.0.0.1:8080`).

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

For team and enterprise environments, workstations are bound to the central Control Hub using cryptographic device enrollment and persistent OS background services.

### Hardware-Bound Device Enrollment

```bash
agentcontrol enroll --token "TOK-ONE-TIME-TOKEN" --hub-url "http://localhost:8400"
```

**Cryptographic Enrollment Flow:**
1. Generates an **Ed25519 Device Keypair** bound to OS secure storage (Windows DPAPI / macOS Keychain / Linux Secret Service `0600`).
2. Generates an **ECDSA P-256 Keypair** and submits a Certificate Signing Request (CSR) to the Control Hub.
3. Exchanges proof-of-possession challenges and receives an authenticated short-lived mTLS device certificate.
4. The one-time token is consumed immediately and never stored in plain text.

### Persistent OS Sentry Background Daemon

Install Agent Control as a system-level background daemon that boots with the operating system:

```bash
# Install Sentry Daemon (Windows SCM / macOS launchd / Linux systemd)
agentcontrol service install \
  --hub-url "http://localhost:8400" \
  --gateway-secret "your-gateway-secret" \
  --policy-read-secret "your-policy-read-secret" \
  --agent-id "dev-workstation-01"

# Check daemon health
agentcontrol service status

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
agentcontrol test --policy agentcontrol-policy.yaml --gateway "http://127.0.0.1:8080" fixture.json

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

### 3-Tier Integration Architecture for IDEs & SDKs

Agent Control provides a 3-tier architecture for governing LLM spend and security across all developer environments:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       3-TIER LLM SPEND & GOVERNANCE                         │
├─────────────────────────────────────────────────────────────────────────────┤
│ TIER 1: Native BaseURL Redirection (Cleanest, Fastest, Zero Certs)         │
│   • Targets: Cline, Roo Code, Continue.dev, OpenCode, Aider, Python/Node SDK│
│   • Configuration: Set `baseURL: http://127.0.0.1:8080/v1`                  │
│   • Path: Handled directly by high-performance proxy (`/v1/chat/completions`)│
├─────────────────────────────────────────────────────────────────────────────┤
│ TIER 2: Native MCP Stdio Proxy Wrapping (Surgical, Zero Network Overhead)  │
│   • Targets: Claude Desktop, Zed, VS Code / Cursor MCP servers              │
│   • Configuration: Auto-wrapped command `agentcontrol stdio-proxy -- <bin>` │
│   • Path: Intercepts JSON-RPC tool calls on stdin/stdout                    │
├─────────────────────────────────────────────────────────────────────────────┤
│ TIER 3: Local MITM Proxy (Locked Proprietary Client Fallback)               │
│   • Targets: Cursor Free Tier (`api2.cursor.sh`), locked enterprise agents │
│   • Configuration: `http.proxy: 127.0.0.1:8080` + User Trust Store Root CA │
│   • Path: Decrypts CONNECT stream, counts prompt/completion tokens, settles │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Cursor Desktop (Free Tier & BYOK)
When running `agentcontrol protect`, Agent Control automatically:
1. Generates and registers an ECDSA P-256 Root CA into the OS Current User trust store (`certutil -user "Root"` / macOS `login.keychain-db`).
2. Configures Cursor's `User/settings.json` with `"http.proxy": "http://127.0.0.1:8080"` and `"cursor.general.disableHttp2": true`.
3. Sets `NODE_EXTRA_CA_CERTS` so Cursor's internal Node runtime trusts the gateway.
4. Streams and records all Chat, Tab Autocomplete, and Composer token usage into the spend ledger.

```bash
# Manage Local CA for LLM Interception
agentcontrol ca status       # Check CA generation & OS trust store status
agentcontrol ca install      # Register Root CA in User Trust Store
agentcontrol ca uninstall    # Cleanly remove Root CA from trust store
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
- **`region_affinity`:** Strict sovereign data residency compliance. If the resolved deployment violates `allowed_regions`, Agent Control deterministically rejects the request with HTTP 503 `routing_policy_violation` to prevent cross-border data leakage.

### High-Throughput Asynchronous Spend Event Writer (AR-3, AR-5)

In high-concurrency enterprise deployments, logging individual token spend events synchronously can bottleneck database transaction pools. Agent Control decouples spend event recording via an asynchronous `SpendEventWriter`:
- **Bounded In-Memory Ring Buffer:** Holds up to 50,000 pending spend events.
- **Multi-Row Batch Flushing:** Batches flushes into PostgreSQL using `pgx.Batch` every 100ms or 1,000 records.
- **Backpressure Shed Protection:** Under extreme database saturation, write attempts block for up to 2 seconds before shedding load with critical audit alerts, shielding request proxies from unbounded latencies.
- **Graceful Shutdown Drain:** Flushes all buffered events to durable storage upon SIGTERM/SIGINT.
- **Decoupled Execution Runs (`runs.Store`):** Analytical run queries (`ListRuns`, `GetRunDossier`) are isolated from transactional ledger updates, preventing dashboard queries from degrading active agent execution.

### Centralized Daemon Job Scheduler (AR-4)

The Go Control Plane manages true background daemons using a centralized, context-aware `Scheduler`:
- **Deterministic Sweeper Registration:** Periodic maintenance jobs (e.g. `SweepJob` for cleaning expired reservation holds) register with specific intervals and jitter.
- **Live Introspection Endpoint:** Operators can inspect active jobs, execution schedules, and run statistics via `GET /internal/jobs`.
- **Graceful Cancellation:** All daemon jobs link directly to the application termination context, guaranteeing clean cancellation on service shutdown.

---

## 10. Human-in-the-Loop (HITL) Action Escalation

High-risk actions (e.g., database drops, production deployments, sensitive file access) can be routed for human authorization.

### Real-Time Interactive Browser Modals
When running locally (`agentcontrol protect` / `agentcontrol dev`), dangerous tool calls trigger a real-time modal in the Local Dashboard (`http://127.0.0.1:8080`). The execution pauses safely until the user clicks **Approve** or **Deny**.

### Asynchronous Slack / MS Teams / Webhook Queue
For team and enterprise deployments, the gateway dispatches an async webhook payload containing:
- Request ID & Timestamp
- Agent OIDC Identity & Project Context
- Tool Name & Raw Parameters
- Cryptographic HMAC-SHA256 Signature

Approvers submit decisions via HTTP callback:
```bash
curl -X POST http://localhost:8080/api/v1/hitl/respond \
  -H "Content-Type: application/json" \
  -H "X-Agent Control-Signature: <HMAC_SIGNATURE>" \
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

## 12. Master CLI Command Reference

| Command | Arguments / Flags | Description |
|---|---|---|
| `agentcontrol protect` | `--dry-run`, `--shadow`, `--no-browser`, `--listen <ADDR>`, `--policy <PATH>` | Single-command automated discovery, atomic IDE wrapping, gateway launch, and dashboard opening |
| `agentcontrol unprotect` | `--dry-run`, `--force` | Reverts all IDE configurations from backups and verifies integrity |
| `agentcontrol status` | *(none)* | Displays active wrap state, paths, and existence for all 9 IDE targets |
| `agentcontrol wrap <target>` | `claude`, `cursor`, `vscode`, `jetbrains`, `zed`, `cline`, `opencode`, `antigravity`, `codex`, or `--all` | Wraps specified IDE configuration(s) with timestamped backup creation |
| `agentcontrol unwrap <target>` | `<target>`, `--force` | Restores specified IDE configuration from its backup |
| `agentcontrol watch` | `--all`, or `<target>` | Starts the OS filesystem watcher daemon for auto-rewrapping on configuration drift |
| `agentcontrol dev` | `--listen <ADDR>`, `--stdio`, `--enforce`, `--learn`, `--dual-agent`, `-- <cmd>` | Starts shadow observation proxy or stdio wrapper with learning mode |
| `agentcontrol start` | `--policy <PATH>`, `--listen <ADDR>`, `--centralized`, `--tls-cert <CERT>`, `--tls-key <KEY>` | Runs the centralized production security gateway daemon |
| `agentcontrol service` | `install`, `uninstall`, `status` | Manages persistent OS background Sentry service (Windows SCM, macOS launchd, Linux systemd) |
| `agentcontrol enroll` | `--token <OTET>`, `--hub-url <URL>` | Performs hardware-bound Ed25519 PKI device enrollment with Control Hub |
| `agentcontrol generate-policy` | `--decay-window <DAYS>`, `--output <PATH>` | Synthesizes a lint-passing `agentcontrol-policy.yaml` from recorded shadow traffic |
| `agentcontrol scan` | `--path <PATH>`, `--format <text\|json>` | Audits local MCP configuration and assigns 0–100 Vexa Security Score |
| `agentcontrol bench` | `--full`, `--compare-baselines`, `--visualize`, `--output <PATH>` | Runs 303-task ADR security benchmark across 17 attack categories |
| `agentcontrol compliance report` | `--log-path <PATH>`, `--format <markdown\|json>`, `--output <PATH>` | Generates SOC 2, ISO 27001, and NIST AI RMF compliance evidence reports |
| `agentcontrol identity create` | `--agent <NAME>`, `--scope <SCOPE>`, `--ttl <TTL>` | Provisions a scoped, short-lived credential for an agent |
| `agentcontrol identity rotate` | `--agent <NAME>`, `--drain-secs <SECS>` | Rotates active agent credential with zero downtime |
| `agentcontrol identity audit` | `--agent <NAME>`, `--verify` | Displays HMAC-chained credential lifecycle audit log |
| `agentcontrol verify-log` | `<LOG_PATH>`, `--key-file <KEY>` | Verifies cryptographic HMAC-SHA256 hash chain of an audit log |
| `agentcontrol report` | `<LOG_PATH>`, `--output <PATH>`, `--risk`, `--format <json\|text>` | Generates session summary report or shadow Risk Delta analysis |
| `agentcontrol lint` | `<POLICY_PATH>` | Checks YAML policy syntax, parameter schemas, and security bounds |
| `agentcontrol validate` | `--policy <PATH>`, `--tool <NAME>`, `--payload <JSON_FILE>` | Evaluates tool call payload offline against policy rules |
| `agentcontrol test` | `--policy <PATH>`, `--gateway <URL>`, `--oidc-token <JWT>`, `<FIXTURE>` | Validates policy test fixtures in CI/CD pipeline against gateway |
| `agentcontrol license keygen` | `--output <DIR>` | Generates Ed25519 keypair for enterprise license generation |
| `agentcontrol license generate`| `--org <ORG>`, `--tier <TIER>`, `--seats <N>`, `--days <D>`, `--signing-key <KEY>` | Issues Ed25519-signed JWT enterprise license token |

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

