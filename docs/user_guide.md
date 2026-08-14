# Vexa AgentWall — Master User Guide

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

**Vexa AgentWall** provides an out-of-process, default-deny security boundary around AI agent execution. Rather than relying on soft system prompts or probabilistic LLM guardrails, AgentWall intercepts, sandboxes, audits, and enforces cryptographic policy rules on all tool calls and LLM egress traffic.

### The 6-Pass Security Pipeline

Every agent tool call and LLM egress payload traversing AgentWall passes sequentially through a 6-pass deterministic pipeline before reaching upstream servers:

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
> **Boundary of Protection:** AgentWall governs all tool calls and network egress routed through its local proxy and wrapped IDE configurations. It is designed to work in synergy with host EDR and OS security policies.

---

## 2. Operating Profile Selection

AgentWall adapts to your infrastructure across three operational deployment profiles:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AgentWall Operating Profiles                                  │
├──────────────────────────┬───────────────────────────────┬──────────────────────────────────────┤
│ 1. Workstation Sidecar   │ 2. Team Control Hub           │ 3. Enterprise Fleet                  │
│    • Individual Devs     │    • Engineering Teams        │    • Enterprise Production Fleet     │
│    • Zero Configuration  │    • Central Docker Compose   │    • Kubernetes Helm Release         │
│    • Embedded SQLite     │    • PostgreSQL Ledger        │    • HAR Container Sidecars          │
│    • Local Dashboard     │    • OIDC Claim Binding       │    • WebSocket Egress Tunneling      │
│    → [Workstation Guide] │    → [Team Hub Guide]         │    → [Enterprise Guide]              │
└──────────────────────────┴───────────────────────────────┴──────────────────────────────────────┘
```

1. **[Workstation Sidecar](workstation_guide.md)** — Statically-linked binary for individual developers. Provides one-command discovery and wrapping of all installed IDEs (`agentwall protect`), 15 out-of-the-box safe mode rules, inline DLP, passive shadow discovery, and an embedded browser dashboard on `http://127.0.0.1:8080`.
2. **[Team Control Hub](team_hub_guide.md)** — Self-hosted centralized management plane deployed via Docker Compose (Go REST API on `:8400`, React Management Console on `:8081`, PostgreSQL database). Coordinates distributed gateways with real-time SSE policy push, OIDC identity binding, centralized provider key custody, and authoritative spend ledgers.
3. **[Enterprise Fleet](enterprise_guide.md)** — High-availability Kubernetes Helm deployment (`./chart`) featuring the Hardened Agent Container Runtime (HAR) sidecar image (`Dockerfile.har`), hardened WebSocket egress tunneling, offline Ed25519 licensing, pure-Rust TLS (`rustls`), and zero-knowledge customer-managed key (CMK) SIEM export.

---

## 3. Master Capabilities Matrix

| Capability | Workstation Sidecar | Team Control Hub | Enterprise Fleet | Primary Command / Interface |
|---|:---:|:---:|:---:|---|
| **Default-Deny Policy Engine** | ✓ | ✓ | ✓ | `agentwall start` / `agentwall protect` |
| **Policy Marketplace (One-Click Templates)** | ✓ | ✓ | ✓ | Web Console `/policy/marketplace` |
| **15 Out-of-the-Box Safe Rules** | ✓ | ✓ | ✓ | Active by default (no YAML needed) |
| **9 Prompt Injection Scanners** | ✓ | ✓ | ✓ | Built-in 6-pass normalizer |
| **Dual-Pass DLP Secret Redaction** | ✓ | ✓ | ✓ | 21 built-in regex detectors |
| **Shadow AI Discovery & Risk Delta** | ✓ | ✓ | ✓ | `agentwall dev` / `agentwall report --risk` |
| **MCP Security Scoring (0–100)** | ✓ | ✓ | ✓ | `agentwall scan` |
| **Multi-IDE Auto-Wrapping (9 IDEs)** | ✓ | ✓ | ✓ | `agentwall protect` / `agentwall wrap` |
| **Event-Driven Config Watcher Daemon** | ✓ | ✓ | ✓ | `agentwall watch --all` |
| **Hardware PKI Device Enrollment** | ✓ | ✓ | ✓ | `agentwall enroll` |
| **Persistent OS Sentry Service** | ✓ | ✓ | ✓ | `agentwall service install` |
| **ADR Security Benchmark (303 Tasks)** | ✓ | ✓ | ✓ | `agentwall bench --full` |
| **Automated Compliance Reports** | ✓ | ✓ | ✓ | `agentwall compliance report` |
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

---

## 4. Workstation Quickstart & Single-Command Protection

The fastest path to complete local AI security is **One-Command Protection** via `agentwall protect`.

### Step 1: Install the AgentWall Binary

* **macOS / Linux / WSL (Bash / Zsh):**
  ```bash
  curl -fsSL https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/install/install.sh | bash
  ```

* **Windows (PowerShell):**
  ```powershell
  irm https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/install/install.ps1 | iex
  ```

* **Windows (Command Prompt):**
  ```cmd
  curl.exe -fsSL https://raw.githubusercontent.com/noviqtechnologies/agentwall/main/install/install.ps1 -o install.ps1 && powershell -ExecutionPolicy Bypass -File install.ps1
  ```

### Step 2: Run One-Command Protection

Execute `agentwall protect` in your terminal:

```bash
# macOS / Linux
agentwall protect

# Windows (PowerShell / CMD)
agentwall.exe protect
```

**What `agentwall protect` performs automatically:**
1. 🛡 **Generates Baseline Policy:** Creates `agentwall-policy.yaml` with baseline P0 DLP rules (blocking `.env`, `.ssh/id_rsa`, `~/.aws/credentials`) if no policy file exists.
2. 🔍 **Auto-Discovers Installed IDEs:** Scans for Cursor, Claude Desktop, VS Code, JetBrains, Zed, Cline, OpenCode, Antigravity, and Codex.
3. 🔒 **Atomically Wraps Configurations:** Updates MCP configs to route through the gateway while creating timestamped backups before writing.
4. 🚀 **Starts Security Gateway:** Binds the local proxy to `127.0.0.1:8080` and streams structured JSONL logs to `~/.agentwall/audit.jsonl`.
5. 🌐 **Launches Local Dashboard:** Automatically opens your default web browser to `http://127.0.0.1:8080`.

```bash
# Useful flags:
agentwall protect --dry-run   # Preview all discovery & wrapping actions without modifying files
agentwall protect --shadow    # Launch in passive observation mode (no active blocking)
agentwall protect --no-browser # Start gateway without opening browser automatically
```

### Step 3: Verify with Instant Telemetry

If you have not connected an IDE yet, generate simulated tool calls to verify the dashboard:

```bash
# macOS / Linux / WSL
python3 ~/.local/bin/quickstart_agent.py

# Windows (PowerShell)
python "$env:USERPROFILE\.local\bin\quickstart_agent.py"
```

### Step 4: Revert Anytime

To cleanly restore all IDE configurations from their original backups:

```bash
agentwall unprotect            # macOS / Linux (verifies backup integrity)
agentwall.exe unprotect        # Windows
agentwall.exe unprotect --force # Emergency recovery: force restore
```

---

## 5. Multi-IDE Integration & File-Lock Management

AgentWall natively discovers, wraps, and monitors 9 leading AI coding environments:

| IDE / Target | Wrap Command | Config File Location | Interception Behavior |
|---|---|---|---|
| **Claude Desktop** | `agentwall wrap claude` | `claude_desktop_config.json` | Replaces stdio commands with AgentWall proxy wrapper |
| **Cursor** | `agentwall wrap cursor` | Cursor `User/settings.json` | Intercepts MCP server registrations & tool invocations |
| **VS Code** | `agentwall wrap vscode` | `.vscode/mcp.json` / Extension storage | Governs extension-based MCP tool calls |
| **JetBrains** | `agentwall wrap jetbrains` | JetBrains AI assistant settings | Wraps external MCP servers with default-deny rules |
| **Zed Editor** | `agentwall wrap zed` | `~/.config/zed/settings.json` | Injects security proxy into Zed language model config |
| **Cline Extension** | `agentwall wrap cline` | Cline extension settings | Intercepts autonomous tool execution and shell commands |
| **OpenCode** | `agentwall wrap opencode` | OpenCode configuration | Secures tool parameter payloads and audits activity |
| **Antigravity IDE** | `agentwall wrap antigravity` | Antigravity settings / MCP config | Governs tool calls and surfaces interactive HITL modals |
| **ChatGPT Codex** | `agentwall wrap codex` | Codex CLI / API settings | Scopes credentials and blocks prompt injections |

### Checking Wrap Status

Run `agentwall status` to inspect all 9 targets:

```bash
agentwall status
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

AI IDEs or extensions may rewrite their configuration files. The AgentWall watcher daemon monitors configuration files via native OS filesystem events (`ReadDirectoryChangesW` on Windows, `FSEvents` on macOS, `inotify` on Linux):

```bash
# Watch all verified IDE targets in the background:
agentwall watch --all

# Watch a specific IDE target:
agentwall watch claude
agentwall watch cursor
```

When an unwrapped entry is detected, the watcher re-wraps the configuration within `<300ms` and records a security audit log.

---

## 6. Hardware PKI Enrollment & OS Sentry Service

For team and enterprise environments, workstations are bound to the central Control Hub using cryptographic device enrollment and persistent OS background services.

### Hardware-Bound Device Enrollment

```bash
agentwall enroll --token "TOK-ONE-TIME-TOKEN" --hub-url "http://localhost:8400"
```

**Cryptographic Enrollment Flow:**
1. Generates an **Ed25519 Device Keypair** bound to OS secure storage (Windows DPAPI / macOS Keychain / Linux Secret Service `0600`).
2. Generates an **ECDSA P-256 Keypair** and submits a Certificate Signing Request (CSR) to the Control Hub.
3. Exchanges proof-of-possession challenges and receives an authenticated short-lived mTLS device certificate.
4. The one-time token is consumed immediately and never stored in plain text.

### Persistent OS Sentry Background Daemon

Install AgentWall as a system-level background daemon that boots with the operating system:

```bash
# Install Sentry Daemon (Windows SCM / macOS launchd / Linux systemd)
agentwall service install \
  --hub-url "http://localhost:8400" \
  --gateway-secret "your-gateway-secret" \
  --policy-read-secret "your-policy-read-secret" \
  --agent-id "dev-workstation-01"

# Check daemon health
agentwall service status

# Uninstall Sentry Daemon
agentwall service uninstall
```

**Sentry Protection Mechanics:**
- **Immutable File Locks:** Applies read-only attributes (`chmod 0444`, BSD `chflags uchg`, Windows ACL Write Deny) to prevent unauthorized tampering with MCP configurations.
- **Continuous Tamper Detection:** Any manual tampering triggers `<300ms` auto-rewrapping and sends a real-time `TAMPER_DETECTED` alert to the Control Hub.
- **Windows Session 0 Multi-User Enumeration:** When running as `SYSTEM` on Windows, automatically scans and protects developer profile hives in `C:\Users\*`.

---

## 7. Policy Configuration & Automated Rule Synthesis

AgentWall enforces zero-trust rules defined in `agentwall-policy.yaml` (Schema v2).

### Baseline Policy Structure

```yaml
version: 2
default_action: deny

# 1. Identity Provider Binding (Enterprise / Team)
identity:
  provider: "oidc"
  issuer: "https://auth.corp.local/oauth2/default"
  audience: "agentwall-gateway-prod"
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

You don't need to write policies by hand. Run `agentwall dev` or `agentwall protect --shadow` during development to observe normal agent behavior, then synthesize a strict, lint-passing policy draft:

```bash
# Synthesize policy from recorded shadow SQLite database
agentwall generate-policy --decay-window 30 --output agentwall-policy.yaml
```

### Policy Linting, Validation & CI/CD Testing

```bash
# 1. Lint policy YAML for structural errors & security warnings
agentwall lint agentwall-policy.yaml

# 2. Test a single tool call payload offline against the policy
agentwall validate --policy agentwall-policy.yaml --tool read_file --payload payload.json

# 3. Validate policy fixtures against a running gateway in CI/CD pipelines
agentwall test --policy agentwall-policy.yaml --gateway "http://127.0.0.1:8080" fixture.json

# 4. Cryptographically sign policy with Ed25519 key for production promotion
agentwall promote --policy agentwall-policy.yaml --key ./keys/prod.key
```

---

## 8. Data Loss Prevention (DLP) & Prompt Injection Defense

AgentWall acts as a dual-pass firewall examining both outbound tool arguments and inbound execution responses.

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

## 9. Authoritative LLM Spend Governance

AgentWall includes an authoritative PostgreSQL-backed spend management engine that prevents budget runaways and token exhaustion.

```
Agent Request ──► [ Preflight Reservation ] ──► (Sufficient Budget?)
                         │                             │
                   [ microcents ]                YES ──┴──► Forward to Provider
                   ceiling math                        │
                                                 NO  ─────► HTTP 429 Hard Deny
```

### Preflight Budget Invariants
- **Integer Microcents Math:** All token calculations use integer microcents ($1.00 = 100,000,000 µ¢) to eliminate floating-point rounding errors.
- **Pre-Dispatch Bounded Reservations:** Before forwarding a prompt to an LLM provider, AgentWall calculates maximum potential cost based on model pricing rules and reserves the amount.
- **Fail-Closed Hard Deny:** If `active_reservations + settled_spend > limit`, the gateway rejects the request with HTTP 429 (`spend_budget_exhausted`). No upstream provider tokens are consumed.

### Requesting a Budget Increase
1. Navigate to the **Spend Status** view in the Web Console (`/spend/status`).
2. Review project budget limits, current window consumption, and active reservations.
3. Submit a budget increase request with requested amount and business justification.
4. Once approved by an operator in `/spend/requests`, the new limit takes effect immediately with zero downtime.

---

## 10. Human-in-the-Loop (HITL) Action Escalation

High-risk actions (e.g., database drops, production deployments, sensitive file access) can be routed for human authorization.

### Real-Time Interactive Browser Modals
When running locally (`agentwall protect` / `agentwall dev`), dangerous tool calls trigger a real-time modal in the Local Dashboard (`http://127.0.0.1:8080`). The execution pauses safely until the user clicks **Approve** or **Deny**.

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
  -H "X-AgentWall-Signature: <HMAC_SIGNATURE>" \
  -d '{"request_id": "req-9842", "decision": "approve"}'
```

---

## 11. Tamper-Evident Audit Logging & Compliance Reporting

Every tool call, policy evaluation, DLP finding, and administrative action is recorded in an immutable, cryptographically chained audit log.

### HMAC-SHA256 Hash Chaining

Each record in `~/.agentwall/audit.jsonl` contains the SHA-256 hash of the preceding record:
$$\text{Hash}_n = \text{HMAC-SHA256}(\text{Record}_n \parallel \text{Hash}_{n-1}, K_{\text{audit}})$$

If any record is altered or deleted, the hash chain breaks immediately.

### Verifying Log Integrity

```bash
# Verify HMAC integrity across the entire audit log
agentwall verify-log ~/.agentwall/audit.jsonl

# Verify with custom HMAC key file
agentwall verify-log ~/.agentwall/audit.jsonl --key-file ./keys/audit.key
```

### Automated Compliance Evidence Generation

Generate audit evidence reports mapped directly to **SOC 2 Type II**, **ISO 27001:2022**, and **NIST AI RMF 1.0**:

```bash
# Generate Markdown compliance report
agentwall compliance report --log-path ~/.agentwall/audit.jsonl --format markdown --output compliance-report.md

# Output JSON structured report for automated compliance platforms
agentwall compliance report --log-path ~/.agentwall/audit.jsonl --format json
```

### Compliance Framework Mappings

| Standard | Control ID | Control Title | AgentWall Verification Evidence |
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
| `agentwall protect` | `--dry-run`, `--shadow`, `--no-browser`, `--listen <ADDR>`, `--policy <PATH>` | Single-command automated discovery, atomic IDE wrapping, gateway launch, and dashboard opening |
| `agentwall unprotect` | `--dry-run`, `--force` | Reverts all IDE configurations from backups and verifies integrity |
| `agentwall status` | *(none)* | Displays active wrap state, paths, and existence for all 9 IDE targets |
| `agentwall wrap <target>` | `claude`, `cursor`, `vscode`, `jetbrains`, `zed`, `cline`, `opencode`, `antigravity`, `codex`, or `--all` | Wraps specified IDE configuration(s) with timestamped backup creation |
| `agentwall unwrap <target>` | `<target>`, `--force` | Restores specified IDE configuration from its backup |
| `agentwall watch` | `--all`, or `<target>` | Starts the OS filesystem watcher daemon for auto-rewrapping on configuration drift |
| `agentwall dev` | `--listen <ADDR>`, `--stdio`, `--enforce`, `--learn`, `--dual-agent`, `-- <cmd>` | Starts shadow observation proxy or stdio wrapper with learning mode |
| `agentwall start` | `--policy <PATH>`, `--listen <ADDR>`, `--centralized`, `--tls-cert <CERT>`, `--tls-key <KEY>` | Runs the centralized production security gateway daemon |
| `agentwall service` | `install`, `uninstall`, `status` | Manages persistent OS background Sentry service (Windows SCM, macOS launchd, Linux systemd) |
| `agentwall enroll` | `--token <OTET>`, `--hub-url <URL>` | Performs hardware-bound Ed25519 PKI device enrollment with Control Hub |
| `agentwall generate-policy` | `--decay-window <DAYS>`, `--output <PATH>` | Synthesizes a lint-passing `agentwall-policy.yaml` from recorded shadow traffic |
| `agentwall scan` | `--path <PATH>`, `--format <text\|json>` | Audits local MCP configuration and assigns 0–100 Vexa Security Score |
| `agentwall bench` | `--full`, `--compare-baselines`, `--visualize`, `--output <PATH>` | Runs 303-task ADR security benchmark across 17 attack categories |
| `agentwall compliance report` | `--log-path <PATH>`, `--format <markdown\|json>`, `--output <PATH>` | Generates SOC 2, ISO 27001, and NIST AI RMF compliance evidence reports |
| `agentwall identity create` | `--agent <NAME>`, `--scope <SCOPE>`, `--ttl <TTL>` | Provisions a scoped, short-lived credential for an agent |
| `agentwall identity rotate` | `--agent <NAME>`, `--drain-secs <SECS>` | Rotates active agent credential with zero downtime |
| `agentwall identity audit` | `--agent <NAME>`, `--verify` | Displays HMAC-chained credential lifecycle audit log |
| `agentwall verify-log` | `<LOG_PATH>`, `--key-file <KEY>` | Verifies cryptographic HMAC-SHA256 hash chain of an audit log |
| `agentwall report` | `<LOG_PATH>`, `--output <PATH>`, `--risk`, `--format <json\|text>` | Generates session summary report or shadow Risk Delta analysis |
| `agentwall lint` | `<POLICY_PATH>` | Checks YAML policy syntax, parameter schemas, and security bounds |
| `agentwall validate` | `--policy <PATH>`, `--tool <NAME>`, `--payload <JSON_FILE>` | Evaluates tool call payload offline against policy rules |
| `agentwall test` | `--policy <PATH>`, `--gateway <URL>`, `--oidc-token <JWT>`, `<FIXTURE>` | Validates policy test fixtures in CI/CD pipeline against gateway |
| `agentwall license keygen` | `--output <DIR>` | Generates Ed25519 keypair for enterprise license generation |
| `agentwall license generate`| `--org <ORG>`, `--tier <TIER>`, `--seats <N>`, `--days <D>`, `--signing-key <KEY>` | Issues Ed25519-signed JWT enterprise license token |

---

## 13. Specialist Documentation Links

For deep architectural specifications, protocol designs, and framework-specific guides, consult our specialist documentation:

- 📖 **[Workstation Sidecar User Guide](workstation_guide.md)** — Step-by-step developer tutorial for local execution.
- 🏢 **[Team Control Hub Guide](team_hub_guide.md)** — Self-hosted Docker Compose control plane, PostgreSQL spend ledger, and fleet governance.
- ☸️ **[Enterprise Fleet Guide](enterprise_guide.md)** — Kubernetes Helm release, HAR container sidecars, and pure-Rust TLS.
- 📜 **[Common Reference Guide](common_guide.md)** — Schema v2 specification, all 21 DLP patterns, and environment variables.
- 🛡️ **[OWASP Agentic Top 10 (ASI 2026)](owasp_agentic_top10.md)** — Architectural security mapping, evidence, and mitigations.
- 🔑 **[OIDC Identity Binding Guide](oidc_identity_binding.md)** — Step-by-step setup for Okta, Keycloak, Entra ID, Auth0, and PingIdentity.
- 📊 **[ADR Security Benchmark Guide](adr_benchmark.md)** — 303 benchmark scenarios and comparative evaluation methodology.
- 🏗️ **[System Architecture Specification](agentwall_architecture.md)** — 6-pass security pipeline and internal component mechanics.
- 🚀 **[Deployment & Installation Guide](deployment.md)** — Multi-platform installation reference across Linux, macOS, and Windows.
- ⚡ **[Quickstart Guide](quickstart.md)** — 5-minute hands-on walkthrough.
